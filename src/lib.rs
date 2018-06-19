//! A crate containing a bunch of hacks to model a fragmented firmware dump as a jigsaw puzzle
//! using header magics as clues to help us piece the pages back together in the correct order in
//! order to reconstruct and correctly decompress Zip File contained therein
#![feature(range_contains)]
#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(missing_docs,
        missing_debug_implementations, missing_copy_implementations,
        trivial_casts, trivial_numeric_casts,
        unsafe_code,
        unused_import_braces, unused_qualifications))]
#![cfg_attr(feature="clippy", warn(cast_precision_loss, cast_sign_loss, empty_enum,
        enum_glob_use, filter_map, if_not_else, int_plus_one, invalid_upcast_comparisons,
        items_after_statements, maybe_infinite_iter, mem_forget,
        missing_docs_in_private_items, mut_mut, mutex_integer, non_ascii_literal, nonminimal_bool,
        option_map_unwrap_or, option_map_unwrap_or_else, option_unwrap_used, print_stdout,
        pub_enum_variant_names, result_unwrap_used, shadow_reuse, shadow_same, shadow_unrelated,
        similar_names, single_match_else, string_add, string_add_assign, stutter, unicode_not_nfc,
        unseparated_literal_suffix, use_debug, use_self, used_underscore_binding,
        wrong_pub_self_convention))]
#[macro_use]
extern crate bitflags;
extern crate chrono;
extern crate cogset;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;

use std::fs::File;
use std::io::prelude::*;

use std::io::Error;

use chunks::{FragSys, CDInstance, LF};
use analysis::Instance;

pub mod parser;
pub mod chunks;
pub mod analysis;

/// Primo function where yon magic happens.
pub fn rip_a_zip(file: &mut File, page_sz: Option<usize>) -> Result<&str, Error> {
    // 0. First of all we're going to want to load a model for the dump (with the data)
    let ps = match page_sz {
        Some(x) => x,
        None => 0x400_usize,
    };

    let mut fs = FragSys::from_file(file, ps)?;

    // 1. Then for each ptr in the listing we should parse it and propagate a new zip file object.
    //    Use the `EOCD` `CD` offset and `CD` size to compute the offset into the first page of the
    //    file and also the number of pages in total. Also use the new `ZipFile` model to set up an
    //    ordered page list.
    let mut zip_files = fs.find_zips();

    // 2. Locate all available `CD` Headers in the raw dump

    let unclassified_cd_listing = fs.find_cds();

    // 3. Classify `CD` headers using the kmeans2 algorithm

    if let Ok(classified_cd_listing) =
        CDInstance::cluster(&unclassified_cd_listing, zip_files.len())
    {
        // 4. For each partition of `CD` headers order them by least `LF` pointer
        //
        //    Note: The following is distinctly crufty, unrustic and Just Gets Stuff Done for the
        //    PoC.

        let sorted_cd_clusters = classified_cd_listing
            .into_iter()
            .map(|cluster| {
                let mut iter = cluster.into_iter();
                iter.as_mut_slice().sort_unstable_by(|a, b| {
                    a.header().lf_offset.cmp(&b.header().lf_offset)
                });
                let sorted = ::analysis::Cluster::new(iter.as_slice());
                debug!("Returned clusters:\n{:?}", &sorted);
                sorted
            })
            .collect::<Vec<_>>();

        // 5. Map k partition sizes to nearest `ZipFile` file count to identify correct EOCD   }
        //    (Optionally, use parsed `CD`s and last `LF` ptr to match)

        for cluster in sorted_cd_clusters {
            // Pretty awful heuristic for matching here which will be outright buggy in some
            // obvious cases. Should be moved into a separate function on collection of zip
            // files and clusters, returning a zip of tuples in order to move past PoC
            //
            // In fact it's buggy and unnecessary -- rather than doing this heuristically by trying
            // to minimise the differences between CD counts and zip file tot entries, we could
            // just render each cluster's CD pages to a continuous buffer, and reparse these in
            // order to get an accurate count, as well as checking whether a ZipFile EOCD is at the
            // tail of each, or alternatively using the offset into the page of the first CD along
            // with the calculated expected offset as a confidence identifier. Any one of these
            // would be a pretty good confirmation, tbh, although more confidence the better in
            // terms of opportunistic parsing and having stronger affirmation/rebuttal of our
            // working hypotheses while solving this stuff. On the one hand, if we make a good
            // guess, it benefits us nothing to continue checking it makes sense, but on the other
            // hand, the faster we eliminate bad guesses the more information we have to go on for
            // making good guesses. Puzzle solving/optimisation is hard.

            if let Some(zf) = zip_files.iter_mut()
                    .min_by(|z1,z2| {
                        let d1 = 
                            (i32::from(z1.eocd.tot_entries) - cluster.iter().count() as i32).pow(2);
                        let d2 = (i32::from(z2.eocd.tot_entries) - cluster.iter().count() as i32).pow(2);
                        d1.cmp(&d2)
                    }) {
                let cd_pg_idx = zf.get_cd_start_pg_idx(fs.page_sz());
                let mut cd_pgs = vec![];
                for instance in cluster {
                    if let Some(page) = fs.get_pg_for_addr(instance.ptr()) {
                        cd_pgs.push(page)
                    }
                }

                // 6. Use CD locations to map `CD` pages into known `CD` `Page` range for
                //    `ZipFile` page buffer, removing the pages from the pool left in the `FragSys`

                let cd_pg_end = cd_pgs.len() + cd_pg_idx;
                debug!("Writing {} CD Pages starting at page {}", cd_pgs.len(), cd_pg_idx);
                zf.assign_pages(cd_pg_idx, cd_pgs);
            }
        }

        // 7. Reparse CD Pages for each zip file (in order to recover page-boundary CD
        //    headers)

        for (i,zip) in zip_files.iter_mut().enumerate() {
            debug!("Reparsing cd headers for {}", i);
            let reparsed_central_directory = zip.find_cds(&fs.data);

            debug!("Found {} cds", reparsed_central_directory.len());
            for cd in reparsed_central_directory {
                let lfh = LF::from(cd.header());
                let lfp = fs.find_lfs();
                if let Some(ptr) = fs.find_lf(&lfh, &lfp) {
                    if let Some(page) = fs.get_pg_for_addr(ptr) {
                        debug!("Found file data for {:?} at page {:?}", cd, page);
                        let idx = zip.get_pg_idx_for_offs(cd.header().lf_offset as usize, ps);
                        zip.assign_page(idx, page);
                    }
                }
            }
            let output = zip.render_pages(&fs.data, ps);
            let mut file = File::create(format!("{}.zip",i))?;
            file.write_all(&output);
        }

        // 8. For each zip file, iterate over each CD in order searching for uniquely
        //    identifiable LF headers which can also be found in the dump (importantly
        //    matching for time and date and so on), mapping pages for each into the zip
        //    file.
        //
        // 9. Perform 8, except for Data Descriptors in cases where they are flagged.
        //
        // 10. For each zip file, find the smallest gap in the LF headers, use CRC32 and
        //     size data to search for, moving pages to the correct location in the ZipFile
        //     list. Restrict this effort to easier cases (1/2 missing pages).
        //
        // 11. Use Shannon Entropy computation to filter remaining pages for high entropy pages
        //     (more likely to be compressed data).
        //
        // 12. Repeat 10 for harder cases.
        //
        // 13. Dump some output. Possibly just return a bunch of boxed `ZipFile`s for the main
        //     to write to disk or sommat

    }
    Ok("We Did it!")
}
