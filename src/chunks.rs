//! A range of data models for zip file chunks as well as fragmented file systems, pages and a
//! model zip file to be fleshed out with data as it's recognised and parsed.

use std::ops::Range;
use std::io::{BufReader, Error, ErrorKind};
use std::io::prelude::*;
use std::iter::repeat;
use std::fs::File;

use analysis::{Cluster, ClusteringError, Instance, Vectorizable};
use parser::{parse_eocd, parse_cd};

use cogset::Euclid;
use nom;
use nom::IResult::Done;

#[derive(Debug)]
/// A Fragmented, paged File System model
pub struct FragSys {
    /// Raw byte stream we're recovering data from.
    pub data: Vec<u8>,
    /// Page size
    page_sz: usize,
    /// Stack of pages to sift through
    ///
    /// Implemented to start with as a Vec but is used more like a book or a hashmap with missing
    /// elements
    ///
    /// Maybe we ought to use a newtype interface for this but trying to minimise boilerplate a
    /// little.
    pages: Vec<Page>,
}

#[derive(Clone, Debug)]
/// A `Page` on a `FragSys`
pub enum Page {
    /// Page with an associated data range
    Assigned(Range<usize>),
    /// Unassigned page - a placeholder within a collection of assigned pages to be replaced later
    Unassigned,
}

impl Page {
    /// Identify whether a Page contains the data for a given pointer
    pub fn contains(&self, addr: usize) -> bool {
        match *self {
            Page::Assigned(ref x) => x.contains(&addr),
            Page::Unassigned => false,
        }
    }
}

/// Implements a Paged interface.
pub trait Paged {

    /// Assign pages to this item's pagebook
    fn assign_pages(&self, insertion_pt: usize, content: Vec<Page>);
}

#[derive(Debug)]
/// An ordered collection of pages on a fragsys
pub struct ZipFile {
    /// Offset into the first page at which the file starts
    init_offs: usize,
    /// End of Central Directory Header
    pub eocd: EOCD,
    /// Orderly collection of pages
    pages: Vec<Page>,
}

impl ZipFile {
    /// Generate a new ZipFile model from data identified within a FragSys with a given pointer
    /// to an EOCD value.
    pub fn new(fs: &mut FragSys, ptr: usize) -> Result<Self, Error> {
        info!("Parsing EOCD ptr: {}", ptr);
        match parse_eocd(&fs.data[ptr..]) {
            Done(_, result) => {
                info!("Parsing Done: {:?}", &result);
                let ps = fs.page_sz();

                // offset of eocd into page located
                let eocd_pg_offs = ptr % ps;

                // offset of eocd within original zip file
                let eocd_offs = (result.cd_sz + result.cd_offset) as usize;

                // offset of start of zip file within the first page of the file
                let init_offs = ps - ((eocd_offs - eocd_pg_offs) % ps);

                let pg_count = {
                    // Ugly-casting bools to additional page counts
                    (if eocd_pg_offs > 0 { 1 } else { 0 }) + (if init_offs > 0 { 1 } else { 0 }) +
                        (eocd_offs - eocd_pg_offs - init_offs) / ps
                };

                // cute idiom:
                // https://stackoverflow.com/a/28208182
                let mut pages = repeat(Page::Unassigned)
                    .take(pg_count + 1)
                    .collect::<Vec<Page>>();


                if let Some(page) = fs.get_pg_for_addr(ptr) {
                    pages[pg_count - 1] = page;
                }

                Ok(Self {
                    init_offs: init_offs,
                    eocd: result,
                    pages: pages,
                })
            }
            _ => Err(Error::new(ErrorKind::Other, "Error parsing EOCD")),
        }
    }

    /// Return the page index for a particular Zip file offset
    pub fn get_pg_idx_for_offs(&self, offs: usize, pg_sz: usize) -> usize {
        let adj_offs = offs + self.init_offs;
        adj_offs / pg_sz
    }

    /// Return the index of the page where Central Directory section starts
    pub fn get_cd_start_pg_idx(&self, pg_sz: usize) -> usize {
        self.get_pg_idx_for_offs(self.eocd.cd_offset as usize, pg_sz)
    }

    /// Assign a collection of pages into a ZipFile starting at `insertion_pt`
    pub fn assign_pages(&mut self, insertion_pt: usize, content: Vec<Page>) {
        let end = insertion_pt + content.len();
        info!("insertion_pt: {}, content len: {}, self.pages.len(): {}", &insertion_pt, content.len(), self.pages.len());
        self.pages.splice(insertion_pt..end, content);
    }

    pub fn assign_page(&mut self, idx: usize, page: Page) {
        if idx <= self.pages.len() {
            self.pages[idx] = page
        }
    }

    pub fn render_pages(&self, data: &[u8], pagesz: usize) -> Vec<u8> {
        let mut rendered = Vec::with_capacity(pagesz * self.pages.len());
        for page in &self.pages {
            if let Page::Assigned(bytes) = page {
                rendered.extend_from_slice(&data[bytes.clone()]);
            } else {
                rendered.extend_from_slice(&[0u8;1024]);
            }
        }
        rendered
    }


    pub fn find_cds(&self, data: &[u8]) -> Vec<CDInstance> {
        let rendered = self.render_pages(data, 1024);

        let cd_ptrs = find_bytes(&rendered, b"PK\x01\x02");

        let mut results = Vec::with_capacity(cd_ptrs.len());
        for ptr in cd_ptrs {
            match CD::from_data(&rendered, ptr) {
                Ok(cd) => results.push(CDInstance(ptr, cd)),
                Err(e) => {
                    error!("Error: {}", e);
                }
            }
        }
        results
    }
}

#[derive(Debug)]
/// A skeleton bytestream.
pub struct Skeleton {
    /// Inner element
    inner: Range<usize>,
}

#[derive(Debug, PartialEq)]
/// An End of Central Directory header
pub struct EOCD {
    /// Current disk number within zip disk set
    pub dsk_no: u16,
    /// Disk number containing the central directory record
    pub dsk_w_cd: u16,
    /// Total entries on current disk
    pub dsk_entries: u16,
    /// Total file entries in zip file
    pub tot_entries: u16,
    /// Size of central directory
    pub cd_sz: u32,
    /// Index within file where Central Directory starts
    pub cd_offset: u32,
    /// Comment length
    pub cmt_len: u16,
    /// Zip File comment field
    pub zip_cmt: String,
}

bitflags! {
    /// General Purpose PKZip bitflags field
    pub struct ZipFlags: u16 {
        /// Zip file is encrypted
        const ENCRYPTED =         0b_0000_0000_0000_0001;
        /// Maximum compression
        const MAXIMUM =           0b_0000_0000_0000_0010; // \
        /// Fast compression                              //  \
        const FAST =              0b_0000_0000_0000_0100; //   |--- Only apply under deflation.
        /// Super fast compression                        //  /
        const SUPER_FAST =        0b_0000_0000_0000_0110; // /
        /// Uses separate data descriptor chunk
        const DATA_DESCRIPTOR =   0b_0000_0000_0000_1000;
        /// Uses enhanced deflate
        const ENHANCED_DEFLATE =  0b_0000_0000_0001_0000;
        /// Uses patch data extension
        const PATCH_DATA =        0b_0000_0000_0010_0000;
        /// Uses "strong encryption" extension
        const STRONG_ENCRYPTION = 0b_0000_0000_0100_0000;
        /// UTF filenames
        const UTF =               0b_0000_1000_0000_0000;
        /// CD Records are scrubbed of data to harden encryption
        const MASKED_CD_RECORDS = 0b_0010_0000_0000_0000; // Only applies under encryption
    }
}

#[derive(Clone, Debug, PartialEq)]
/// A Central Directory Header
pub struct CD {
    /// Version used to produce (can include OS flags and other metadata)
    pub v_made_by: u16,
    /// Version needed to decompress
    pub v_needed: u16,
    /// General Purpose flags
    pub gp_flags: ZipFlags,
    /// Compression Method (generally speaking this will be deflate/0x8 but not necessarily).
    pub method: u16,
    /// Timestamp (stored here in unix epoch)
    pub timestamp: u32,
    /// Data Descriptor chunk (contains file size and checksum)
    pub dd: DD,
    /// Filename Length
    pub fn_len: u16,
    /// Extra Field Length
    pub ef_len: u16,
    /// File comment length
    pub fc_len: u16,
    /// Disk number start (zip files can be spread across multiple "disks").
    pub dsk_no_s: u16,
    /// Internal Attributes
    pub int_attr: u16,
    /// External attributes
    ///
    /// Haven't seen a use for these.
    pub ext_attr: u32,
    /// Local File Header Offset
    ///
    /// A pointer relative to the start of the zip file for the corresponding LF header. This
    /// helps us locate other pages with the corresponding headers.
    pub lf_offset: u32,
    /// Filename
    pub filename: String,
    //ef: Sometype,
    //filecomment: SomeType,
}

#[derive(Clone, Debug, PartialEq)]
/// An instance of a CD Header found and parsed (wrapping the location in the original dataset with
/// the header object).
pub struct CDInstance(usize, CD);

impl CD {
    /// From an existing FragSys with a given pointer to a CD magic spawn a CD model
    fn new(fs: &mut FragSys, ptr: usize) -> Result<Self, Error> {
        // opportunistically parse, or alternatively don't panic if fail.
        match parse_cd(&fs.data[ptr..]) {
            Done(_, cd) => {
                debug!("Successfully parsed CD: {:?}",cd);
                Ok(cd)
            }
            nom::IResult::Error(_) => Err(Error::new(
                ErrorKind::Other,
                format!("Failed to parse cd at {}", ptr),
            )),
            _ => Err(Error::new(ErrorKind::Other, "Incomplete")),
        }
    }

    fn from_data(data: &[u8], ptr: usize) -> Result<Self, Error> {
        match parse_cd(&data[ptr..]) {
            Done(_,cd) => {
                debug!("Successfully parsed CD: {:?}",cd);
                Ok(cd)
            }
            nom::IResult::Error(_) => Err(Error::new(
                ErrorKind::Other,
                format!("Failed to parse cd at {}", ptr),
            )),
            _ => Err(Error::new(ErrorKind::Other, "Incomplete")),
        }
    }

    fn to_lf(&self) -> LF {
        LF{dd: self.dd, ef_len: self.ef_len, fn_len: self.fn_len, method: self.method,
            v_needed: self.v_needed, timestamp: self.timestamp, filename: self.filename.clone(), gp_flags: self.gp_flags}
    }
}

impl Vectorizable for CD {
    type Output = Euclid<[f64; 5]>;

    fn to_euclidean(&self) -> Self::Output {
        // Time
        // method
        // z_ver
        // z_ver_needed
        // utf
        // datadescriptor
        Euclid(
            [f64::from(self.timestamp),          // Time/date
                f64::from(self.method),             // Method
                f64::from(self.v_made_by),          // Version used
                f64::from(self.v_needed),           // Version Needed
                f64::from(self.gp_flags.bits()),    // Flags cast to number, could be better as
                                                    // individual GF dimensions
        ],
        )
    }
}

impl Instance for CDInstance {
    type Item = CD;

    fn ptr(&self) -> usize {
        self.0
    }

    fn header(&self) -> &Self::Item {
        &self.1
    }

    fn cluster(data: &[Self], k: usize) -> Result<Vec<Cluster<Self>>, ClusteringError> {
        ::analysis::cluster(data, k)
    }
}

#[derive(Debug, PartialEq)]
/// A Local File Header
pub struct LF {
    /// Version needed to decompress
    ///
    /// (In practical terms this is often in practical terms used as a flag for the type of
    /// compressed object, so as to determine whether the file is a folder, or a file, or some
    /// other marker within the zip file)
    pub v_needed: u16,
    /// General purpose zip flags
    pub gp_flags: ZipFlags,
    /// Compression method
    pub method: u16,
    /// Timestamp (stored here in unix epoch)
    pub timestamp: u32,
    /// Data Descriptor chunk
    pub dd: DD,
    /// Filename Length
    pub fn_len: u16,
    /// Extra Field Length
    pub ef_len: u16,
    /// Filename
    pub filename: String,
    // ef_len:  Sometype,
}

fn u16_to_le(u: u16) -> [u8;2] {
    return [(u&0xff) as u8, (u>>8) as u8]
}

fn u32_to_le(mut u: u32) -> [u8;4] {
    let mut x = [0u8;4];
    for i in 0..4 {
        x[i] = (u & 0xff) as u8;
        u >>= 8;
    }
    x
}

fn dostime_to_bytes(ts: u32) -> [u8;4] {
    use chrono::{NaiveDate, NaiveDateTime, Timelike, Datelike};
    let mut res = [0u8;4];
    let datetime = NaiveDateTime::from_timestamp(ts as i64, 0);
    let time = ((datetime.hour() << 11) | (datetime.minute() <<5) | (datetime.second()/2)) as u16;
    for (i,v) in u16_to_le(time).iter().enumerate() {
        res[i] = *v;
    }
    let date = ((((datetime.year() - 1980) << 9) as u32) | (datetime.month() << 5) | datetime.day()) as u16;
    for (i,v) in u16_to_le(date).iter().enumerate() {
        res[i+2] = *v;
    }
    res
}

impl LF {
    pub fn from(cd: &CD) -> Self {
        cd.to_lf()
    }

    pub fn unparse(&self) -> Vec<u8> {
        use std::mem::transmute;
        let mut res = Vec::new();
        res.extend_from_slice(b"PK\x03\x04");
        res.extend_from_slice(&u16_to_le(self.v_needed));
        res.extend_from_slice(&u16_to_le(self.gp_flags.bits));
        res.extend_from_slice(&u16_to_le(self.method));
        res.extend_from_slice(&dostime_to_bytes(self.timestamp));
        if (self.gp_flags.contains(DATA_DESCRIPTOR)) {
            res.extend_from_slice(&[0u8;12]);
        } else {
            res.extend_from_slice(&self.dd.unparse());
        }
        res.extend_from_slice(&u16_to_le(self.fn_len));
        res.extend_from_slice(&u16_to_le(self.ef_len));
        res.extend_from_slice(self.filename.as_bytes());
        //debug!("Unparsed to {:?}", res);
        res
    }
}

/// A Data Descriptor Chunk
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DD {
    /// CRC32 checksum over zipped value.
    pub crc32: u32,
    /// Compressed size
    pub z_sz: u32,
    /// Uncompressed size
    pub u_sz: u32,
}

impl DD {
    pub fn unparse(&self) -> [u8;12] {
        let mut res = [0u8;12];
        for (i,v) in u32_to_le(self.crc32).iter().enumerate() {
            res[i] = *v;
        }
        for (i,v) in u32_to_le(self.z_sz).iter().enumerate() {
            res[i+4] = *v;
        }
        for (i,v) in u32_to_le(self.u_sz).iter().enumerate() {
            res[i+8] = *v;
        }
        debug!("Unparsed DD: ({},{},{}) to {:?}", self.crc32, self.z_sz, self.u_sz, res);
        res
    }
}


impl FragSys {
    /// Create a model for a fragmented FS from a `File`
    pub fn from_file(file: &mut File, page_sz: usize) -> Result<Self, Error> {
        let len = file.metadata()?.len() as usize;
        let mut reader = BufReader::new(file);
        let mut bytes = Vec::with_capacity(len);
        let len_read = reader.read_to_end(&mut bytes)?;
        if len_read != len {
            return Err(Error::new(
                ErrorKind::Other,
                "length read doesn't match length available",
            ));
        }

        // Check dat uglycast
        let pg_count = len / page_sz + (if len % page_sz > 0 { 1 } else { 0 });

        // Initialize Big Ole Page Map
        let pages = (0..pg_count)
            .map(|pg| {
                let start = pg * page_sz;
                let stop = page_sz * (pg + 1);
                Page::Assigned(start..stop)
            })
            .collect();

        Ok(Self {
            data: bytes,
            page_sz: page_sz,
            pages: pages,
        })
    }

    /// Search FragSys for a given page, and if found, pull the page from the FS.
    pub fn get_pg_for_addr(&mut self, address: usize) -> Option<Page> {
        let matches: Vec<usize> = self.pages
            .iter()
            .enumerate()
            .filter_map(|(i, page)|
                        if page.contains(address) {
                            Some(i)
                        } else {
                            None
                        })
            .collect();
        match matches.len() {
            count if count == 1 => {
                let pg = self.pages.swap_remove(matches[0]);
                Some(pg)
            }
            _ => None,
        }
    }

    /// Return Page Size for FS
    pub fn page_sz(&self) -> usize {
        self.page_sz
    }

    //    /// Update `FragSys` with fresh page size
    //    pub fn with_page_sz(&mut self, page_sz: usize) {
    //        self.page_sz = page_sz;
    //    }

    /// A currently somewhat inefficient function for searching for Zip header magic values
    fn find_bytes(&self, pattern: &[u8]) -> Vec<usize> {
        let range = self.data.len() - pattern.len();
        let mut findings = Vec::new();
        for i in 0..range {
            if self.data[i..(i + 4)] == *pattern {
                findings.push(i);
            }
        }
        findings
    }

    /// Find all identifiable EOCD magics, returning a collection of pointers.
    fn find_eocds(&self) -> Vec<usize> {
        self.find_bytes(b"PK\x05\x06")
    }

    /// Find and return a collection of ZipFile instances
    ///
    /// This is performed by searching for EOCD magic values and then parsing them with nom.
    pub fn find_zips(&mut self) -> Vec<ZipFile> {
        let eocd_list = self.find_eocds();
        let mut zips = Vec::with_capacity(eocd_list.len());
        for ptr in eocd_list {
            match ZipFile::new(self, ptr) {
                Ok(zf) => zips.push(zf),
                Err(e) => {
                    error!("Error: {}", e);
                }
            };
        }
        zips
    }

    /// Return a collection of instances of CD Headers recognised and parsed with nom.
    pub fn find_cds(&mut self) -> Vec<CDInstance> {
        let cd_ptrs = find_bytes(&self.data, b"PK\x01\x02");
        let mut results = Vec::with_capacity(cd_ptrs.len());
        for ptr in cd_ptrs {
            match CD::new(self, ptr) {
                Ok(cd) => results.push(CDInstance(ptr, cd)),
                Err(e) => {
                    error!("Error: {}", e);
                }
            }
        }
        results
    }

    /// Return a collection of pointers to instances of Local File Header magics.
    pub fn find_lfs(&self) -> Vec<usize> {
        self.find_bytes(b"PK\x03\x04")
    }

    pub fn find_lf(&self, lf: &LF, lfp: &[usize]) -> Option<usize> {
        let bytes = lf.unparse();
        for i in lfp {
            if &self.data[*i..(*i+bytes.len())] == bytes.as_slice() {
                return Some(*i)
            }
        }
        None
    }
}

/// A currently somewhat inefficient function for searching for Zip header magic values
fn find_bytes(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    let mut cursor = 0;
    let mut findings = Vec::new();
    while let Some(ptr) = data[cursor..].windows(pattern.len()).position(|window| window == pattern) {
        findings.push(ptr + cursor);
        //debug!("Cursor moving to: {}", cursor + ptr + pattern.len());
        cursor = cursor + ptr + pattern.len();
    }
    findings
}
