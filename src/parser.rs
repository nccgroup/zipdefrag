//! Module containing the various nom adapters for parsing Zip file header chunks into the
//! appropriate data structures.

use nom::{le_u16, le_u32};
use chrono;
use chunks::{EOCD, CD, LF, DD, ZipFlags};

named!(#[doc = "Try to parse an `EOCD` End of Central Directory header"],
       pub parse_eocd<&[u8],EOCD>,
       do_parse!(
           tag!("PK\x05\x06")  >>
           dsk_no:      le_u16 >>
           dsk_w_cd:    le_u16 >>
           dsk_entries: le_u16 >>
           tot_entries: le_u16 >>
           cd_sz:       le_u32 >>
           cd_offset:   le_u32 >>
           cmt_len:     le_u16 >>
           zip_cmt: take_str!(cmt_len)>>
           (EOCD{
               dsk_no:      dsk_no,
               dsk_w_cd:    dsk_w_cd,
               dsk_entries: dsk_entries,
               tot_entries: tot_entries,
               cd_sz:       cd_sz,
               cd_offset:   cd_offset,
               cmt_len:     cmt_len,
               zip_cmt:     String::from(zip_cmt),
           })
           )
       );

named!(#[doc = "Parse an MS-DOS formatted time to HMS tuple"],
    pub parse_dostime<&[u8],(u32,u32,u32)>,
    verify!(
        do_parse!(
            t: le_u16 >>
            (
                u32::from((t>>11) & 0x1f),  // Hours
                u32::from(t>>5 & 0x3f),     // Minutes
                u32::from(2*(t&0x1f))       // Seconds
            )
       ),
       |(h,m,s)| (h < 24) && (m < 60) && (s < 60)
    ));

named!(#[doc = "Parse an MS-DOS formatted date to YMD tuple. Damn you Bill"],
       pub parse_dosdate<&[u8],(i32,u32,u32)>,
    verify!(
        do_parse!(
            d: le_u16 >>
            (
                i32::from((d>>9)&0x7f)+1980,   // Year
                u32::from((d>>5)&0xf),         // Month
                u32::from(d&0x1f))             // Date
            ),
        |(y,m,d)| (y >= 1970) && (m <= 12) && (m > 0) && (d <= 31) && (d > 0)
        )
    );

named!(#[doc = "Parse an MS-DOS formatted datetime and convert to epoch"],
       pub parse_dosdatetime<&[u8],u32>,
       do_parse!(
           t: parse_dostime            >>
           d: parse_dosdate            >>
            (
                chrono::NaiveDate::from_ymd(d.0,d.1,d.2)
                    .and_hms(t.0,t.1,t.2)
                    .timestamp() as u32
            )
       )
    );

named!(#[doc = "Parse a `CD` Central Directory header"],
       pub parse_cd<&[u8],CD>,
       do_parse!(
           tag!(b"PK\x01\x02")           >>
           v_made_by:  le_u16            >> // Version data ought to be raw bytes but
                                            // too lazy to write type specific parser
           v_needed:   le_u16            >>
           gp_flags:   le_u16            >>
           method:     le_u16            >>
           timestamp:  parse_dosdatetime     >> // Dos time data parsed to unix epoch w00t w00t
           dd:         parse_dd          >>
           fn_len:     le_u16            >>
           ef_len:     le_u16            >>
           fc_len:     le_u16            >>
           dsk_st:     le_u16            >>
           int_attr:   le_u16            >>
           ext_attr:   le_u32            >>
           lf_offset:  le_u32            >>
           filename:   take_str!(fn_len)   >>
           (CD {
               v_made_by:  v_made_by,
               v_needed:   v_needed,
               gp_flags:   ZipFlags::from_bits_truncate(gp_flags),
               method:     method,
               timestamp:  timestamp,
               dd:         dd,
               fn_len:     fn_len,
               ef_len:     ef_len,
               fc_len:     fc_len,
               dsk_no_s:   dsk_st,
               int_attr:   int_attr,
               ext_attr:   ext_attr,
               lf_offset:  lf_offset,
               filename:   String::from(filename),
                })
            )
       );

named!(#[doc = "Parse a `LF` local file header"],
       pub parse_lf<&[u8],LF>,
       do_parse!(
           tag!(b"PK\x03\x04")          >>
           v_needed:  le_u16            >>
           gp_flag:   le_u16            >>
           method:    le_u16            >>
           timestamp: parse_dosdatetime     >>
           dd:        parse_dd          >>
           fn_len:    le_u16            >>
           ef_len:    le_u16            >>
           filename:  take_str!(fn_len) >>
           (LF{
               v_needed: v_needed,
               gp_flags: ZipFlags::from_bits_truncate(gp_flag),
               method: method,
               timestamp: timestamp,
               dd: dd,                      // Need to do wrap this in a result for
                                            // case where DD elsewhere
               fn_len: fn_len,
               ef_len: ef_len,
               filename: String::from(filename),
           }))
       );

named!(#[doc = "Parse a Data Descriptor"],
       pub parse_dd<&[u8],DD>,
       do_parse!(
            opt!(tag!(b"PK\x07\x08")) >> // Sometimes we're looking for this data
                                         // as a separate header, sometimes it's
                                         // buried in an LFH/CD
            crc: le_u32   >>
            z_sz: le_u32  >>
            u_sz: le_u32  >>
            (DD{
                crc32: crc,
                z_sz:  z_sz,
                u_sz:  u_sz,
            })
        )
    );

#[cfg(test)]
mod tests {
    use parser::*;

    #[test]
    fn dostimestamp() {
        let raw_dostimestamp = b"\x69\x8c\x9d\x48";
        let (_, parsed) = parse_dosdatetime(raw_dostimestamp).unwrap();
        let expected = chrono::NaiveDate::from_ymd(2016, 4, 29)
            .and_hms(17, 35, 18)
            .timestamp() as u32;

        assert_eq!(parsed, expected);
    }

    #[test]
    fn eocd_test() {
        let raw_eocd = b"PK\x05\x06\x00\x00\x00\x00\x9c\x03\x9c\x03\xbf\
                           \xdb\x00\x00\nm\t\x00\x00\x00\xff\xff\xff\xff\
                           \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
                           \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\
                           \xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

        let (_, parsed) = parse_eocd(raw_eocd).unwrap();
        assert_eq!(parsed.tot_entries, 924); // Zip file has 924 records
    }

    #[test]
    fn cd_headertest() {
        //macro_rules! nom_res {
        //        ($p:expr,$t:expr) => ($p($t).to_result())
        //}

        // raw cd data
        let raw_cd = b"PK\x01\x02\x14\x00\x14\x00\x08\x08\x08\x00i\x8c\
                       \x9dH\x1f\xcd]z/\x11\x00\x00,'\x00\x00\x07\x00\
                       \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                       \xd1\x02\x00\x00b.classPK\x01\x02\x14\x00\x14";

        let (_, parsed) = parse_cd(raw_cd).unwrap();
        assert_eq!(parsed.filename, "b.class".to_string());
    }

    #[test]
    fn lf_headertest() {
        let raw_lf = b"PK\x03\x04\n\x00\x00\x08\x08\x00N\x83EIRa\xe7Sh\
                       \x00\x00\x00u\x00\x00\x00\x08\x00\x00\x00bc.cla\
                       ss;\xf5o\xd7>\x06\x06\x06\x03\x06.v\x06\x0ev\x06\
                       N.\x06&\x06\x16";
        let (_, parsed) = parse_lf(raw_lf).unwrap();
        assert_eq!(parsed.filename, "bc.class".to_string());

    }
}
