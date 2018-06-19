import datetime
import calendar
import sys
import struct
import mmap
from aenum import Enum,Flag
from scipy.cluster.vq import kmeans2
from scipy.stats import entropy
from collections import Counter
from hashlib import md5
from zlib import crc32

"""
Experimentally, any page with a lower entropy score than 1 calculated using the
following method is a very poor candidate for a data page. Some do exist
(specifically pages where a small amount of file data is recorded amongst a
bunch of empty bytes -- not a case which concerns us recovering multipage zip
files when we deterministically know where the first and last page is).
Even this source code file (which aren't wildly high entropy) scores just over 3.
All the same, a safer score for filtering out false results would be 0.35. This
pretty much does empty pages and very nearly empty pages.
"""
def page_entropy(page_data):
    ctr = Counter(page_data) # Do a count of values identified over a set
    return entropy(ctr.values()) # Get the Shannon entropy for the distribution
                                 # of resulting values found.

class Chunk(Enum):
    EOCD = b"PK\x05\x06"
    LFH = b"PK\x03\x04"
    CD = b"PK\x01\x02"
    DDesc = b"PK\x07\x08"

class ZMethod(Enum):
    NoCompression = 0
    Shrunk = 1
    CmpFactor1 = 2
    CmpFactor2 = 3
    CmpFactor3 = 4
    CmpFactor4 = 5
    Imploded = 6
    Deflated = 8
    EnhancedDeflated = 9
    PKWareDCLImploded = 10
    BZ2 = 12
    LZMA = 14
    IBMTerse = 18
    IBMLZ77z = 19
    PPMdV1R1 = 98

class ZFlags(Flag):
    Encrypted = 0x1
    Opt1 = 0x2
    Opt2 = 0x4
    DataDescriptor = 0x8
    EnhDeflation = 0x10
    PatchData = 0x20
    StrongEnc = 0x40
    UTF8 = 0x800
    MaskHdrValues = 0x2000

    def check(self,flag):
        return flag in self

def findPageIdxForPtr(slice_list, ptr):
    for (idx,s) in enumerate(slice_list):
        if s and ptr >= s.start and ptr < s.stop:
            return idx
    return None

"""
An abstract model of an unknown fragmented file system
"""
class FragSys:
    def __init__(self, path, pageSz):
        self.pageSz = pageSz
        self.data = None
        self.fragments = []
        self.zipFiles = []
        self.fileHeaders = []
        self.CDHeaders = []

        if not path==None:
            with open(path) as f:
                # mmap the file rather than just reading it into memory to avoid
                # memory issues on larger files
                self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            self.fragments = [slice(x*self.pageSz, (x+1) * self.pageSz) for x in range(0,len(self.data)//pageSz)]
        # Otherwise initialise our own data map

    def getChunks(self, chType):
        cursor = 0
        data = self.data
        while True:
            cursor = data.find(chType.value, cursor)
            if cursor == -1:
                break
            else:
                if chType == Chunk.EOCD:
                    z = zipFile.from_data(data[cursor:])
                    z.ptr = cursor
                    if (self.pageSz - (cursor % self.pageSz) < 20):
                        z.boundaryTaint = True

                    (z.start_offset,z.pg_ct) = self.getStartOffset(z, cursor)
                    z.fragments = [None for i in range(z.pg_ct)]
                    self.zipFiles.append(z)
                elif chType == Chunk.LFH:
                    l = LFH.from_data(data[cursor:])
                    l.ptr = cursor
                    if (self.pageSz - (cursor % self.pageSz) < 30):
                        l.boundaryTaint = True
                    self.fileHeaders.append(l)
                elif chType == Chunk.CD:
                    c = CDH.from_data(data[cursor:])
                    c.ptr = cursor
                    if (self.pageSz - (cursor % self.pageSz) < 0x46):
                        c.boundaryTaint = True
                    self.CDHeaders.append(c)
                cursor += 1

    def getStartOffset(self, z, cursor):
        eocd_page_offset = cursor % self.pageSz
        eocd_file_offset = z.cd_offset + z.cdSize
        start_offset = self.pageSz - \
                ((eocd_file_offset - eocd_page_offset) % self.pageSz)
        page_count = int(eocd_page_offset > 0) + int(start_offset > 0) +\
               (eocd_file_offset - eocd_page_offset - start_offset) /  \
               self.pageSz
        return (start_offset,page_count)

    def findEOCDs(self):
        self.getChunks(Chunk.EOCD)

    def findLFHs(self):
        self.getChunks(Chunk.LFH)

    def findCDs(self):
        self.getChunks(Chunk.CD)

    def classifyChunks(self, chType):
        if chType == Chunk.LFH:
            chunks = [i for i in self.fileHeaders]
        elif chType == Chunk.CD:
            chunks = [i for i in self.CDHeaders]

        number = len(self.zipFiles)

        # Eliminate chunks with invalid datetime.
        chunks = [c for c in chunks if not c.last_mod_datetime == None]

        centroids,classes = kmeans2([i.sig_vector() for i in chunks], number, minit='points')
        silos = [[j[1] for j in zip(classes,chunks) if j[0]==i] for i in range(number)]
        return zip(silos,centroids)

    def renderFragList(self, fragments):
        data = b""
        for f in fragments:
            if f is None:
                data += "\x00"*self.pageSz
            else:
                data += self.data[f]
        return data

"""Parse a int encoded PKZip flags field into a dict of boolean flags

:param flags: the Flags value as a python int
:return: Collection of labelled boolean flag values (not checked exhaustively)
:rtype: dict
"""
def parse_flags(flags):
    return {
            'encrypted': bool(flags & 1),
                'data-desc': bool(flags >> 3 & 1),
                'patchdata': bool(flags >> 5 & 1),
                'strong-encryption': bool(flags >> 6 & 1),
                'utf-8': bool(flags >> 11 & 1)
            }

"""Parse a dos time and date to a python datetime"""
def parse_dos_datetime(t, d):
    year = (d >> 9 & 0x7f) + 1980
    month = d >> 5 & 0xf
    if month > 12:
        return None
    day = d & 0x1f # Already clamped to maxdays
    hour = (t>>11 & 0x1f)
    if hour > 23:
        return None
    minute = (t>>5 & 0x3f)
    if minute > 59:
        return None
    seconds = ((t & 0x1f)*2)
    if seconds > 59:
        return None
    return datetime.datetime(year,month,day,
            hour=hour,
            minute=minute,
            second=seconds)

class LFH(object):
    """
    Parse an Local File Header from a given byte string slice
    """
    @classmethod
    def from_data(cls, data):
        l = LFH()
        if len(data) < 0x1d:
            return None
        sig = struct.unpack('I',data[:4])[0]
        if not sig == 0x04034b50:
            print("Sig not found")
            return None
        l.zVer = struct.unpack('h',data[4:6])[0]
        l.flags = ZFlags(struct.unpack('h',data[6:8])[0])
        l.comp_method = ZMethod(struct.unpack('h',data[8:10])[0])
        l.last_mod_t = struct.unpack('h',data[10:12])[0]
        l.last_mod_d = struct.unpack('h',data[12:14])[0]
        l.last_mod_datetime = parse_dos_datetime(l.last_mod_t, l.last_mod_d)
        l.crc32 = struct.unpack('I',data[14:18])[0]
        l.cSize = struct.unpack('I',data[18:22])[0]
        l.uSize = struct.unpack('I',data[22:26])[0]
        l.fnLen = struct.unpack('h',data[26:28])[0]
        l.cmtLen = struct.unpack('h',data[28:30])[0]
        l.fn = data[30:30+l.fnLen]
        l.cmt = data[30+l.fnLen:30+l.fnLen+l.cmtLen]

        return l
    """
    Convert a Local File Header to a floating point vector signature
    """
    def sig_vector(self):
        return [
                float(calendar.timegm(self.last_mod_datetime.utctimetuple())),
                float(self.comp_method.value)] + \
              [float(flag in self.flags) for flag in list(ZFlags)]

    def __str__(self):
        s = ("LFH:{%s -- verNeeded: %r, method: %r, crc32: 0x%x, cSz: 0x%x, datetime: %s, ptr: 0x%x}" %
                (self.fn, self.zVer, self.comp_method, self.crc32,self.cSize,
                    self.last_mod_datetime, self.ptr))
        return s

"""
Central Directory Header
"""
class CDH(object):
    """
    Parse a Central Directory header from a given byte slice (presuming it has
    the correct magic header)
    """
    @classmethod
    def from_data(cls, data):
        c = CDH()
        if len(data) < 0x2e:
            print("Too short CD")
            return None
        sig = struct.unpack('I',data[:4])[0]

        if not sig == 0x02014b50:
            print("sig not found")
            print sig
            return None
        c.z_ver = struct.unpack('H',data[4:6])[0]
        c.z_v_needed = struct.unpack('H',data[6:8])[0]
        c.flags = struct.unpack('H',data[8:0xa])[0]
        method = struct.unpack('H',data[0xa:0xc])[0]
        if method in [zmeth.value for zmeth in ZMethod]:
            c.method = ZMethod(method)
        else:
            c.method = None
        c.last_mod_t = struct.unpack('H',data[0xc:0xe])[0]
        c.last_mod_d = struct.unpack('H',data[0xe:0x10])[0]
        c.last_mod_datetime = parse_dos_datetime(c.last_mod_t,c.last_mod_d)
        c.crc32 = struct.unpack('I',data[0x10:0x14])[0]
        c.c_sz = struct.unpack('I',data[0x14:0x18])[0]
        c.u_sz = struct.unpack('I',data[0x18:0x1c])[0]
        c.fn_len = struct.unpack('h',data[0x1c:0x1e])[0]
        c.xf_len = struct.unpack('h',data[0x1e:0x20])[0]
        c.fc_len = struct.unpack('h',data[0x20:0x22])[0]
        c.dsk_start = struct.unpack('h',data[0x22:0x24])[0]
        c.int_attr = struct.unpack('h',data[0x24:0x26])[0]
        c.ext_attr = struct.unpack('I',data[0x26:0x2a])[0]
        c.lf_offset = struct.unpack('I',data[0x2a:0x2e])[0]
        c.fn = data[0x2e:0x2e+c.fn_len]
        c.xf = data[0x2e + c.fn_len: 0x2e + c.fn_len + c.xf_len]
        c.fc = data[0x2e + c.fn_len + c.xf_len: 0x2e + c.fn_len + c.xf_len +
                c.fc_len]
        c.len = 0x2e + c.fn_len + c.xf_len + c.fc_len

        return c

    def __str__(self):
        return ("CD:{zVer: %x, zVerNeeded: %d, compressedSize: %d, filename: %s, lfOffset: 0x%x, flags: %r, ptr: 0x%x }" %
                (self.z_ver, self.z_v_needed, self.c_sz, self.fn, self.lf_offset, self.flags, self.ptr))

    """
    Convert a Central Directory Header to a floating point signature vector for
    clustering.
    """
    def sig_vector(self):
        return [
                float(calendar.timegm(self.last_mod_datetime.utctimetuple())),
                float(self.method.value),
                float(self.z_ver),
                float(self.z_v_needed)] + \
              [float(bool(flag.value & self.flags)) for flag in list(ZFlags)]

    """
    Derive the corresponding Local File Header for a given Central Directory
    header
    """
    def to_LFH(self):
        lfh = "PK\x03\x04"
        lfh += struct.pack('H',self.z_v_needed)
        lfh += struct.pack('H',self.flags)
        lfh += struct.pack('H',self.method.value)
        lfh += struct.pack('H',self.last_mod_t)
        lfh += struct.pack('H',self.last_mod_d)
        if ZFlags.DataDescriptor in ZFlags(self.flags):
            lfh += "\0"*12
            # We need to zero out all of the data descriptor fields
        else:
            lfh += struct.pack('I',self.crc32)
            lfh += struct.pack('I',self.c_sz)
            lfh += struct.pack('I',self.u_sz)
        lfh += struct.pack('h',self.fn_len)
        lfh += struct.pack('h',self.fc_len)
        lfh += self.fn

        return lfh

    """
    Derive the corresponding Data Descriptor chunk for a given Central directory
    Header
    """
    def to_DD(self):
        dd = "PK\x07\x08"
        dd += struct.pack('I',self.crc32)
        dd += struct.pack('I',self.c_sz)
        dd += struct.pack('I',self.u_sz)
        return dd


"""
Actually an abstraction for EOCD structures (with associated page and data
buffers, ultimately)
"""
class zipFile(object):

    @classmethod
    def from_data(cls, data):
        z = zipFile()
        # Minimum of 20 bytes needed consecutive to avoid risk of inter-page
        # splitting based corruption
        if len(data) < 20:
            return None
        sig = struct.unpack('I',data[:4])[0]
        # check signature is valid or bail
        if not sig == 0x06054b50:
            print("sig not found")
            print(sig)
            return None
        z.diskNo = struct.unpack('h',data[4:6])[0]
        z.diskNoForCD = struct.unpack('h',data[6:8])[0]
        z.diskEntries = struct.unpack('h',data[8:10])[0]
        z.totalEntries = struct.unpack('h',data[10:12])[0]

        if not z.diskEntries == z.totalEntries:
            return None

        # Should use this to validate guesses about recovered CD when full
        z.cdSize = struct.unpack('I',data[12:16])[0]
        z.cd_offset = struct.unpack('I',data[16:20])[0]
        z.cmtLength = struct.unpack('h',data[20:22])[0]
        z.comment = data[22:22+z.cmtLength]
        z.tot_sz = z.cmtLength + 0x16 + z.cdSize + z.cd_offset
        return z

    def __str__(self):
        return ("EOCD:{diskNo: %d,diskEntries: %d,totalEntries: %d,cdSize: 0x%x, cd_offset: 0x%x, comment: \"%s\", fileSize: %d }" %
                (self.diskNo, self.diskEntries, self.totalEntries, self.cdSize, self.cd_offset, self.comment, self.tot_sz))

    # Each of these represents a separate zip file to look for.
    # Stuff to probably ignore for now:
    # Number of this disk
    # Disk where cd starts.
    # Stuff to pay attention to:
    # - Number of CD records on this disk (we can count against these for a full
    #   set
    # - Total number of CD records (if different from previous revise initial
    #   assumptions).
    # Size of CD in bytes - can we use this to validate guesses about the recovered CD?
    # CD Offset - This is also the length of the LFH chunks up to the end, and
    # may be used for validating predictions.


# The current organisation of the main routine is purely exploring a proof of
# concept for the existance of a viable reconstruction method.

# Additionally, there are significant issues with consistency between snake,
# camel, etc casing and variable naming conventions owing to the rapid
# prototyping approach to development.
if __name__=="__main__":
    path = sys.argv[1]
    if len(sys.argv) > 2:
        pageSz = int(sys.argv,0)
    else:
        pageSz = 0x400           # Default to a kilobyte for page size
    f = FragSys(path,pageSz)
    f.findEOCDs()
    print "Found %d zip files (EOCD chunks)" % len(f.zipFiles)
    for i in f.zipFiles:
        print "Header: %s" % i

    f.findLFHs()

    print "Found %d Local File Headers" % len(f.fileHeaders)

    f.findCDs()

    print "Found %d Central Directory headers" % len(f.CDHeaders)

    print "Using kmeans2 to match CD headers to %d distinct zip files" % len(f.zipFiles)
    # Classify known chunks by central directory "centroid"
    classified = f.classifyChunks(Chunk.CD)

    # Surprisingly effective way of reconstructing Central Directory pages
    # in correct order, and repairing cases where records are split
    # across page boundaries

    for i in range(len(classified)):
        print "%d similar CD chunks for zip file %d" % (len(classified[i][0]),
                (i+1))

    for (chunklist,centroid) in classified:
        print "Classifier Centroid:"
        print centroid
        print len(chunklist)
        data = ""
        # Get CD header correlating to lowest offset
        pages = []
        last = None
        while len(chunklist) > 0:
            chunk = min(chunklist, key=lambda c: c.lf_offset)
            if all(chunk.lf_offset > z.cd_offset for z in f.zipFiles):
                break
            last = chunk
            page_idx = findPageIdxForPtr(f.fragments, chunk.ptr)
            if page_idx:
                pages.append(f.fragments[page_idx])
                f.fragments.pop(page_idx)
            else:
                page = findPageIdxForPtr(pages, chunk.ptr)
                if not page:
                    print "CD page lost somewhere? ptr: %d, fn: %s" % (chunk.ptr, chunk.fn)

            chunklist.remove(chunk)
        lastpage = pages[-1]

        for z in f.zipFiles:
            if findPageIdxForPtr([lastpage],z.ptr) <> None:
                z.cdpages = pages

    # We need to re-parse the CD records for each and get an ordered list of
    # expected LFH headers in the zip file so we can estimate the page locations
    # and place them.

    # We then need to check if data descriptors are in use to help find end
    # pages.

    # We then need to eliminate pages already found and locate combinations of
    # pages remaining that to fill the appropriate gaps in our final zip
    # document.

    for zip_idx,z in enumerate(f.zipFiles):
        print("Dumping recovered CD record for zip file %d:" % zip_idx)

        # Render cdpages to temporary file system in order to
        # find, parse and use CD records
        tf = FragSys(None, 0x400)
        tf.data = "".join([f.data[p] for p in z.cdpages])

        # index in new data structure of the first cdpage
        cd_start_page = (z.start_offset + z.cd_offset) / f.pageSz

        tf.fragments = ([None] * cd_start_page) + z.cdpages

        # Find the starting point in the page of the initial cd header
        loc_cdoffs = tf.data.find('PK\x01\x02')
        LFpagecount = (z.cd_offset - loc_cdoffs) / f.pageSz

        tf.findCDs()

        print "Number of of recovered CD chunks: %d" % len(tf.CDHeaders)

        for cd in tf.CDHeaders:
            # Iterate over all CDs
            # Generate the corresponding LFH to search the data for it
            lfh = cd.to_LFH()
            ptr = []
            i = 0
            while f.data[i:].find(lfh) <> -1:
                p = f.data[i:].find(lfh)
                i = p+1
                ptr += [p]

            if len(ptr) == 1:
                # We want to avoid cases where we've got too many candidates.
                # We can't trust them, so we only handle cases where 1 pointer
                # is returned

                (ptr,) = ptr

                new_pg_idx = (cd.lf_offset + z.start_offset) / f.pageSz
                page_idx = findPageIdxForPtr(f.fragments, ptr)

                # Here's the meat of our solution
                if page_idx:
                    tf.fragments[new_pg_idx] = f.fragments[page_idx]
                    f.fragments.pop(page_idx)
                elif not findPageIdxForPtr(tf.fragments, ptr):
                    print "Somehow this lost LF page: %d" % ptr

            if ZFlags.DataDescriptor in ZFlags(cd.flags):
                dd = cd.to_DD()
                # TODO: do some searching for data descriptor chunk and add
                # the page in the right place if found and it doesn't exist
                # yet in our zip file fragments list

        # TODO: For each incomplete CD, starting with the smallest ones, we
        # should find missing pages.
        # Strategies for this include:
        # - Eliminating low-entropy pages
        # - Possibly finding other ways to reduce possible missing pages?
        # - Using CRC values to validate the missing pages
        # - Shifting fragment onto temporary file fragments list each time
        # removing from the outstanding fragment pool to reduce complexity of
        # subsequent searches

        tally = 0
        emptychunks = [] # Build a running map of tuples (count, start_page)
                         # indicating contiguously empty chunks, so we can
                         # prioritise these by smallest first for solutions
        for (idx,frag) in enumerate(tf.fragments):
            if frag is None:
                tally += 1
            elif tally > 0:
                print("Empty chunk, %d page%s long, at page %d" %
                    (tally,
                     "s" if tally > 1 else "",
                     idx - tally))
                emptychunks.append((tally, idx-tally))
                tally = 0

        emptychunks = sorted(emptychunks, key=lambda chunk: chunk[0])
        for chunk in filter(lambda chunk: len(chunk) == 1, emptychunks):
            # Find the last LFH in the page beforehand, and use the CRC32 value
            # to hunt for the next data page.

            # Alternatively, check if we have a boundary-trailing LFHeader, and
            # use the recovered CD records to hunt for the missing piece.
            pass

        # Important to cut in from the zip start offset
        filedata = f.renderFragList(tf.fragments)[z.start_offset:]
        print "Percentage recovered %f" % (100.0*len(filter(lambda x: x <> None, tf.fragments))/len(tf.fragments))
        m = md5()
        m.update(filedata)
        of_name = "recovered_" + m.hexdigest() + ".zip"
        with open(of_name,'wb') as zip_out:
            zip_out.write(filedata)
