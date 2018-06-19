# This Dump Is A Puzzle

*or Advanced Shotgun Parsing for Fools and Rebels*

## *il était une fois*

Once upon a time, dear reader, on a dark and stormy night, your faithful author
stumbled upon a perplexing and mysterious situation - a system where the only
thing preventing chip off memory analysis and reversing was an unknokwn
proprietary file system breaking existing tools for memory extraction.

Some ad hoc solution might have been cobbled together at the time by manually
concatenating chunks that looked like they fitted together with a bit of
hideous python console work and ugly ad hoc bash scripting. It was Good Enough,
but Time Intensive.

This case was particularly puzzling - an embedded Java system was involved, and
while extracting plain uncompressed data in chip-off analysis is a fairly
humdrum job in the day of a hardware hacker, compression poses significant problems
when pieces of it are littered just everywhere in an irrational and displeasing
manner.

## But surely there must be a better way?

There are some interesting things about Zip files in particular (which is the
basic format used for JAR files). As an earnest
student of the [International Journal of
PoC||GTFO](https://github.com/tylert/pocorgtfo) for quite some time now and
particularly following the work in file format stunting by [Ange
Albertini](https://github.com/corkami/pics), I reckoned there might be enough
data inside of a zip file about the zip file that you could do a decent job of
stitching it all back together again.

So with reference points out of the way, let's get into the tech details.

First things first, we may not know (and from the perspective of my research,
independently from the system I had encountered the problem on, I decided it was
simply better not to care about) the specifics of the file system. But we know a
thing or two about the way most file systems are implemented. In particular we
know they tend to be written in chunks. The chunks have a minimum size of some
sort, known as pages, and we can identify that page size by browsing the dump and
identifying the minimal block size written. 

Some of these may run contiguously, some won't, with no clear pattern to when
blocks are contiguous.

All of which is to say, the problem we have is how to reorder the data pages in
such a way as they provide us valid (or close enough) images of the files we
want to extract.

Zip files are written in such a way they implement a sort of reverse hierarchy.
First the compressed file data (wrapped in local file headers describing it).
Then a central directory (which lists the offsets of the local file headers) and
then an end of central directory record (which amongst other things describes the
number of files stored in the zip, the offset where the central directory starts
and the size of the central directory).

Let's put that backwards, digging into a bit more detail:

* The End of Central Directory tells us:

  - The exact location, within the Zip file, of the EOCD record (the offset of
    the CD, plus the length of the CD, which preceeds the EOCD)
  - How many files (and therefore CD records) to look for.
  - The precise location in the Zip file of the first CD record.

* Each Central Directory record tells us:

  - CRC32 of the compressed file data
  - Timestamp
  - Plenty of other metadata (compression method, flags, OS version
    used/needed...)
  - An index within the file for the corresponding LF chunk
  - Critically: enough data to construct an image of the corresponding LF chunk.

* Each Local File record tells us:

  - The location in our dump of the start of a file
  - If it's a small enough file, we get the whole file within the same page, or
    thanks to the next file header appearing in the next paged chunk of zip file!
  - if enough small files are packed into enough pages, we can use the location
    of the pages and the known directory values to create an ordering for the
    pages (with known gaps!)

All of the above leads us to having for the vast majority of the file having
been reconstructed.

### Plot Twist - We must realistically deal with more than one JAR firmware!

First of all we need a step in order to distinguish data from different firmwares.
The reason for this is that all of the offsets are only relevant within their
respective zip files -- any conflict will lead to mismatching zip streams and
corruption, and we emphatically want to get as much uncorrupted data as possible
out. Also we want good assurances that, e.g any vulnerabilities we diagnose in the
target firmware affect the one we normally see running and not some other file
that's just been left lying around.

The solution needed here is the kmeans algorithm (AKA "Lloyd's Algorithm"). There's
[a great video here](https://www.youtube.com/watch?v=_aWzGGNrcic) explaining how it
works. SciPy had a good version ready to go but I had to
[identify](https://github.com/huonw/cogset/issues/5)/
[patch](https://github.com/huonw/cogset/pull/6)
the only clustering/analytics crate implementing the algorithm to get this
working for the Rust implementation. Luckily I didn't have to write it from
scratch.

After that job's a good'un.

We can use a number of features to do this. The Flags, Method, and
Version fields all vary based on the Zip stack used to compress the file.
Additionally, the headers have timestamps, and it's generally unlikely that all
of the firmwares were compiled and compressed exactly the same time.

	As an aside, it is worth noting that Zip files use MS-DOS format timestamps,
	which are bit packed shorts representing year-month-day and hour-minute-two-seconds.
	If these weren't converted to an absolute scalar value before using this as
	classification data, you might well give as much weight to a year's difference
	as you do to a second and that's no good at all!

We convert these into a Euclidean Vector (which is a fancy word for an
n-dimentional array of values in ℝ, or float coords, but the video linked above
is probably the most straightforward explanation) and the clustering algorithm
pretty much does everything else for us, collecting all the parsed headers into the
number of buckets we're expecting.

### A quick side-note on the parsing

Although I've written this in *fairly sketchy* Python script for prototyping
this method, having gotten to roughly 70-80% JAR content recovery rate with the
PoC I've decided to stop there and move to implementing a fast version in Rust.

Rust has a crate called `nom` which is absolutely fantastic for writing
parser-verifiers. This was one of the main attractions for re-writing it in
Rust, fwiw. The ability to write clear and extremely strict parsers makes this
far easier in some ways than it was trying to handle this all in Python (which
tends to be far more tolerant, so much so that it's sometimes a bit of a
challenge being certain you're not glossing over erroneous failures to catch an
edge case.

If awesome fast legible parsers sounds interesting go check out
* [Writing Parsers like it's 2017](http://spw17.langsec.org/papers/chifflier-parsing-in-2017.pdf)
* [Nom Benchmarks](https://github.com/Geal/nom_benchmarks/tree/master/http) -
  wherein someone wrote an http parser from scratch in Rust, slightly faster
  than a very fast C implementation, with no buffer overflows.

Besides anything else, running analysis of this sort in Python is intrinsically 
on the slow side, and was never really intended to be much more than a route to
a PoC for exploring the viability of this approach.

Anyway, enough of that...

### Carrying onwards

Approaches to reconstructing the remaining chunks include filtering remaining
pages for high entropy candidates first, filling smaller gaps first (eliminating
as many pages from the search list as possible, as testing permutations on these
is an exponential time task in the worst case, so solving the easier cases fast
is a priority and exponentially simplifies our problem as we go!).

We can also get a fast win by finding instances where a local file header is
unparseable because of a page boundary (we ought to be able to match it up to
an identically aligned counterpart, at least for cases where similarly alignments
are unique and don't collide with other corruption artefacts).

How do we check candidates for missing pages? Well we've got our CRC32 checksums
for the files sat right there in our Central Directory! Rather than computing
CRC32 over the file, probably the best way to go about this is comput CRC32 over
the chunks we already know (forward from the data in at the end of the page before
our gap starts, and in reverse from the data (or DataDescriptor chunk after the 
deflate stream) and work out from these what intermediate CRC32 we ought to expect
for each block of missing pages.

Essentially any time we choose the simplest/fastest problem to solve, we make
the harder problems significantly simpler by eliminating chaff. Which is the
reason for using Shannon entropy to just outright throw out empty pages or nearly
empty pages -- It's not guaranteed that we'll only have high-entropy zip pages
but even if there are outliers it's a massive speed up avoiding dealing with
that complication to start with.

### I just wanted to build this damn thing, what gives? ###


If you want to tinker with it, install rust (recommended with the awesome [rustup
nightly](https://github.com/rust-lang-nursery/rustup.rs#installation). Then:

```console
$ git clone [repo]
...
$ cd zipdefrag
...
$ cargo build --release
```

You can avoid the release flag to enable debugging. 

Build artefacts will be in /target/{debug,release}

Build documentation with `cargo doc` (This crate is heavily documented. I like writing.)

Currently there's no terminal output by default for the Rust version, if you want
to run the cli harness you need to set the environment variable `RUST_LOG=zipdefrag`
which enables verbose terminal logging demonstrating the analysis so far.

### Known Issues

* Performance is currently busted for the rust implementation due to wasteful behaviour around
searching for corresponding LFH chunks. Will fix

## More to come:

* A fast portable native executable (with python hooks) for puzzle-solving
  zip dumps from unknown file systems (the PoC works better than binwalk on our
  sample of one firmware dump, however 

* A demonstration dump

## Known Issues

This technique does not work well when many of the files in the JAR are
significantly larger than the page size. As it relies on heavy use of the
structure inherent in zip files, data-heavy files just don't work out so well.

Conveniently class files tend to be fairly small in general for J2ME midlets,
but large binaries packaged inside will probably be unrecoverable.

Also, the python PoC contains a number of arithmetic bugs.
