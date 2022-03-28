# nvtool

A tool to convert Tomato router NVRAM files to/from various formats.

To convert from a FreshTomato backup .cfg file to a human-readable file:

	nvtool.py  mybackup.cfg  mybackup.expq

To convert back to an ARM FreshTomato backup:

	nvtool.py -o hdr2  mybackup.expq  mybackup.cfg


NB: this is a work in progress


```
usage: nvtool.py [-h] [-d] [-o <otype>] [-C] [-S] [-R <r>] [-T <r>]
                 [-V <vers>] [-Z] [-D <file>] [-O <file>] [-F <file>] [-I]
                 [infile] [outfile]

nvtool v0.9.4

Convert router nvram files/data to/from text.

Keys/values are read from input, optionally filtered and sorted,
and written to output.

The input format is automatically detected. If --otype is not provided, the
output type is inferred from the output file extension if possible.

positional arguments:
  infile                        the input file name (or '-' for stdin)
  outfile                       the output file name (or '-' for stdout)

optional arguments:
  -h, --help                    show this help message and exit
  -d, --debug                   increase debug level
  -o <otype>, --otype <otype>   produce output of type <otype>
  -C, --keepconfig              include any internal CFG: keys in the output
  -S, --nosort                  don't sort the output by key
  -R <r>, --router <r>          infile keys/values are assumed to be from
                                router OS <r>
  -T <r>, --target <r>          output keys/values to be formatted for router
                                OS <r>
  -V <vers>, --version <vers>   produce output for version <vers>
  -Z, --nozip                   don't gzip the output (for those gzipped
                                output formats)
  -D <file>, --default <file>   add all the keys/values from <file> before
                                reading the input
  -O <file>, --override <file>  add all keys/values from <file> after reading
                                the input
  -F <file>, --filter <file>    filter the input using the regex patterns from
                                <file>. This can be used multiple times to
                                catenate filters
  -I, --invert                  invert the filter

Output <otype> types (and extensions):
    expq     - Tomato MIPS-compatible nvram export --quote format
    hdr1     - Tomato ARM original HDR1 backup/config file
    hdr2     - Tomato ARM obfuscated HDR2 backup/config file
    nvfilter - tab-delimited key-values suitable for use with --filter
    rml      - Router markup: human-readable, diffable pseudo-INI
    sh       - shell script of 'nvram set' commands
    tcf1     - Tomato MIPS TCF1 backup/config file

Router OSes:
    freshtomato-2020.8 - FreshTomato 2020.8 -- 2021.3
    freshtomato-2021.3 - FreshTomato 2021.3+

The --filter option can be used to filter out nvram keys.
A filter file is a list of lines with three tab-delimited fields:
    <key_pat>   [\t+ <val_pat>  [\t+ <action>]]
where <key_pat> and <val_pat> are Python regular expressions (which
may be contained in double-quotes which are stripped), and <action>
is either ACCEPT or DENY (if missing it defaults to ACCEPT).
If <val_pat> is missing or empty, it defaults to '.*' (match any) unless
it is a double-quoted empty string ("") in which case it matches only
the empty string.
The file can have comments starting with hash '#'.
If a filter is specified, entries that don't match the filter are denied.
The --invert option is useful to test if your filter has ignored any default
or hardware-specific settings (e.g. from a factory-reset config).

When outputing a Tomato MIPS TCF1 file, a hw_type field is written into the
file header.  This can be specified by providing a special key in the input
(or via the default/override options):
    CFG:hw_type=0x<nnnnnnnn>
where <nnnnnnnn> is the appropriate hex HW type.  This key can also be
written to the output by reading a TCF1 file and including the -C option.
(Tomato ARM backup files do not have a hw_type header field or check.)

infile and outfile can use router-specific key/value translations
(some file types are router-specific) which can be overridden with -R and -T
respectively.  --default and --override files as well as filters use
key/values in canonical "RML" form (i.e. as defined in FreshTomato 2021.2).
```
