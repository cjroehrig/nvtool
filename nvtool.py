#!/usr/bin/env python3
"""nvtool: Convert Tomato nvram to/from text.
"""

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Lesser Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Lesser Public License for more details.
#
#   You should have received a copy of the GNU Lesser Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#   Copyright (c) 2021 Chris Roehrig <croehrig@crispart.com>
#


#==============================================================================
# Imports and definitions
import sys
import os
import argparse
import gzip
import re
import random
import math

# Program version
# NB: make sure there is alway an NVFile_rml subclass to handle it.
__version__ = "0.9.4"


# NB: string encoding needs to support embedded arbitrary binary values
NV_ENCODING = 'latin1'
#NV_ENCERR = 'backslashreplace'
NV_ENCERR = 'strict'


# a bit of /etc/protocols (parse/emit hooks)
PROTOCOLS={
    '1'   : "ICMP",
    '6'   : "TCP",
    '8'   : "EGP",
    '17'  : "UDP",
    '41'  : "IPv6"
    }
PROTOCOLS_REV = {v: k for k,v in PROTOCOLS.items()}



#==============================================================================
# Debug output

# this is modified by command-line options
DEBUG = 0

"""C-style printf output"""
def printf(fmt, *args):
    print(fmt % args, end='')

def error(fmt, *args):
    global LINENO
    if LINENO:
        prefix = "ERROR (line %d): " % LINENO
    else:
        prefix = "ERROR: "
    print(prefix + fmt % args, file=sys.stderr)
    sys.exit(1)

def warn(fmt, *args):
    global LINENO
    if LINENO:
        prefix = "WARNING (line %d): " % LINENO
    else:
        prefix = "WARNING: "
    print(prefix + fmt % args, file=sys.stderr)

def dbg(fmt, *args):
    global DEBUG, LINENO
    if DEBUG >= 1:
        if LINENO: fmt = "[line %d]: " % LINENO + fmt
        print(fmt % args, end='', file=sys.stderr)

def dbg2(fmt, *args):
    global DEBUG, LINENO
    if DEBUG >= 2:
        if LINENO: fmt = "[line %d]: " % LINENO + fmt
        print(fmt % args, end='', file=sys.stderr)

#==============================================================================
#  I/O functions

#======================================
def read_file(path):
    """Read file into a bytearray and return it.
    'path' is the path to the file or '-' for stdin.
    """
    if path == '-':
        dbg("Reading binary blob from <stdin>\n")
        buf = sys.stdin.buffer.read()
    else:
        dbg("Reading binary blob from %s\n", path)
        with open(path, 'rb') as f:
            buf = f.read()
    return buf

#======================================
def write_file(path, buf):
    """Write bytearray 'buf' to file at 'path'.
    If path is '-', write to stdout."""
    if path == '-':
        dbg("Writing to <stdout>...\n")
        sys.stdout.buffer.write(buf)
    else:
        dbg("Writing to %s...\n", path)
        with open(path, 'wb') as f:
            f.write(buf)


#==============================================================================
#  Data manipulation functions

#======================================
def all_subclasses(cls):
    """Return all subclasses (including descendents) of class cls."""
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in all_subclasses(c)])

#======================================
def deobfuscate(buf, offset):
    """Apply Tomato ARM de-obfuscation to buf and return it.
       offset is the obfuscation offset.
    """
    dbg("de-obfuscating with offset=0x%02x...\n", offset)
    buf = bytearray(buf)    # make a mutable copy
    for i in range(len(buf)):
        if buf[i] < 0xfd:       # non-null; rotate
            buf[i] = ( 0xff - buf[i] + offset ) % 256
        else:
            buf[i] = 0x0        # nullchar
    return buf

#======================================
def obfuscate(buf, offset):
    """Apply Tomato ARM obfuscation to buf and return it.
       offset is the obfuscation offset.
    """
    dbg("obfuscating with offset=0x%02x...\n", offset)
    buf = bytearray(buf)    # make a mutable copy
    for i in range(len(buf)):
        if buf[i] == 0x00:
            # nulls --> 0xfe or 0xff
            buf[i] = 0xfd + random.randint(1,2)     # non-zero rand
        else:
            # rotate it
            buf[i] = (0xff - buf[i] + offset) % 256
    return buf


#======================================
def strip_quotes(s, qchar='"'):
    """Return string s with any enclosing quotes removed.
    They are only removed if both are present."""
    if len(s) > 1:
        if s[0] == qchar and s[-1] == qchar:
            s = s[1:-1]
    return s


#======================================
def dequote(v, dequoted=False, qchar='"'):
    """Remove quotes (qchar) from v if dequoted is False and return
       (v, dequoted) where dequoted=True if quotes were removed.
    """
    if not dequoted:
        if len(v) > 1 and v[0] == qchar and v[-1] == qchar:
            v = v[1:-1]
            dequoted = True
    return v, dequoted

#======================================
def dequote_kv(k, v, qchar='"', dequoted=None):
    """Remove quotes from k and v if they haven't already been done.
    dequoted is a pair of booleans, True if (k,v) has already been dequoted,
    respectively.
    k, v should be split from a string k=v where k or v could be
    quoted or the entire k=v expression could be quoted.
    """
    if dequoted is None:
        (dequoted_k, dequoted_v) = (False, False)
    else:
        (dequoted_k, dequoted_v) = dequoted

    if len(k) > 1 and not dequoted_k and k[0] == qchar:
        if k[-1] == qchar:
            # k is enclosed in quotes; remove them
            k = k[1:-1]
            dequoted_k = True
            # now check v independently:
            (v, dequoted_v) = dequote(v, dequoted_v, qchar=qchar)
        elif len(v) > 0 and v[-1] == qchar:
            # entire expression enclosed in quotes
            k = k[1:]
            v = v[:-1]
            dequoted_k = True
            dequoted_v = True
    else:
        # no quotes on k; check v
        (v, dequoted_v) = dequote(v, dequoted_v, qchar=qchar)

    return k, v, (dequoted_k, dequoted_v)

#==============================================================================
#  NVRAM Dictionary filtering

#======================================
def filter_matches(key, val, filterlist, default_action=True):
    """Return true if key matches the filterlist"""
    dbg2("FILTERMATCH (%s,%s): ", key, val)
    for (key_pat, val_pat, action) in filterlist:
        if re.fullmatch(key_pat, key):
            if val_pat is None:
                dbg2("%s\n", action)
                return action
            elif re.fullmatch(val_pat, val):
                dbg2("%s\n", action)
                return action
    dbg2("NO MATCH\n")
    return default_action

#======================================
def nvfilter(nvdict, filterlist, default_action=True, invert=False ):
    """Apply filterlist to nvdict and return the result.
    filterlist is a list of triplets: (key_pat, val_pat, action)
    where key_pat and val_pat are regexes and
    action is True (pass) or False (deny).
    default_action applies to keys that do not match any filter entries.
    If invert is True, then entries that do not match the filter are returned.
    """
    result = {}
    for k,v in nvdict.items():
        matches = filter_matches(k, v, filterlist, default_action)
        if invert:
            if not matches:
                result[k] = v
        else:
            if matches:
                result[k] = v
    return result



#======================================
def filter_read(path, filterlist=None):
    """Read a filter file from 'path', append to filterlist and return it."""
    global LINENO
    if path == '-':
        dbg("Reading filter from <stdin>\n")
        buf = sys.stdin.buffer.read()
    else:
        dbg("Reading filter from %s\n", path)
        with open(path, 'r') as f:
            buf = f.read()
    if filterlist is None:
        filterlist = []
    LINENO = 0
    for line in buf.splitlines():
        LINENO += 1
        fields = re.split('\t+', line)
        if not fields: continue

        # Key pattern
        key_pat = fields.pop(0)
        if not key_pat or key_pat.startswith('#'):
            # no filter present
            continue
        key_pat = strip_quotes(key_pat)
        if not fields:
            filterlist.append( (key_pat, None, True) )
            continue

        # Value pattern
        val_pat = fields.pop(0)
        if not val_pat or val_pat.startswith('#'):
            # empty val_pat - action must also be missing
            filterlist.append( (key_pat, None, True) )
            continue
        if val_pat == '""':
            val_pat = ""        # empty string pattern
        else:
            val_pat = strip_quotes(val_pat)
        if val_pat == ".*":
            val_pat = None      # short-circuit/bypass the re.match
        if not fields:
            filterlist.append( (key_pat, val_pat, True) )
            continue

        # Action
        action = fields.pop(0)
        if not action or action.startswith('#'):
            action = True
        elif action == "ACCEPT":
            action = True
        elif action == "DENY":
            action = False
        else:
            warn("Unknown filter action: %s", action)
            action = False
        dbg2("Filter: adding (%s,%s,%s)\n", key_pat, val_pat, action)
        filterlist.append( (key_pat, val_pat, action) )

    LINENO = None
    return filterlist


#==============================================================================
# Routers

class Router(object):
    """
    A Router object is just a mapping of keys/values to/from
    our device-independent (rml) representation.

    XXX: for now we just use FreshTomato keys & values as the device-independent
    representation.

    XXX: Any NVRAM values containing escaped newlines will get converted
    to actual newlines when writing.
    """
    name = "default"
    help = None

    # Subclasses can override these to do simple key renaming
    keymap = None
    keymap_rev = None
    #keymap_rev = {v: k for k,v in keymap.items()}

    #==================================
    @classmethod    # FACTORY METHOD
    def from_name(cls, name):
        """Return a router object from a class with the given name."""
        subclass = None
        for c in all_subclasses(cls):
            if c.name and c.name == name:
                subclass = c
                break
        if subclass:
            # instantiate
            obj = subclass()
        else:
            error("Unknown router OS: %s", name)
            obj = None
        return obj

    #==================================
    def to_rml(self, k, v):
        """Default translation from our router to RML."""
        #(k, v) = super().to_rml(k, v)      # NB: do the super's translations
        if self.keymap:
            if k in self.keymap:
                k = self.keymap[k]
        return k, v

    #==================================
    def from_rml(self, k, v):
        """Default translation from RML to our router."""
        #(k, v) = super().from_rml(k, v)    # NB: do the super's translations
        if self.keymap_rev:
            if k in self.keymap_rev:
                k = self.keymap_rev[k]
        return k, v

    #==================================
    def convert_to(self, nvdict):
        """Convert nvdict from rml to our router."""
        nv = {}
        for k, v in nvdict.items():
            (k, v) = self.from_rml(k, v)
            nv[k] = v
        return nv

    #==================================
    def convert_from(self, nvdict):
        """Convert nvdict from our router to rml."""
        nv = {}
        for k, v in nvdict.items():
            (k, v) = self.to_rml(k, v)
            nv[k] = v
        return nv


#==========================================================
class Router_FreshTomato_2021_3(Router):
    name = "freshtomato-2021.3"
    help = "FreshTomato 2021.3+"

    #==================================
    def to_rml(self, k, v):
        k, v = super().to_rml(k, v)
        if k == "bwl_rules":
            # add field 0: enable
            # add field 9: description
            pass
        return k, v

    #==================================
    def from_rml(self, k, v):
        if k == "bwl_rules":
            # remove field 0: enable
            # remove field 9: description
            pass
        k, v = super().from_rml(k, v)
        return k, v


#==========================================================
class Router_FreshTomato_2020_8(Router):
    name = "freshtomato-2020.8"
    help = "FreshTomato 2020.8 -- 2021.3"

    keymap = {
        "new_qoslimit_enable"   : "bwl_enable",
        "new_qoslimit_rules"    : "bwl_rules",
        # XXX These were done at some point; move to separate Router
        #"new_qoslimit_ibw"      : "wan_qos_ibw",
        #"new_qoslimit_obw"      : "wan_qos_obw",
        "limit_br0_dlc"         : "bwl_br0_dlc",
        "limit_br0_dlr"         : "bwl_br0_dlr",
        "limit_br0_enable"      : "bwl_br0_enable",
        "limit_br0_prio"        : "bwl_br0_prio",
        "limit_br0_tcp"         : "bwl_br0_tcp",
        "limit_br0_udp"         : "bwl_br0_udp",
        "limit_br0_ulc"         : "bwl_br0_ulc",
        "limit_br0_ulr"         : "bwl_br0_ulr",
        "limit_br1_dlc"         : "bwl_br1_dlc",
        "limit_br1_dlr"         : "bwl_br1_dlr",
        "limit_br1_enable"      : "bwl_br1_enable",
        "limit_br1_prio"        : "bwl_br1_prio",
        "limit_br1_ulc"         : "bwl_br1_ulc",
        "limit_br1_ulr"         : "bwl_br1_ulr",
        "limit_br2_dlc"         : "bwl_br2_dlc",
        "limit_br2_dlr"         : "bwl_br2_dlr",
        "limit_br2_enable"      : "bwl_br2_enable",
        "limit_br2_prio"        : "bwl_br2_prio",
        "limit_br2_ulc"         : "bwl_br2_ulc",
        "limit_br2_ulr"         : "bwl_br2_ulr",
        "limit_br3_dlc"         : "bwl_br3_dlc",
        "limit_br3_dlr"         : "bwl_br3_dlr",
        "limit_br3_enable"      : "bwl_br3_enable",
        "limit_br3_prio"        : "bwl_br3_prio",
        "limit_br3_ulc"         : "bwl_br3_ulc",
        "limit_br3_ulr"         : "bwl_br3_ulr",

    }
    keymap_rev = {v: k for k,v in keymap.items()}


#==============================================================================
class NVFile(object):
    """Superclass for NVRAM file handlers.

    Generally these objects don't keep any nvram state, but rather just
    transform/read/write and return them.

    The device-independent NVRAM representation is a dict (nvdict) of keys
    and values which are translated to/from the router-specific keys/values
    by the Router subclass.
    """

    # Subclasses should set these:
    help    = None          # help (usage) string
    ftype   = None          # string used in --otype option (and file extension)
    router  = None          # the Router subclass specific to this file type.
    magic   = None          # header magic bytearray
    is_zipped = False       # True if the native file format is gzipped
    is_sorted = True        # True if the native file format is sorted

    #==================================
    @classmethod    # FACTORY METHOD
    def from_type(cls, ftype, *, path=None, router=None, version=None):
        """Return an instance of the appropriate NVFile subclass for the
        given ftype and file name path.
        If ftype is None, then try to detect it from the file name.
        Router is passed to the subclass constructor.
        Version is passed to the subclass constructor.
        Return None if it can't be determined.
        """
        subclass = None
        if not ftype and path:
            (_, ext) = os.path.splitext(path)
            if ext:
                ext = ext[1:]   # remove leading '.'
                # NB: don't use all_subclasses; let each
                # subclass decide how to choose its subclass.
                #for c in all_subclasses(NVFile):
                for c in NVFile.__subclasses__():
                    if c.ftype and ext == c.ftype:
                        subclass = c
                        break
        elif ftype:
            #for c in all_subclasses(NVFile):
            for c in NVFile.__subclasses__():
                if c.ftype and c.ftype == ftype:
                    subclass = c
                    break
        if subclass:
            # instantiate
            obj = subclass(router=router, version=version)
            obj.path = path
        else:
            obj = None

        return obj

    #==================================
    @classmethod    # FACTORY METHOD
    def from_file(cls, path, *, router=None, version=None):
        """Read file from 'path', auto-detect the type of NVFile subclass,
        and return an instance of it.
        Router is passed to the subclass constructer.
        Return None on error.
        """
        buf = read_file(path)

        # Gunzip any gzipped data
        gzipped = False
        if buf[:2] == b'\x1f\x8b':
            dbg("Found GZIP magic, decompressing...\n")
            buf = gzip.decompress(buf)
            gzipped = True

        # Detect file type from magic string in header
        subclass = None
        # NB: don't use all_subclasses; let each
        # subclass decide how to choose its subclass.
        for cls in NVFile.__subclasses__():
            if cls.magic:
                if type(cls.magic) is list:
                    # (lists only work for read-only NVFiles...)
                    for m in cls.magic:
                        if buf[:len(m)] == m:
                            subclass = cls
                            break
                elif buf[:len(cls.magic)] == cls.magic:
                    subclass = cls
                    break

        if not subclass:
            error("Can't detect input file format for %s\nbuf[0:5]=%s",
                    path, buf[0:5])
            return None

        obj = subclass(filebuf=buf, router=router, version=version)
        obj.path = path
        obj.was_zipped = gzipped

        # convert file buffer to our nvdict
        obj.nvdict = obj.reader(buf)

        return obj

    #==================================
    def __new__(cls, *, router=None, version=None, filebuf=None):
        """Constructor.
        router is the router class to be used to translate keys/values to/from
        our internal device-independent representation.
        version is an optional version tag which can be used by subclasses.
        filebuf is the file buffer can be used by subclasses to determine
        the version.
        """
        obj = super().__new__(cls)
        if router:
            if obj.router:
                warn("%s: Overriding intrinsic router '%s' with '%s'",
                    obj.ftype, obj.router.name, router.name)
            obj.router = router
        return obj


    #==================================
    def __init__(self, *args, **kwds):
        """Initialize an instance. """
        self.nvdict = None
        self.path = None
        self.was_zipped = False
        self.keepconfig = False


    #==================================
    def write(self, path, nvdict):
        """Convert nvdict to our file format using our writer method
        and write the file to 'path'.
        """
        # Convert nv to bytearray using our writer ...
        buf = self.writer(nvdict)
        if not buf:
            buf=b""     # make sure we at least write an empty file
        # compress it
        if self.is_zipped:
            buf = gzip.compress(buf, compresslevel=9)
        # write the file
        write_file(path, buf)

    #======================================
    def sorted_keys(self, nvdict):
        """Return the keys of nvdict, sorted according to our is_sorted
        setting.
        """
        keys = nvdict.keys()
        if self.is_sorted:
            # sort keys with a trailing '=' to be the same as sorting the file 
            keys = sorted(keys, key=lambda x: x+'=')
        return keys

    #======================================
    def filterconfig(self, nvdict):
        """Return nvdict with our CFG RECORDS filtered out."""
        if not self.keepconfig:
            nvdict = nvfilter(nvdict, [("CFG:.*", None, False)])
        return nvdict

    # Subclasses should override these:
    #==================================
    def reader(self, buf):
        """Return the nvram dict representation of bytearray 'buf'
        (which is typically the binary file data)."""
        return None

    #==================================
    def writer(self, nvdict):
        """Return a bytearray data buffer which is the binary file
        representation of nvdict (uncompressed)."""
        return None

#==========================================================
# expq
class NVFile_expq(NVFile):
    help    = "Tomato MIPS-compatible nvram export --quote format"
    ftype   = "expq"
    magic   = b'"'      # file starts with a double quote
    router  = None      # no translation by default

    #==================================
    def reader(self, buf):
        dbg("Reading %s...\n", self.ftype)
        buf = buf.decode(NV_ENCODING, errors=NV_ENCERR)
        nvdict = {}
        for line in buf.splitlines():
            (k, v) = line.split('=', 1)
            (k, v, _) = dequote_kv(k, v)
            if k:
                nvdict[k] = v
        if self.router: nvdict = self.router.convert_from(nvdict)
        return nvdict

    #==================================
    def writer(self, nvdict):
        dbg("Writing %s\n", self.ftype)
        # Filter out our CFG RECORDs
        nvdict = self.filterconfig(nvdict)
        if self.router: nvdict = self.router.convert_to(nvdict)
        keys = self.sorted_keys(nvdict)
        buf=""
        for k in keys:
            v = nvdict[k]
            buf += '"{}={}"\n'.format(k, v)
        # convert to bytearray, expand any backslashes
        buf = bytearray(buf, NV_ENCODING, NV_ENCERR)
        return buf

#==========================================================
# sh
class NVFile_sh(NVFile):
    help    = "shell script of 'nvram set' commands"
    ftype   = "sh"
    magic   = b'#!'
    router = None       # generic

    #==================================
    def reader(self, buf):
        global LINENO
        dbg("Reading %s...\n", self.ftype)
        buf = buf.decode(NV_ENCODING, errors=NV_ENCERR)
        nvdict = {}
        LINENO = 0
        for line in buf.splitlines():
            LINENO += 1
            mine = line.lstrip()
            if not line: continue               # blank lines
            if line.startswith('#'): continue   # comments
            if line.startswith('#'): continue   # comments
            if not line.startswith("nvram set "):
                warn("Skipping: %s\n", line)
                continue
            line = line[len("nvram set "):]
            line = line.lstrip()
            (k, v) = line.split('=', 1)
            (k, v, dequoted) = dequote_kv(k, v, '"')
            (k, v, dequoted) = dequote_kv(k, v, "'", dequoted)
            if k:
                nvdict[k] = v
        if self.router: nvdict = self.router.convert_from(nvdict)
        LINENO = None
        return nvdict


    #==================================
    def writer(self, nvdict):
        dbg("Writing %s\n", self.ftype)
        # Filter out our CFG RECORDs
        nvdict = self.filterconfig(nvdict)
        if self.router: nvdict = self.router.convert_to(nvdict)
        keys = self.sorted_keys(nvdict)
        buf="#!/bin/sh\n"
        for k in keys:
            v = nvdict[k]
            buf += "nvram set '{}={}'\n".format(k, v)
        # convert to bytearray, expand any backslashes
        buf = bytearray(buf, NV_ENCODING, NV_ENCERR)

        return buf
#==========================================================
# nvfilter
class NVFile_nvfilter(NVFile):
    help    = "tab-delimited key-values suitable for use with --filter"
    ftype   = "nvfilter"
    magic   = b'#nvfilter'

    #==================================
    def reader(self, buf):
        error("Unable to read %s files\n", self.ftype)
        return None

    #==================================
    def writer(self, nvdict):
        dbg("Writing %s\n", self.ftype)
        # Filter out our CFG RECORDs
        nvdict = self.filterconfig(nvdict)
        if self.router: nvdict = self.router.convert_to(nvdict)
        buf = self.magic.decode(NV_ENCODING)    # start with our magic
        buf += "\n# vim: ts=4\n"                # and a decent VIM modeline 
        buf += self.fmt("# Key", "Value", "Action")
        keys = self.sorted_keys(nvdict)
        for k in keys:
            v = nvdict[k]
            v = re.escape(v)
            # escape any non-ASCII (binary) characters:
            v = v.encode('ASCII', 'backslashreplace').decode()
            v = v.replace('\ ', ' ')    # unescape spaces
            if not v:
                v = '""'
            elif len(v) > 30:
                v = '"' + v + '"'
            buf += self.fmt(k, v, "")
        return bytearray(buf, NV_ENCODING, NV_ENCERR)

    #==================================
    def fmt(self, k, v, a):
        """Format a line with k, v, a (action) and return it."""
        tabstop = 4
        buf = k + '\t'
        i = len(k) + 1
        i = math.ceil(i/tabstop) * tabstop
        while i < 36:
            buf += '\t'
            i += tabstop
        buf += v + '\t'
        i += len(v) + 1
        i = math.ceil(i/tabstop) * tabstop
        while i < 60:
            buf += '\t'
            i += tabstop
        # empty 'action' == "ACCEPT"
        buf += a + '\n'
        return buf




#==========================================================
# tcf1
class NVFile_tcf1(NVFile):
    help    = "Tomato MIPS TCF1 backup/config file"
    ftype   = "tcf1"
    magic   = b'TCF1'
    #router  = Router_Tomato_MIPS()
    is_zipped = True

    #==================================
    def reader(self, buf):
        dbg("Reading %s...\n", self.ftype)
        hw_type = int.from_bytes(buf[4:8], byteorder='little', signed=False)
        dbg(" TCF1: hw_type=0x%08x\n", hw_type)
        kvnull = NVFile_kvnull(router=self.router)
        nvdict = kvnull.reader(buf[8:]) # skip 8-byte header
        nvdict["CFG:hw_type"] = "0x%08x" % hw_type      # CFG RECORD
        return nvdict

    #==================================
    def writer(self, nvdict):
        dbg("Writing %s\n", self.ftype)
        # check for our CFG RECORD
        if "CFG:hw_type" in nvdict:
            hw_type = int(nvdict["CFG:hw_type"],0)
        else:
            warn("Saving TCF1 using hw_type=0 (hardware type unknown)")
            hw_type = 0
        # Filter out our CFG RECORDs
        nvdict = self.filterconfig(nvdict)
        # convert the data to kvnull bytearray
        kvnull = NVFile_kvnull(router=self.router)
        kvnull.is_sorted = self.is_sorted
        nvbuf = kvnull.writer(nvdict)
        # construct header
        buf = bytearray()
        buf += self.magic
        buf += hw_type.to_bytes(4, byteorder='little')
        # add the data
        buf += nvbuf
        return buf

#==========================================================
# hdr1
class NVFile_hdr1(NVFile):
    help    = "Tomato ARM original HDR1 backup/config file"
    ftype   = "hdr1"
    magic   = b'HDR1'
    #router  = Router_Tomato_ARM()
    is_zipped = True

    #==================================
    def reader(self, buf):
        dbg("Reading %s...\n", self.ftype)
        buflen = int.from_bytes(buf[4:8], byteorder='little', signed=False)
        dbg(" HDR1: buflen=%d (0x%08x)\n", buflen, buflen )
        dbg(" HDR1: len(buf)=%d\n", len(buf))
        kvnull = NVFile_kvnull(router=self.router)
        nvdict = kvnull.reader(buf[8:]) # skip 8-byte header
        return nvdict

    #==================================
    def writer(self, nvdict):
        dbg("Writing %s\n", self.ftype)
        # Filter out our CFG RECORDs
        nvdict = self.filterconfig(nvdict)
        # convert the data to kvnull bytearray
        kvnull = NVFile_kvnull(router=self.router)
        kvnull.is_sorted = self.is_sorted
        nvbuf = kvnull.writer(nvdict)
        # construct header
        buf = bytearray()
        buf += self.magic
        buf += len(nvbuf).to_bytes(4, byteorder='little')
        # add the data
        buf += nvbuf
        return buf


#==========================================================
# hdr2
class NVFile_hdr2(NVFile):
    help    = "Tomato ARM obfuscated HDR2 backup/config file"
    ftype   = "hdr2"
    magic   = b'HDR2'
    #router  = Router_Tomato_ARM()
    is_zipped = False       # NB: not zipped!
    obfuscate = True
    blocksize = 1024        # HDR2 files are rounded up to this blocksize
                            # (must be a power of 2)

    #==================================
    def reader(self, buf):
        dbg("Reading %s...\n", self.ftype)
        # 'HDR2'    4 bytes
        # <buflen>  3 bytes (rounded up to next kb); ignored
        # <rand>    1 byte - a random perturbation
        buflen = int.from_bytes(buf[4:7], byteorder='little', signed=False)
        rand = int(buf[7])
        buf = buf[8:]               # skip header
        dbg(" %s: buflen=%d (0x%06x)  rand=0x%02x\n",
                self.ftype, buflen, buflen, rand)
        dbg(" %s: len(buf)=%d\n", self.ftype, len(buf))
        if self.obfuscate:
            buf = deobfuscate(buf, rand)
        kvnull = NVFile_kvnull(router=self.router)
        nvdict = kvnull.reader(buf)
        nvdict["CFG:hdr2_rand"] = "0x%02x" % rand      # CFG RECORD
        return nvdict

    #==================================
    def writer(self, nvdict):
        dbg("Writing %s\n", self.ftype)
        # check for our CFG RECORD
        if "CFG:hdr2_rand" in nvdict:
            rand = int(nvdict["CFG:hdr2_rand"],0)
            dbg(" %s: using rand=0x%02x found in CFG:hdr2_rand\n",
                    self.ftype, rand)
        else:
            # From nvram_arm/main.c:
            #do {
            #    rand = get_rand() % 30         # from /dev/urandom; nonzero!
            #} while (rand > 7 && rand < 14)    # omit 8-13  ascii \b to \r
            #
            #  XXX: there is a bug here in nvram_arm/main.c:
            #     if rand is 7, TAB chars \t (==0x09) will get obfuscated
            #     to:  0xff - 0x09 + 7 = 0xfd
            #   and will be de-obfuscated to a nullchar, truncating the field
            #   [CONFIRMED using a tab in a dnsmasq_custom comment.]
            if self.obfuscate:
                rand = random.choice( list(range(1,8)) + list(range(14,30)) )
            else:
                rand = 0
        # Filter out our CFG RECORDs
        nvdict = self.filterconfig(nvdict)
        # convert the data to kvnull bytearray
        kvnull = NVFile_kvnull(router=self.router)
        kvnull.is_sorted = self.is_sorted
        nvbuf = kvnull.writer(nvdict)
        # align and pad to 1k boundary
        nvlen = len(nvbuf)  # NB: MUST include the terminating null record
        datalen = (nvlen + self.blocksize - 1) & ~(self.blocksize-1)
        padlen = datalen - nvlen
        nvbuf += bytearray(padlen) # add padding of zeros
        # obfuscate it
        if self.obfuscate:
            nvbuf = obfuscate(nvbuf, rand)
        # construct header
        buf = bytearray()
        buf += self.magic
        buf += datalen.to_bytes(3, byteorder='little')
        buf += rand.to_bytes(1, byteorder='little')
        dbg(" %s: buflen=%d (0x%06x)  rand=0x%02x\n",
                self.ftype, datalen, datalen, rand)
        dbg(" %s: len(nvbuf)=%d\n", self.ftype, len(nvbuf))
        # append the obfuscated data
        buf += nvbuf
        return buf

#==========================================================
# (INTERNAL): kvnull: Null-terminated key/value format
class NVFile_kvnull(NVFile):

    #==================================
    def reader(self, buf):
        """Return a dict representation of buf which should consist
        of a series of null-terminated key=value strings.
        """
        start = 0
        end = 0

        buflen = len(buf)
        nvdict = {}
        while start < buflen:
            while buf[end] != 0x0:  end += 1
            if end > start:
                kvstr = buf[start:end]
                (k,v) = kvstr.split(b'=', 1)
                k = k.decode(NV_ENCODING)
                #k = strip_quotes(k)
                if k:
                    # value could be binary...
                    v = v.decode(NV_ENCODING, errors=NV_ENCERR)
                    #v = strip_quotes(v)    # remove enclosing quotes
                    v = v.replace('\n', "\\n") # escape newlines
                    nvdict[k] = v
                dbg2("KV_READ  %s=\"%s\"\n", k, nvdict[k])
            end += 1        # skip nullchar
            start = end
        if self.router: nvdict = self.router.convert_from(nvdict)
        return nvdict


    #==================================
    def writer(self, nvdict):
        """Return a bytearray buffer of null-terminated key=value strings
        from nv which is our nvram dict representation."""
        if self.router: nvdict = self.router.convert_to(nvdict)
        keys = self.sorted_keys(nvdict)
        buf=bytearray()
        for k in keys:
            v = nvdict[k]
            v = v.replace("\\n", '\n') # un-escape newlines
            val = "{}={}".format(k, v)
            val = bytearray(val, NV_ENCODING, NV_ENCERR)
            buf += val + b'\x00'
        buf += b'\x00'      # terminating null record
        return buf



#==============================================================================
# rml: Our custom pseudo-INI format

class NVFile_rml(NVFile):
    """RML is just unquoted key=value lines with expanded INI-style 'tag'
    sections of the form:
        [TAG:key]
            contents
        [/TAG]
    Each Tag Section has its own parser/emitter for its type of contents.
    Generally, the contents are nicely formatted, human-readable, and
    suitable for diffing.

    RML files have a version string that follows the #RML magic
    header (whitespace delimited).  If the version isn't the same as
    the program version and a subclass of NVFile_rml exists whose version
    matches the start of the version string, then that subclass is used to
    process the RML file.
    """
    help    = "Router markup: human-readable, diffable pseudo-INI"
    ftype   = "rml"
    magic   = b'#RML'

    # The RML version this class handles.
    # This can also be a list of versions and prefixes, in which case
    # the first entry must be the full canonical version number to be written
    # into the header.
    version = None

    #==================================
    # Subclasses can override these to translate to/from the current version.
    def to_rml(self, k, v):     return k, v
    def from_rml(self, k, v):   return k, v


    #==================================
    def __new__(cls, *, router=None, version=None, filebuf=None):
        """Constructor: determine the version and return the subclass.
        """
        if filebuf:
            # detect the version/subclass from the file header
            header, _ = filebuf.split(b'\n', maxsplit=1)
            header = header.decode(NV_ENCODING, errors=NV_ENCERR)
            (mag, vers) = header.split()
        elif version:
            # specified by command-line/parm
            vers = version
        else:
            # use current version
            vers = __version__

        # Find a subclass to handle this version
        subclass = None
        for c in all_subclasses(NVFile_rml):
            if c.version:
                if type(c.version) is list:
                    for v in c.version:
                        if vers.startswith(v):
                            subclass = c
                            break
                if vers.startswith(v):
                    subclass = c
                    break

        if not subclass:
            error("Unknown RML version: '%s'", vers)
            return None

        # instantiate
        rml = super().__new__(subclass)

        # set the file_version instance variable:
        # NB: this happens BEFORE rml's __init__ is called
        rml.file_version = vers

        return rml

    #==================================
    def reader(self, buf):
        """NVFile_rml reader."""
        global LINENO
        dbg("Reading %s...\n", self.ftype)

        buf = buf.decode(NV_ENCODING, errors=NV_ENCERR)

        nvdict = {}
        tag_handler = None
        LINENO = 0
        for line in buf.splitlines():
            LINENO += 1
            if tag_handler:
                # currently parsing a tag section
                if line[:len(tag)+2] == "[/"+tag :
                    # closing tag
                    val = tag_handler.parse_close()
                    (key, val) = self.to_rml(key, val)
                    nvdict[key] = val
                    dbg2("Read [%s:%s]\n", tag, key)
                    tag_handler = None
                else:
                    tag_handler.parse_line(line)

            elif line[0] == '[':
                # start of tag section
                line = line[1:-1]       # remove brackets
                (tag, key) = line.split(':',1)
                # find the tag handler
                tag_handler = TagSection(tag, key, nvdict)
            else:
                # normal entry
                if line[0] == '#': continue     # skip comments
                (key, val) = line.split('=', 1)
                (key, val) = self.to_rml(key, val)
                nvdict[key] = val
                dbg2("Read KEY '%s'\n", key)
        LINENO = None
        return nvdict


    #==================================
    def writer(self, nvdict):
        dbg("Writing %s\n", self.ftype)
        # Filter out our CFG RECORDs
        nvdict = self.filterconfig(nvdict)

        # translate from the current rml
        nv = {}
        for k, v in nvdict.items():
            (k, v) = self.from_rml(k, v)
            nv[k] = v
        nvdict = nv

        keys = self.sorted_keys(nvdict)

        buf = self.magic.decode(NV_ENCODING)    # start with our magic
        if type(self.version) is list:
            version = self.version[0]
        else:
            version = self.version
        buf += ' ' + version + '\n'        # and version
        if self.vim_modeline:
            buf += self.vim_modeline + '\n'
        for k in keys:
            val = nvdict[k]
            if val:
                # expand tag sections (only for non-empty values)
                if k in self.tag_keys:
                    # output special section:
                    tag = self.tag_keys[k]
                    tag_handler = TagSection(tag, k, nvdict)
                    buf += "[{}:{}]\n".format(tag, k) # open tag
                    buf += tag_handler.emit(val)
                    buf += "[/{}]\n".format(tag)      # close tag
                else:
                    buf += '{}={}\n'.format(k, val)
            else:
                buf += '{}=\n'.format(k)

        # convert to bytearray
        buf = bytearray(buf, NV_ENCODING)
        return buf


#==========================================================================
# RML subclasses for different versions...
class NVFile_rml_v0(NVFile_rml):
    help    = None

    # For now, just match __version__ at the top of file.
    version = [ __version__ , "0." ]

    # an optional VIM modeline to appear at the top:
    #vim_modeline = "# vim: ts=12:vartabstop=6,15,12,10,15,12"
    vim_modeline = "# vim: ts=4"
    vim_modeline += ":nowrap:list:lcs=tab\:\ \ ,extends\:#"

    # a dict of key to TagSection tag mappings:
    tag_keys = {
        'portforward'           : 'FWD',
        'adblock_blacklist'     : 'TABC',
        'dhcpd_static'          : 'STATIC',
        #'bwl_rules'             : 'TAB',
        'bwl_rules'             : 'BWL',
        'trigforward'           : 'TABC',
        'ntp_server'            : 'SPACEN',
        'qos_classnames'        : 'SPACEN',
        'qos_irates'            : 'COMMAN',
        'qos_orates'            : 'COMMAN',
        'qos_orules'            : 'QOS',
        'dnsmasq_custom'        : 'TXT',
    }
    no_tag_keys = {             # placeholder for debugging/disable
    }

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        if self.file_version:
            if self.file_version.startswith("0.8"):
                warn("RML version 0.8 ignores blah blah")



#==========================================================================
# Global RML TagSection field hooks
def emit_onoffdisabled(self, nvdict, value):
    if value == '0':
        return "Off"
    elif value == '1':
        return "On"
    elif value == '-1':
        return "Disabled"

def parse_onoffdisabled(self, nvdict, value):
    if value == "Off":
        return '0'
    elif value == "On":
        return '1'
    elif value == "Disabled":
        return '-1'

def emit_range(self, nvdict, value):
    return value.replace(':', '-')
def parse_range(self, nvdict, value):
    return value.replace('-', ':')

#==========================================================================
# RML Tag Section Handlers

class TagSection(object):
    """Superclass for a Tag Section Handler.

    A TagSection is a parser and formatter for a custom-formatted
    RML-file section for a specific key type.
    A new instance must be used for each parsing or formatting task.

    The parser converts the RML tag section into a NVRAM value string that
    typically is a set of records of fields with field-separator='<' and
    record-separator='>':
        parse_line(line)    - parse the next RML line.
        parse_close()       - finalize the NVRAM value and return it.
    The formatter converts the NVRAM value string into a formatted RML
    tag section:
        emit(value)         - format the RML section for value and return it.

    This default superclass formats NVRAM records into one record per line,
    with tab-delimited fields and optional record-numbering.

    NB: NVRAM field values cannot contain tabs if nv_field_separator != None.
    """
    tag = None                      # subclasses define this (all uppercase)
    nv_field_separator = '<'        # None: only 1 field per record.
    nv_record_separator = '>'       # 
    nv_close_fields  = False        # True: NVRAM has a closing field_separator 
    nv_close_records = False        # True: NVRAM has a closing record separator
    numbering = False               # True: first RML field is the record number
                                    # (NB: ignored when parsing).

    #==============================
    def __new__(cls, tag, key, nvdict=None):
        """Class factory: return a TagSection subclass for string 'tag'.
        key is the associated nvram key (for diagnostic messages).
        nvdict is the current NVRAM dictionary which can be used to
        look up values for other keys.
        """
        for c in all_subclasses(cls):
            if c.tag and c.tag == tag:
                return super().__new__(c)
        error("Unknown RML section tag: %s", tag)
        return cls

    #==============================
    def __init__(self, tag, key, nvdict=None):
        """Initialize formatting and parsing.
        (only one will be subsequently done by this instance).
        """
        self.tag = tag
        self.key = key
        self.nvdict = nvdict
        self.value = ""     # initialize parsed string value
        self.first = True   # True if parsing the first line

    #==============================
    def parse_close(self):
        """Close off parsing, convert our value to the final NVRAM string
        and return it.
        """
        # strip closing nv_record_separator if this NVRAM key omits it:
        #if (self.value and not self.nv_close_records and
        #            self.value[-1] == self.nv_record_separator):
        #    self.value = self.value[:-1]
        if self.nv_close_records:
            self.value += self.nv_record_separator
        return self.value

    #==============================
    def parse_line(self, line):
        """Parse the next line of the section and add it to our NVRAM value."""
        if line.lstrip()[0] == '#': return       # skip comments
        if self.numbering:
            (n, line) =  line.split('\t', maxsplit=1)  # NB: n is ignored
        if self.nv_field_separator:
            # multiple fields per record
            fields = line.split('\t')
            value = self.nv_field_separator.join(fields)
            if self.nv_close_fields:
                value += self.nv_field_separator
        else:
            value = line
        if self.first:
            self.first = False
        else:
            self.value += self.nv_record_separator
        self.value += value


    #==============================
    def emit(self, value):
        """Return a string consisting of the entire formatted section.
        Parse the NVRAM value into records of fields using nv_record_separator
        and nv_field_separator, and write them as lines of tab-delimited fields,
        with optional record numbering.
        """
        buf = ""
        # strip any trailing record delimiter
        if (value and self.nv_close_records and
                value[-1] == self.nv_record_separator):
            value = value[:-1]
        records = value.split(self.nv_record_separator)
        count = 0
        for rec in records:
            count += 1
            if self.numbering:
                buf += "{}\t".format(count)
            if self.nv_field_separator:
                nvfields = rec.split(self.nv_field_separator)
                if self.nv_close_fields:
                    nvfields = nvfields[:-1]  # last field is empty terminator
                buf += "\t".join(nvfields)
            else:
                buf += rec
            buf += "\n"
        return buf

#======================================================
class TagSection_TAB(TagSection):
    """TAB Section: basic tab separated fields."""
    tag = "TAB"
#======================================================
class TagSection_TABN(TagSection):
    """TABN Section: same as TAB but with numbering."""
    tag = "TABN"
    numbering = True
#======================================================
class TagSection_TABC(TagSection):
    """TABC Section: same as TAB but NVRAM has a closing '>'."""
    tag = "TABC"
    nv_close_records = True
#======================================================
class TagSection_TABCN(TagSection):
    """TABCN Section: same as TABC but with numbering."""
    tag = "TABCN"
    nv_close_records = True
    numbering = True

#======================================================
class TagSection_COMMA(TagSection):
    """COMMA Section: comma-delimited NVRAM records formatted into
    separate numbered lines."""
    tag = "COMMA"
    nv_field_separator = None
    nv_record_separator = ','
class TagSection_COMMAN(TagSection_COMMA):
    tag = "COMMAN"
    numbering = True

#======================================================
class TagSection_SPACE(TagSection):
    """SPACEN Section: space-delimited NVRAM record formatted into
    separate numbered lines."""
    tag = "SPACE"
    nv_field_separator = None
    nv_record_separator = ' '
class TagSection_SPACEN(TagSection_SPACE):
    tag = "SPACEN"
    numbering = True

#======================================================
class TagSection_TXT(TagSection):
    """TXT Section: text with NVRAM escaped \t tabs and \n newlines expanded."""
    tag = "TXT"

    #==============================
    def parse_line(self, line):
        """Parse the next line of the section and add it to our NVRAM value."""
        self.value += line.replace('\t', "\\t") + "\\n"

    #==============================
    def parse_close(self):
        # strip last newline if required
        if self.value and not self.nv_close_records:
            if self.value[-2:] == "\\n":
                self.value = self.value[:-2]
        return self.value

    #==============================
    def emit(self, value):
        buf = value.replace("\\t", '\t')
        buf = buf.replace("\\n", '\n')
        if buf[-1] != '\n':
            buf += '\n'
        return buf


#======================================================
class TagSectionSpaces(TagSection):
    """
    TagSection with formatted space-delimited fields (abstract superclass).

    Each record appears as a formatted space-delimited line of positional
    fields, followed optionally by non-positional lines starting with
    a tab (\t), that have the format:
        \t <field-name>: <value>

    fielddefs is a list of record field definitions in order of
    appearance in the RML file.
    Each fielddefs entry is a dict with the following fields:
        name        - The field name as it appears in the header comment.
        width       - The field width for formatting (space-padded).
                        0    - no truncation (use only for last field).
                        None - field is always on a non-positional line.
                      Values are always right-padded to width.  If they
                      exceed width, then they are bumped to a non-positional
                      line and the special value '@' is used.
        pos         - The field position in the NVRAM record (offset 0).
                      This can also be a string:
            'number'     -  Emit: the record number; Parse: ignored.
        hook        - A pair of hooks to translate to/from the RML value:
                        (emit_hook, parse_hook)
                      Each has the form:  hook(self, nvdict, value)
                      where self is the TagSection instance doing the calling.
                      NB: when parsing, the nvdict will only contain values
                      parsed up to that point in the file.
        default     - [optional]: used for non-positional fields. If
                      the NVRAM value is this value, the non-positional line
                      is omitted in the RML.  If absent, the default default
                      is the empty string.
    See subclass examples below.

    The emitter/parser includes a header comment with the field names
    in the order they appear in the file, and they are parsed in
    that order (it doesn't need to match the fielddefs order). (This allows
    for re-arranging the fielddefs order in RML files without breaking the
    parsing).

    Parsing a fielddefs record assumes field values don't contain spaces.
    Some NVRAM record fields may contain spaces and these should appear
    last in the fielddefs list (the last field preserves spaces), and
    should have a 'width' of zero.
    (Only one field can preserve spaces this way, but so far this is true
    for all known NVRAM records. If multiple space-preserving fields are
    needed, set 'width' to None make the field non-positional.

    Fielddef names must not contain spaces.
    There must be at least one positional field.

    Special RML field values:
        -       - (single dash): emptychar: value is ""
        @       - bumpchar:  value is found on a following non-positional line.

    """
    header_magic = "#-"     # to detect the header comment
    # These can be overridden on a per field basis by including
    # 'emptychar' or 'bumpchar' entries in a fielddef entry.
    emptychar = '-'         # value is ""
    bumpchar = '@'          # value is on a following line
    fielddefs = None

    #==============================
    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        # for parsing:
        self.first = True       # True if this is the first record
        self.nvram_fields = self.get_nvram_fields()
        self.field_map = None
        # Get the list of positional field indexes (width != None)
        self.positional_fields = [
            idx for idx in range(len(self.fielddefs)) if
                    self.fielddefs[idx]['width'] is not None]
        self.pending = None      # pending data for the current record
        self.maxsplit = len(self.positional_fields)
        if self.fielddefs[self.positional_fields[-1]]['width'] == 0:
            # last positional field preserves spaces; don't split on it:
            self.maxsplit -= 1
        # for emitting:
        self.fmt = self.make_fmt()

    #==============================
    def make_fmt(self):
        """Construct and return a fmt string for the positional line."""
        if not self.fielddefs: return None
        fmt = ""
        first = True
        for f in self.fielddefs:
            width = f['width']
            if width is None: continue      # omit non-positional
            if not first:
                fmt += ' '
            else:
                first = False
            if width == 0:
                fmt += "{:<}"
            else:
                nlen = len(f['name'])
                if nlen > width:
                    width = nlen
                fmt += "{{:<{}}}".format(width)
        return fmt

    #==============================
    def get_field_idx(self, fname):
        """Return the index of our fielddef entry with name fname."""
        for idx in range(len(self.fielddefs)):
            if self.fielddefs[idx]['name'] == fname:
                return idx
        return None

    #==============================
    def get_nvram_fields(self):
        """Return a list of our fielddef entry indexes in order of
        NVRAM position."""
        if not self.fielddefs: return None
        flist = [None] * len(self.fielddefs)
        for idx in range(len(self.fielddefs)):
            pos = self.fielddefs[idx]['pos']
            if isinstance(pos, int):
                flist[pos] = idx
        return flist

    #==============================
    def parse_close(self):
        """Close off parsing, convert our value to the final NVRAM string
        and return it.
        """
        if self.pending:
            self.close_record()
        if self.nv_close_records:
            self.value += self.nv_record_separator
        return self.value

    #==============================
    def parse_line(self, line):
        """Parse the next line of the section and add it to our NVRAM value.
        """
        if not self.fielddefs:
            warn("TagSection %s: INTERNAL: no fielddefs defined!\n", self.tag)
            return

        line_lstrip = line.lstrip()
        # Empty line:
        if not line_lstrip:
            return

        # Comments:
        elif line_lstrip[0] == '#':
            if self.first:
                line = line_lstrip
                if line[:len(self.header_magic)] == self.header_magic:
                    # Initial header comment; set a new positional_fields
                    # (an array of fielddef indexes)
                    self.positional_fields = []
                    line = line[len(self.header_magic):]     # skip magic
                    for fname in line.split():
                        idx = self.get_field_idx(fname)
                        if idx is None:
                            error("TagSection [%s:%s]: unknown field name"
                                    " in header comment: %s",
                                    self.tag, self.key, fname)
                            continue
                        self.positional_fields.append(idx)
            return

        # Non-positional fields:
        elif line[0] == '\t':
            (fname, val) = re.split(':', line[1:], maxsplit=1)
            val = val[1:]   # strip one leading space
            if not self.pending:
                # No pending record:
                error("TagSection [%s:%s]: spurious entry: %s: %s\n",
                    self.tag, self.key, fname, val)
                return
            idx = self.get_field_idx(fname)
            if idx is None:
                error("TagSection [%s:%s]: unknown field name: %s",
                        self.tag, self.key, fname)
                return
            self.pending[idx] = val
            return

        # New record (positional line)
        else:
            # close any pending record.
            if self.pending:
                self.close_record()

            # Get the field values from the line 
            values = line.split(maxsplit=self.maxsplit)
            if len(values) != len(self.positional_fields):
                error("TagSection [%s:%s]: expecting %d fields, found %d\n",
                    self.tag, self.key,
                    len(self.positional_fields), len(values))
                return

            # Create a new pending record:
            # an array of parsed values in fielddefs order.
            self.pending = [None] * len(self.fielddefs)
            i = 0
            for idx in self.positional_fields:
                self.pending[idx] = values[i]
                i += 1

    #==============================
    def close_record(self):
        """Close any pending parsed record and add it to our nvram value..."""
        if not self.pending: return

        # add any record separator
        if self.first:
            self.first = False
        else:
            self.value += self.nv_record_separator

        # iterate in NVRAM field order:
        nv_values = []
        for idx in self.nvram_fields:
            if idx is None: continue          # skip non-NVRAM fields
            f = self.fielddefs[idx]
            val = self.pending[idx]
            val = self.parse_value(f, val)  # convert to NVRAM value
            nv_values.append(val)

        # Append to our value with appropriate separators
        self.value += self.nv_field_separator.join(nv_values)
        if self.nv_close_fields:
            self.value += self.nv_field_separator

        self.pending = None

    #==============================
    def get_emptychar(self, f):
        return f['emptychar'] if 'emptychar' in f else self.emptychar
    def get_bumpchar(self, f):
        return f['bumpchar'] if 'bumpchar' in f else self.bumpchar

    #==============================
    def parse_value(self, f, val):
        """Convert RML value 'val' to the appropriate NVRAM value
        for field f and return it."""

        # Handle any special values
        if val == self.get_emptychar(f):
            val = ""
        elif val == self.get_bumpchar(f):
            warn("Missing value for '%s'\n", f['name'])
            val = ""
        elif val == None:
            val = f['default'] if 'default' in f else ""
            dbg("Assigning default value for '%s': '%s'\n",
                f['name'], str(val))

        # apply any hook
        if f['hook']:
            (emit_hook, parse_hook) = f['hook']
            if parse_hook:
                val = parse_hook(self, self.nvdict, val)

        return val

    #==============================
    def emit(self, value):
        """Return a string consisting of the entire formatted section.
        """
        buf = ""
        # strip any trailing record delimiter from the NVRAM value
        if (value and self.nv_close_records and
                value[-1] == self.nv_record_separator):
            value = value[:-1]
        records = value.split(self.nv_record_separator)

        # output any field headers
        if self.fielddefs and self.fmt:
            buf += self.header_magic
            buf += self.fmt.format(
                *[f['name'] for f in self.fielddefs if f['width'] is not None])
            buf += "\n"
        # output a comment for non-positionals:
        non_pos = [f['name'] for f in self.fielddefs if f['width'] is None]
        if non_pos:
            buf += "# Extra fields (NB: use tab): " + ' '.join(non_pos) + '\n'

        # output records
        count = 0
        for rec in records:
            count += 1
            nvfields = rec.split(self.nv_field_separator)
            if self.nv_close_fields:
                nvfields = nvfields[:-1]  # last field is empty terminator
            buf += self.emit_record(nvfields, count)
        return buf

    #==============================
    def emit_record(self, nvfields, count=None):
        """Return the formatted value for record consisting of nvfields.
        count is the current record number.
        Format a line of positional columns described by the our 'fielddefs'
        instance variable, followed by lines for any non-positional fields.
        """
        buf = ""
        non_positionals = []
        # Line of positional fields:
        val_list = []
        for f in self.fielddefs:
            fwidth = f['width']
            if fwidth is None: continue     # skip non-positional
            (nv, val) = self.emit_value(f, nvfields, count=count)
            # bump any overwidth:
            if fwidth > 0 and len(str(val)) > fwidth:
                non_positionals.append((f, nv, val))
                val = self.get_bumpchar(f)
            # special substitutions:
            if not val:
                val = self.get_emptychar(f)
            val_list.append(val)
        buf += ' ' * len(self.header_magic)     # to match header comment
        buf += self.fmt.format(*val_list)
        buf += '\n'

        # Non-positional fields:
        for f in self.fielddefs:
            if f['width'] is not None: continue     # skip positional
            (nv, val) = self.emit_value(f, nvfields, count=count)
            non_positionals.append((f, nv, val))
        for f, nv, val in non_positionals:
            default = f['default'] if 'default' in f else ""
            if nv == default:
                # skip defaults
                dbg("Omitting non-positional default value for '%s': '%s'\n",
                    f['name'], str(nv))
                continue
            buf += "\t{}: {}\n".format(f['name'], val)
        return buf



    #==============================
    def emit_value(self, f, nvfields, count=None):
        """Return the value for field f as a pair (nv, val) where
        nv is the raw NVRAM value and val is the formatted value.
        f is the fielddef entry and nvfields is the list of NVRAM field values.
        count is the current record number.
        """
        pos = f['pos']
        if isinstance(pos, int):
            nv = nvfields[pos]
            # apply any hook
            if f['hook']:
                (emit_hook, parse_hook) = f['hook']
                if emit_hook:
                    val = emit_hook(self, self.nvdict, nv)
                    dbg2("HOOK %s(%s) --> %s\n",
                            emit_hook.__name__, str(nv), str(val))
            else:
                val = nv
        elif pos == 'number' and count is not None:
            nv = None
            val = count
        else:
            error("Invalid 'pos' value in %s['%s']: '%s'",
                    self.__class__.__name__, f['name'], pos)
            nv = None
            val = "?"
        return (nv, val)

#======================================================

#============================================
class TagSection_FWD(TagSectionSpaces):
    """FWD Section: port forwarding layout"""
    tag = "FWD"
    nv_close_records = True

    protos={'0': "", '1': "TCP", '2': "UDP", '3': "Both"}

    def emit_proto(self, nvdict, value):
        return self.protos[value]

    def parse_proto(self, nvdict, value):
        for k,v in self.protos.items():
            if value == v:
                return k
        return value

    fielddefs=[
        {'name':  "on",           'width': 4,      'pos': 0,
            'hook': ( emit_onoffdisabled, parse_onoffdisabled )},
        {'name':  "proto",        'width': 4,      'pos': 1,
            'hook': ( emit_proto, parse_proto )},
        {'name':  "src-addr",     'width': None,   'pos': 2,  'hook':None},
        {'name':  "ext-ports",    'width': 11,     'pos': 3,
            'hook': ( emit_range, parse_range )},
        {'name':  "int-addr",     'width': 15,     'pos': 5,  'hook':None},
        {'name':  "int-port",     'width': 5,      'pos': 4,  'hook':None},
        {'name':  "description",  'width': 0,      'pos': 6,  'hook':None},
    ]

#============================================
class TagSection_STATIC(TagSectionSpaces):
    """Static DHCP Section"""
    tag = "STATIC"
    nv_close_records = True

    fielddefs=[
        {'name':  "bound",       'width': 5,      'pos': 3,
            'hook': ( emit_onoffdisabled, parse_onoffdisabled )},
        {'name':  "ip-addr",     'width': 15,     'pos': 1,  'hook':None},
        {'name':  "mac-addrs",   'width': 35,     'pos': 0,  'hook':None},
        {'name':  "hostname",    'width': 0,      'pos': 2,  'hook':None},
    ]

#============================================
class TagSection_BWL(TagSectionSpaces):
    """Bandwidth Limit Section"""
    tag = "BWL"
    nv_close_records = False

    fielddefs=[
# XXX: enab/descr (to be) added in 2021.3; don't forget to renum 'pos'
#        {'name':  "enab",        'width': 4,      'pos': 0,  'hook': (
#                emit_onoffdisabled,
#                parse_onoffdisabled )},
        {'name':  "ipmac",       'width': 19,     'pos': 0,  'hook':None},
        {'name':  "dlrate",      'width': 6,      'pos': 1,  'hook':None},
        {'name':  "dlceil",      'width': 6,      'pos': 2,  'hook':None},
        {'name':  "ulrate",      'width': 6,      'pos': 3,  'hook':None},
        {'name':  "ulceil",      'width': 6,      'pos': 4,  'hook':None},
        {'name':  "prio",        'width': 4,      'pos': 5,  'hook':None},
        {'name':  "tcplimit",    'width': 8,      'pos': 6,  'hook':None,
            'default' : '0'},
        {'name':  "udplimit",    'width': 8,      'pos': 7,  'hook':None,
            'default' : '0'},
#        {'name':  "descr",       'width': 0,      'pos': 9,  'hook':None},
    ]


#============================================
class TagSection_QOS(TagSectionSpaces):
    """QOS Section: QoS classification rules"""
    tag = "QOS"

    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self.classnames = None
        self.classdict = None

    def chk_classnames(self, nvdict):
        """Check our classnames list exists; create if not."""
        if not self.classnames:
            if 'qos_classnames' in nvdict:
                self.classnames = nvdict['qos_classnames'].split(' ')
                self.classnames[-1] = "Disabled"
            else:
                warn("qos_classnames not found - is RML sorted?")

    def chk_classdict(self, nvdict):
        """Check our classdict dict exists; create if not."""
        if not self.classdict:
            self.chk_classnames(nvdict)
            if self.classnames:
                self.classdict = {}
                for i in range(len(self.classnames)):
                    self.classdict[self.classnames[i]] = str(i)
                self.classdict['Disabled'] = "-1"

    def emit_qosclass(self, nvdict, value):
        """Convert numerical class names to symbolic."""
        self.chk_classnames(nvdict)
        if self.classnames:
            value = self.classnames[int(value)]
        return value

    def parse_qosclass(self, nvdict, value):
        """Convert symbolic class names to their index."""
        if value and not value.isdigit():
            self.chk_classdict(nvdict)
            if self.classdict:
                value = self.classdict[value]
        return value

    adirs = {'0':"Any", '1':"Dst IP", '2':"Src IP", '3':"Src MAC"}
    adirs_rev = {v:k for k,v in adirs.items()}
    def emit_adir(self, nvdict, value):
        return self.adirs[value] if value in self.adirs else value
    def parse_adir(self, nvdict, value):
        return self.adirs_rev[value] if value in self.adirs_rev else value

    pdirs = {'a':"Any", 'd':"Dst", 's':"Src", 'x':"Src/Dst"}
    pdirs_rev = {v:k for k,v in pdirs.items()}
    def emit_pdir(self, nvdict, value):
        return self.pdirs[value] if value in self.pdirs else value
    def parse_pdir(self, nvdict, value):
        return self.pdirs_rev[value] if value in self.pdirs_rev else value

    def emit_proto(self, nvdict, value):
        if value == '-2':
            return "Any"
        elif value == '-1':
            return "TCP/UDP"
        else:
            return PROTOCOLS[value] if value in PROTOCOLS else value
    def parse_proto(self, nvdict, value):
        if value == "Any":
            return '-2'
        elif value == 'TCP/UDP':
            return '-1'
        else:
            return PROTOCOLS_REV[value] if value in PROTOCOLS_REV else value


    fielddefs=[
        {'name':  "N",      'width': 3,    'pos': 'number',  'hook':None},
        {'name':  "proto",  'width': 7,    'pos': 2,
            'hook': ( emit_proto, parse_proto )},
        {'name':  "pdir",   'width': 7,    'pos': 3,
            'hook': ( emit_pdir, parse_pdir )},
        {'name':  "port",   'width': 12,   'pos': 4,
            'hook': ( emit_range, parse_range )},
        {'name':  "kbytes", 'width': 9,    'pos': 7,
            'hook': ( emit_range, parse_range )},
        {'name':  "class",  'width': 12,   'pos': 9,
            'hook': ( emit_qosclass, parse_qosclass )},
        {'name':  "name",   'width': 0,    'pos': 10, 'hook':None},
        {'name':  "adir",    'width': None,    'pos': 0,
            'default' : '0',
            'hook': ( emit_adir, parse_adir )},
        {'name':  "addr",   'width': None, 'pos': 1,  'hook':None},
        {'name':  "layer7", 'width': None, 'pos': 6,  'hook':None},
        {'name':  "ipp2p",  'width': None, 'pos': 5,  'hook':None,
                'default': "0",
            },
        {'name':  "dscp",   'width': None, 'pos': 8,  'hook':None},
    ]


#==============================================================================
# Args

def handle_args():
    """Parse args and return the resulting Namespace object."""

    parser = argparse.ArgumentParser(
        description =
"nvtool v" + __version__ +
'''

Convert router nvram files/data to/from text.

Keys/values are read from input, optionally filtered and sorted,
and written to output.

The input format is automatically detected. If --otype is not provided, the
output type is inferred from the output file extension if possible.

''',

        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=35),
        # NB: use add_help=False to prevent auto -h/--help
        epilog =

        "\nOutput <otype> types (and extensions):\n" +
            "\n".join(
            map(lambda cls: "    {:8s} - {}".format(cls.ftype, cls.help),
                sorted(
                    [cls for cls in NVFile.__subclasses__() if cls.help],
                    key=lambda c: c.ftype))
                ) + "\n" +

        "\nRouter OSes:\n" +
            "\n".join(
            map(lambda cls: "    {:16s} - {}".format(cls.name, cls.help),
                sorted(
                    [cls for cls in all_subclasses(Router) if cls.help],
                    key=lambda c: c.name))
                ) + "\n" +

'''

The --filter option can be used to filter out nvram keys.
A filter file is a list of lines with three tab-delimited fields:
    <key_pat>   [\\t+ <val_pat>  [\\t+ <action>]]
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
'''

        )

    # Options
    parser.add_argument(
        '-d', '--debug', action='count', default=0,
        help="increase debug level")
    #parser.add_argument(
    #    '-v', '--verbose', action='count', default=0,
    #    help='''increase verbosity''')
    parser.add_argument(
        '-o', '--otype',
        metavar='<otype>',
        choices=[t.ftype for t in NVFile.__subclasses__() if t.ftype],
        help="produce output of type %(metavar)s")

    parser.add_argument(
        '-C', '--keepconfig', action='store_true',
        help="include any internal CFG: keys in the output")
    parser.add_argument(
        '-S', '--nosort', action='store_true',
        help="don't sort the output by key")
    parser.add_argument(
        '-R', '--router', action='store',
        metavar='<r>',
        help="infile keys/values are assumed to be from router OS %(metavar)s")
    parser.add_argument(
        '-T', '--target', action='store',
        metavar='<r>',
        help="output keys/values to be formatted for router OS %(metavar)s")
    parser.add_argument(
        '-V', '--version', action='store',
        metavar='<vers>',
        help="produce output for version %(metavar)s")
    parser.add_argument(
        '-Z', '--nozip', action='store_true',
        help="don't gzip the output (for those gzipped output formats)")

    parser.add_argument(
        '-D', '--default', action='store',
        metavar='<file>',
        help="add all the keys/values from %(metavar)s before reading the input")
    parser.add_argument(
        '-O', '--override', action='store',
        metavar='<file>',
        help="add all keys/values from %(metavar)s after reading the input")

    parser.add_argument(
        '-F', '--filter', action='append',
        metavar='<file>',
        help="filter the input using the regex patterns from %(metavar)s. " +
            " This can be used multiple times to catenate filters"
        )
    parser.add_argument(
        '-I', '--invert', action='store_true',
        help="invert the filter")

    # positional args
    parser.add_argument('infile', nargs='?', default='-',
        help="the input file name (or '-' for stdin)")
    parser.add_argument('outfile', nargs='?', default='-',
        help="the output file name (or '-' for stdout)")

    opts = parser.parse_args()

    return opts

#==============================================================================
def main():
    """The main program.  Parse args, initialize and run."""
    opts = handle_args()

    # set globals for diagnostics
    global DEBUG, LINENO
    DEBUG = opts.debug
    LINENO = None
    dbg("opts=%s\n", str(opts))

    # Get a router object for the name
    in_router = Router.from_name(opts.router) if opts.router else None
    out_router = Router.from_name(opts.target) if opts.target else None

    # Read any defaults and initialize nvdict
    if opts.default:
        dbg("Reading defaults from %s", opts.default)
        default_nvfile = NVFile.from_file(opts.default)
        nvdict = default_nvfile.nvdict.copy()
    else:
        nvdict = {}

    # Read input file
    if opts.infile:
        in_nvfile = NVFile.from_file(opts.infile, router=in_router)
        in_dict = in_nvfile.nvdict
    else:
        in_dict = {}

    # Apply any filter (only to the input file, not the defaults)
    if opts.filter:
        filterlist = []
        for f in opts.filter:
            filterlist = filter_read(f, filterlist)
        dbg2("filterlist=%s\n", str(filterlist))
        filtered_dict = nvfilter(in_dict, filterlist,
            default_action=False,
            invert=opts.invert)
    else:
        filtered_dict = in_dict

    # Merge into nvdict (python 3.4+)
    nvdict = { **nvdict, **filtered_dict }

    # Merge in any overrides:
    if opts.override:
        override_nvfile = NVFile.from_file(opts.override)
        nvdict = { **nvdict, **override_nvfile.nvdict }

    # write it:
    out_nvfile = NVFile.from_type(opts.otype,
                path=opts.outfile,
                router=out_router,
                version=opts.version)
    if not out_nvfile:
        error("Unable to determine output type.\n")
        exit(1)

    # set output options:
    if opts.nosort:             out_nvfile.is_sorted = False
    if opts.nozip:              out_nvfile.is_zipped = False
    if opts.keepconfig:         out_nvfile.keepconfig = True

    # write it
    out_nvfile.write(opts.outfile, nvdict)

#==============================================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("caught interrupt")
