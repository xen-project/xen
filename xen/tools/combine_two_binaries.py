#!/usr/bin/env python3

from __future__ import print_function
import argparse
import functools
import re
import struct
import sys

parser = argparse.ArgumentParser(description='Generate assembly file to merge into other code.')
auto_int = functools.update_wrapper(lambda x: int(x, 0), int) # allows hex
parser.add_argument('--script', dest='script',
                    required=True,
                    help='Linker script for extracting symbols')
parser.add_argument('--bin1', dest='bin1',
                    required=True,
                    help='First binary')
parser.add_argument('--bin2', dest='bin2',
                    required=True,
                    help='Second binary')
parser.add_argument('--gap', dest='gap',
                    required=True,
                    type=auto_int,
                    help='Gap inserted at the start of code section')
parser.add_argument('--text-diff', dest='text_diff',
                    required=True,
                    type=auto_int,
                    help='Difference between code section start')
parser.add_argument('--output', dest='output',
                    help='Output file')
parser.add_argument('--map', dest='mapfile',
                    help='Map file (NM) to read for symbols to export')
parser.add_argument('--exports', dest='exports',
                    help='Symbols to export')
parser.add_argument('--section-header', dest='section_header',
                    default='.section .init.text, "ax", @progbits',
                    help='Section header declaration')
parser.add_argument('-v', '--verbose',
                    action='store_true')
args = parser.parse_args()

gap = args.gap
text_diff = args.text_diff

# Parse linker script for external symbols to use.
# Next regex matches expanded DECLARE_IMPORT lines in linker script.
symbol_re = re.compile(r'\s+(\S+)\s*=\s*\.\s*\+\s*\((\d+)\s*\*\s*0\s*\)\s*;')
symbols = {}
lines = {}
for line in open(args.script):
    m = symbol_re.match(line)
    if not m:
        continue
    (name, line_num) = (m.group(1), int(m.group(2)))
    if line_num == 0:
        raise Exception("Invalid line number found:\n\t" + line)
    if line_num in symbols:
        raise Exception("Symbol with this line already present:\n\t" + line)
    if name in lines:
        raise Exception("Symbol with this name already present:\n\t" + name)
    symbols[line_num] = name
    lines[name] = line_num

exports = []
if args.exports is not None:
    exports = dict([(name, None) for name in args.exports.split(',')])

# Parse mapfile, look for symbols we want to export.
if args.mapfile is not None:
    exports["dummy_start"] = None
    for line in open(args.mapfile):
        parts = line.split()
        if len(parts) != 3:
            continue
        addr, sym_type, sym = parts
        if sym_type.upper() == 'T' and sym in exports:
            exports[sym] = int(addr, 16)
    if exports["dummy_start"] != 0:
        raise Exception("dummy_start symbol expected to be present and 0")
    del exports["dummy_start"]

for (name, addr) in exports.items():
    if addr is None:
        raise Exception("Required export symbols %s not found" % name)

file1 = open(args.bin1, 'rb')
file2 = open(args.bin2, 'rb')
file1.seek(0, 2)
size1 = file1.tell()
file2.seek(0, 2)
size2 = file2.tell()
if size1 > size2:
    file1, file2 = file2, file1
    size1, size2 = size2, size1
if size2 != size1 + gap:
    raise Exception('File sizes do not match')
del size2

file1.seek(0, 0)
data1 = file1.read(size1)
del file1
file2.seek(gap, 0)
data2 = file2.read(size1)
del file2

max_line = max(symbols.keys())

def to_int32(n):
    '''Convert a number to signed 32 bit integer truncating if needed'''
    mask = (1 << 32) - 1
    h = 1 << 31
    return (n & mask) ^ h - h

i = 0
references = {}
internals = 0
while i <= size1 - 4:
    n1 = struct.unpack('<I', data1[i:i+4])[0]
    n2 = struct.unpack('<I', data2[i:i+4])[0]
    i += 1
    # The two numbers are the same, no problems
    if n1 == n2:
        continue
    # Try to understand why they are different
    diff = to_int32(n1 - n2)
    if diff == -gap: # this is an internal relocation
        pos = i - 1
        print("Internal relocation found at position %#x "
              "n1=%#x n2=%#x diff=%#x" % (pos, n1, n2, diff),
              file=sys.stderr)
        i += 3
        internals += 1
        if internals >= 10:
            break
        continue
    # This is a relative relocation to a symbol, accepted, code/data is
    # relocatable.
    if diff < gap and diff >= gap - max_line:
        n = gap - diff
        symbol = symbols.get(n)
        # check we have a symbol
        if symbol is None:
            raise Exception("Cannot find symbol for line %d" % n)
        pos = i - 1
        if args.verbose:
            print('Position %#x %d %s' % (pos, n, symbol), file=sys.stderr)
        i += 3
        references[pos] = symbol
        continue
    # First byte is the same, move to next byte
    if diff & 0xff == 0 and i <= size1 - 4:
       continue
    # Probably a type of relocation we don't want or support
    pos = i - 1
    suggestion = ''
    symbol = symbols.get(-diff - text_diff)
    if symbol is not None:
        suggestion = " Maybe %s is not defined as hidden?" % symbol
    raise Exception("Unexpected difference found at %#x "
                    "n1=%#x n2=%#x diff=%#x gap=%#x.%s" % \
                    (pos, n1, n2, diff, gap, suggestion))
if internals != 0:
    raise Exception("Previous relocations found")

def line_bytes(buf, out):
    '''Output an assembly line with all bytes in "buf"'''
    # Python 2 compatibility
    if type(buf) == str:
        print("\t.byte " + ','.join([str(ord(c)) for c in buf]), file=out)
    else:
        print("\t.byte " + ','.join([str(n) for n in buf]), file=out)

def part(start, end, out):
    '''Output bytes of "data" from "start" to "end"'''
    while start < end:
        e = min(start + 16, end)
        line_bytes(data1[start:e], out)
        start = e

def reference(pos, out):
    name = references[pos]
    n = struct.unpack('<I', data1[pos:pos+4])[0]
    sign = '+'
    if n >= (1 << 31):
        n -= (1 << 32)
    n += pos
    if n < 0:
        n = -n
        sign = '-'
    print("\t.hidden %s\n"
          "\t.long %s %s %#x - ." % (name, name, sign, n),
          file=out)

def output(out):
    prev = 0
    exports_by_addr = {}
    for (sym, addr) in exports.items():
        exports_by_addr.setdefault(addr, []).append(sym)
    positions = list(references.keys())
    positions += list(exports_by_addr.keys())
    for pos in sorted(positions):
        part(prev, pos, out)
        prev = pos
        if pos in references:
            reference(pos, out)
            prev = pos + 4
        if pos in exports_by_addr:
            for sym in exports_by_addr[pos]:
                print("\t.global %s\n"
                      "\t.hidden %s\n"
                      "%s:" % (sym, sym, sym),
                      file=out)
    part(prev, size1, out)

out = sys.stdout
if args.output is not None:
    out = open(args.output, 'w')
print('''/*
 * File autogenerated by combine_two_binaries.py DO NOT EDIT
 */''', file=out)
print('\t' + args.section_header, file=out)
print('obj32_start:', file=out)
output(out)
print('\n\t.section .note.GNU-stack,"",@progbits', file=out)
out.flush()
