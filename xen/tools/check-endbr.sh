#!/bin/sh
#
# Usage ./$0 xen-syms
#
# When CET-IBT (Control-flow Enforcement Technology, Indirect Branch Tracking)
# is active, ENDBR instructions mark legal indirect branch targets in the
# .text section.
#
# However x86 is a variable length instruction set so the same byte pattern
# can exist embedded in other instructions, or crossing multiple instructions.
# This script searches .text for any problematic byte patterns which aren't
# legitimate ENDBR instructions.
#
set -e

# Pretty-print parameters a little for message
MSG_PFX="${0##*/} ${1##*/}"

OBJCOPY="${OBJCOPY:-objcopy}"
OBJDUMP="${OBJDUMP:-objdump}"
ADDR2LINE="${ADDR2LINE:-addr2line}"
AWK="${AWK:-awk}"

D=$(mktemp -d)
trap "rm -rf $D" EXIT

TEXT_BIN=$D/xen-syms.text
VALID=$D/valid-addrs
ALL=$D/all-addrs
BAD=$D/bad-addrs

# Check that grep can do binary searches.  Some, e.g. busybox, can't.  Leave a
# warning but don't fail the build.
echo "X" | grep -aob "X" -q 2>/dev/null ||
    { echo "$MSG_PFX Warning: grep can't do binary searches" >&2; exit 0; }

# Check whether grep supports Perl regexps. Older GNU grep doesn't reliably
# find binary patterns otherwise.
perl_re=true
echo "X" | grep -aobP "\x58" -q 2>/dev/null || perl_re=false

#
# First, look for all the valid endbr64 instructions.
# A worst-case disassembly, viewed through cat -A, may look like:
#
# ffff82d040337bd4 <endbr64>:$
# ffff82d040337bd4:^If3 0f 1e fa          ^Iendbr64 $
# ffff82d040337bd8:^Ieb fe                ^Ijmp    ffff82d040337bd8 <endbr64+0x4>$
# ffff82d040337bda:^Ib8 f3 0f 1e fa       ^Imov    $0xfa1e0ff3,%eax$
#
# Want to grab the address of endbr64 instructions only, ignoring function
# names/jump labels/etc, so look for 'endbr64' preceded by a tab and with any
# number of trailing spaces before the end of the line.
#
${OBJDUMP} -j .text $1 -d -w | grep '	endbr64 *$' | cut -f 1 -d ':' > $VALID &

#
# Second, look for all endbr64, endbr32 and nop poison byte sequences
# This has a couple of complications:
#
# 1) Grep binary search isn't VMA aware.  Copy .text out as binary, causing
#    the grep offset to be from the start of .text.
#
# 2) dash's printf doesn't understand hex escapes, hence the use of octal.
#    `grep -P` on the other hand has various ambiguities with octal-like
#    escapes, so use hex escapes instead which are unambiguous.
#
# 3) AWK can't add 64bit integers, because internally all numbers are doubles.
#    When the upper bits are set, the exponents worth of precision is lost in
#    the lower bits, rounding integers to the nearest 4k.
#
#    Instead, use the fact that Xen's .text is within a 1G aligned region, and
#    split the VMA so AWK's numeric addition is only working on <32 bit
#    numbers, which don't lose precision.  (See point 5)
#
# 4) MAWK doesn't support plain hex constants (an optional part of the POSIX
#    spec), and GAWK and MAWK can't agree on how to work with hex constants in
#    a string.  Use the shell to convert $vma_lo to decimal before passing to
#    AWK.
#
# 5) Point 4 isn't fully portable.  POSIX only requires that $((0xN)) be
#    evaluated as long, which in 32bit shells turns negative if bit 31 of the
#    VMA is set.  AWK then interprets this negative number as a double before
#    adding the offsets from the binary grep.
#
#    Instead of doing an 8/8 split with vma_hi/lo, do a 9/7 split.
#
#    The consequence of this is that for all offsets, $vma_lo + offset needs
#    to be less that 256M (i.e. 7 nibbles) so as to be successfully recombined
#    with the 9 nibbles of $vma_hi.  This is fine; .text is at the start of a
#    1G aligned region, and Xen is far far smaller than 256M, but leave safety
#    check nevertheless.
#
eval $(${OBJDUMP} -j .text $1 -h |
    $AWK '$2 == ".text" {printf "vma_hi=%s\nvma_lo=%s\n", substr($4, 1, 9), substr($4, 10, 16)}')

${OBJCOPY} -j .text $1 -O binary $TEXT_BIN

bin_sz=$(stat -c '%s' $TEXT_BIN)
[ "$bin_sz" -ge $(((1 << 28) - $vma_lo)) ] &&
    { echo "$MSG_PFX Error: .text offsets must not exceed 256M" >&2; exit 1; }

# instruction:    hex:           oct:
# endbr64         f3 0f 1e fa    363 017 036 372
# endbr32         f3 0f 1e fb    363 017 036 373
# nopw (%rcx)     66 0f 1f 01    146 017 037 001
if $perl_re
then
    LC_ALL=C grep -aobP '\xf3\x0f\x1e(\xfa|\xfb)|\x66\x0f\x1f\x01' $TEXT_BIN
else
    grep -aob -e "$(printf '\363\17\36\372')" -e "$(printf '\363\17\36\373')" \
         -e "$(printf '\146\17\37\1')" $TEXT_BIN
fi | $AWK -F':' '{printf "%s%07x\n", "'$vma_hi'", int('$((0x$vma_lo))') + $1}' > $ALL

# Wait for $VALID to become complete
wait

# Sanity check $VALID and $ALL, in case the string parsing bitrots
val_sz=$(stat -c '%s' $VALID)
all_sz=$(stat -c '%s' $ALL)
[ "$val_sz" -eq 0 ]         && { echo "$MSG_PFX Error: Empty valid-addrs" >&2; exit 1; }
[ "$all_sz" -eq 0 ]         && { echo "$MSG_PFX Error: Empty all-addrs" >&2; exit 1; }
[ "$all_sz" -lt "$val_sz" ] && { echo "$MSG_PFX Error: More valid-addrs than all-addrs" >&2; exit 1; }

# $BAD = $ALL - $VALID
sort $VALID $ALL | uniq -u > $BAD
nr_bad=$(wc -l < $BAD)

# Success
[ "$nr_bad" -eq 0 ] && exit 0

# Failure
echo "$MSG_PFX Fail: Found ${nr_bad} endb32, nop poison, or embedded endbr64 instructions" >&2
${ADDR2LINE} -afip -e $1 < $BAD >&2
exit 1
