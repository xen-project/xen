#!/bin/sh
#
# Usage ./$0 xen-syms
#
set -e

# Pretty-print parameters a little for message
MSG_PFX="${0##*/} ${1##*/}"

OBJCOPY="${OBJCOPY:-objcopy}"
OBJDUMP="${OBJDUMP:-objdump}"
ADDR2LINE="${ADDR2LINE:-addr2line}"

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
# Second, look for any endbr64 byte sequence
# This has a couple of complications:
#
# 1) Grep binary search isn't VMA aware.  Copy .text out as binary, causing
#    the grep offset to be from the start of .text.
#
# 2) dash's printf doesn't understand hex escapes, hence the use of octal.
#
# 3) AWK can't add 64bit integers, because internally all numbers are doubles.
#    When the upper bits are set, the exponents worth of precision is lost in
#    the lower bits, rounding integers to the nearest 4k.
#
#    Instead, use the fact that Xen's .text is within a 1G aligned region, and
#    split the VMA in half so AWK's numeric addition is only working on 32 bit
#    numbers, which don't lose precision.
#
eval $(${OBJDUMP} -j .text $1 -h |
    awk '$2 == ".text" {printf "vma_hi=%s\nvma_lo=%s\n", substr($4, 1, 8), substr($4, 9, 16)}')

${OBJCOPY} -j .text $1 -O binary $TEXT_BIN
grep -aob "$(printf '\363\17\36\372')" $TEXT_BIN |
    awk -F':' '{printf "%s%x\n", "'$vma_hi'", int(0x'$vma_lo') + $1}' > $ALL

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
echo "$MSG_PFX Fail: Found ${nr_bad} embedded endbr64 instructions" >&2
${ADDR2LINE} -afip -e $1 < $BAD >&2
exit 1
