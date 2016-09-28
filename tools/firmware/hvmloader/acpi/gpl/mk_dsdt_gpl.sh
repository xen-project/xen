#!/bin/sh

# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; If not, see <http://www.gnu.org/licenses/>.
#

cat <<'EndOfASL'
    /* Beginning of GPL-only code */

    /* _S3 and _S4 are in separate SSDTs */
    Name (\_S5, Package (0x04) {
        0x00,  /* PM1a_CNT.SLP_TYP */
        0x00,  /* PM1b_CNT.SLP_TYP */
        0x00,  /* reserved */
        0x00   /* reserved */
    })
    Name(PICD, 0)
    Method(_PIC, 1) {
        Store(Arg0, PICD)
    }
EndOfASL

# PCI-ISA link definitions
# BUFA: List of ISA IRQs available for linking to PCI INTx.
# BUFB: IRQ descriptor for returning from link-device _CRS methods.
cat <<'EndOfASL'
    Scope ( \_SB.PCI0 )  {
        Name ( BUFA, ResourceTemplate() { IRQ(Level, ActiveLow, Shared) { 5, 10, 11 } } )
        Name ( BUFB, Buffer() { 0x23, 0x00, 0x00, 0x18, 0x79, 0 } )
        CreateWordField ( BUFB, 0x01, IRQV )
EndOfASL

for i in $(seq 1 4)
do
    link=`echo "A B C D" | cut -d" " -f $i`
    cat <<EndOfASL
        Device ( LNK$link ) {
            Name ( _HID,  EISAID("PNP0C0F") )
            Name ( _UID, $i)
            Method ( _STA, 0) {
                If ( And(PIR$link, 0x80) ) {
                    Return ( 0x09 )
                } Else {
                    Return ( 0x0B )
                }
            }
            Method ( _PRS ) {
                Return ( BUFA )
            }
            Method ( _DIS ) {
                Or ( PIR$link, 0x80, PIR$link )
            }
            Method ( _CRS ) {
                And ( PIR$link, 0x0f, Local0 )
                ShiftLeft ( 0x1, Local0, IRQV )
                Return ( BUFB )
            }
            Method ( _SRS, 1 ) {
                CreateWordField ( ARG0, 0x01, IRQ1 )
                FindSetRightBit ( IRQ1, Local0 )
                Decrement ( Local0 )
                Store ( Local0, PIR$link )
            }
        }
EndOfASL
done

# PCI interrupt routing definitions
# _PRT: Method to return routing table.
cat <<'EndOfASL'
        Method ( _PRT, 0 ) {
            If ( PICD ) {
                Return ( PRTA )
            }
            Return ( PRTP )
        }
EndOfASL

# PRTP: PIC routing table (via ISA links).
echo "        Name(PRTP, Package() {"
for dev in $(seq 1 31)
do
    for intx in $(seq 0 3)  # INTA-D
    do
	link_idx=$(( ((dev + intx) & 3) + 1 ))
	link=`echo "A B C D" | cut -d" " -f $link_idx`
	printf "            Package(){0x%04xffff, %u, \\\\_SB.PCI0.LNK%c, 0},\n" \
	    $dev $intx $link
    done
done
echo "        })"

# PRTA: APIC routing table (via non-legacy IOAPIC GSIs).
echo "        Name(PRTA, Package() {"
for dev in $(seq 1 31)
do
    for intx in $(seq 0 3)  # INTA-D
    do
	idx=$(( ((dev * 4 + dev/8 + intx) & 31) + 16 ))
	printf "            Package(){0x%04xffff, %u, 0, %u},\n" \
	    $dev $intx $idx
    done
done
echo "        })"

echo "    }"

echo "    /* End of GPL-only code */"
