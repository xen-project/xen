/*
 * Implementation of stub functions for calls to the TCG BIOS
 * extension in 32bit memory area.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

/*******************************************************************
  Support for TCPA ACPI logging
 ******************************************************************/

ASM_START
MACRO POST_MEASURE
	push word #0x000f
	push #?2
	push word #0x000f
	push #?1
	call _tcpa_measure_post
	add sp, #8
MEND
ASM_END

void
tcpa_do_measure_POSTs()
{
	ASM_START

	POST_MEASURE(post, nmi)
	POST_MEASURE(floppy_drive_post, hard_drive_post)
	POST_MEASURE(hard_drive_post, ebda_post)
	POST_MEASURE(ebda_post, eoi_jmp_post)
	POST_MEASURE(eoi_jmp_post, timer_tick_post)
	POST_MEASURE(timer_tick_post, int76_handler)

	ret
	ASM_END
}

/*
 * C-dispatcher for the TCG BIOS functions
 */
#define TCG_MAGIC 0x41504354L
  void
int1a_function32(regs, ES, DS, FLAGS)
  pushad_regs_t regs;
  Bit16u ES, DS, FLAGS;
{
	Bit16u rc;

	BX_DEBUG_INT1A("int1a_32: AX=%04x\n", regs.u.r16.ax);

	switch (regs.u.r8.ah) {
	case 0xbb:
		/*
		 * all functions except for TCG_StatusCheck need to have the
		 * TCG_MAGIC in 'ebx'.
		 */
		if (regs.u.r8.al != 0 &&
		    regs.u.r32.ebx != TCG_MAGIC) {
		    SET_CF();
		    return;
		}
		switch(regs.u.r8.al) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
			TCGInterruptHandler(((Bit32u)get_SS() << 4) + (Bit32u)&regs,
			                    ES, DS,
			                    ((Bit32u)get_SS() << 4) + (Bit32u)&FLAGS);
			break;

		default:
			SET_CF();
		}
		break;
	default:
		SET_CF();
		break;
	}
	BX_DEBUG_INT1A("int1a_32: FLAGS=%04x\n", FLAGS);
}
