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
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

/*******************************************************************
  Support for TCPA ACPI logging
 ******************************************************************/

/*
 * Extend the ACPI log with the given entry by copying the
 * entry data into the log.
 * Input
 *  Pointer to the structure to be copied into the log
 *
 * Output:
 *  lower 16 bits of return code contain entry number
 *  if entry number is '0', then upper 16 bits contain error code.
 */
Bit32u tcpa_extend_acpi_log(entry_ptr)
    Bit32u entry_ptr;
{
	ASM_START
	DoUpcall(IDX_TCPA_EXTEND_ACPI_LOG)
	ASM_END
}


/*
   initialize the TCPA ACPI subsystem; find the ACPI tables and determine
   where the TCPA table is.
 */
 void
tcpa_acpi_init()
{
	ASM_START
	DoUpcall(IDX_TCPA_ACPI_INIT)
	ASM_END
}


/*
 * Add measurement to log about call of int 19h
 */
 void
tcpa_calling_int19h()
{
	ASM_START
	DoUpcall(IDX_TCPA_CALLING_INT19H)
	ASM_END
}

/*
 * Add measurement to log about retuning from int 19h
 */
 void
tcpa_returned_int19h()
{
	ASM_START
	DoUpcall(IDX_TCPA_RETURNED_INT19H)
	ASM_END
}

/*
 * Add event separators for PCRs 0 to 7; specs 8.2.3
 */
 void
tcpa_add_event_separators()
{
	ASM_START
	DoUpcall(IDX_TCPA_ADD_EVENT_SEPARATORS)
	ASM_END
}


/*
 * Add a wake event to the log
 */
 void
tcpa_wake_event()
{
	ASM_START
	DoUpcall(IDX_TCPA_WAKE_EVENT)
	ASM_END
}


/*
 * Add measurement to the log about option rom scan
 * 10.4.3 : action 14
 */
 void
tcpa_start_option_rom_scan()
{
	ASM_START
	DoUpcall(IDX_TCPA_START_OPTION_ROM_SCAN)
	ASM_END
}


/*
 * Add measurement to the log about an option rom
 */
 void
tcpa_option_rom(seg)
    Bit32u seg;
{
	ASM_START
	DoUpcall(IDX_TCPA_OPTION_ROM)
	ASM_END
}

/*
 * Add a measurement regarding the boot device (CDRom, Floppy, HDD) to
 * the list of measurements.
 */
void
 tcpa_add_bootdevice(bootcd, bootdrv)
  Bit32u bootcd;
  Bit32u bootdrv;
{
	ASM_START
	DoUpcall(IDX_TCPA_ADD_BOOTDEVICE)
	ASM_END
}

/*
 * Add a measurement to the log in support of 8.2.5.3
 * Creates two log entries
 *
 * Input parameter:
 *  seg    : segment where the IPL data are located
 */
 void
tcpa_ipl(seg)
    Bit32u seg;
{
	ASM_START
	DoUpcall(IDX_TCPA_IPL)
	ASM_END
}


Bit32u
tcpa_initialize_tpm(physpres)
  Bit32u physpres;
{
	ASM_START
	DoUpcall(IDX_TCPA_INITIALIZE_TPM)
	ASM_END
}

void
tcpa_measure_post(from, to)
   Bit32u from;
   Bit32u to;
{
	ASM_START
	DoUpcall(IDX_TCPA_MEASURE_POST)
	ASM_END
}

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

Bit32u
TCGInterruptHandler(regs_ptr, es, ds, flags_ptr)
   Bit32u regs_ptr;
   Bit16u es;
   Bit16u ds;
   Bit32u flags_ptr;
{
	ASM_START
	DoUpcall(IDX_TCGINTERRUPTHANDLER)
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
	default:
		SET_CF();
		break;
	}
}
