/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

ENTRY(_start)

SECTIONS
{
  /* Merge code and data into one section. */
  .text : {
        *(.text)
        *(.text.*)
        *(.data)
        *(.data.*)
        *(.rodata)
        *(.rodata.*)
        *(.bss)
        *(.bss.*)
  }

  /DISCARD/ : {
        /*
         * PIC/PIE executable contains .got.plt section even if it is not linked
         * with dynamic libraries. In such case it is just placeholder for
         * _GLOBAL_OFFSET_TABLE_ symbol and .PLT0. .PLT0 is filled by dynamic
         * linker and our code is not supposed to be loaded by dynamic linker.
         * So, from our point of view .PLT0 is unused. This means that there is
         * pretty good chance that we can safely drop .got.plt as a whole here.
         * Sadly this is not true. _GLOBAL_OFFSET_TABLE_ is used as a reference
         * for relative addressing (and only for that thing) and ld complains if
         * we remove .got.plt section here because it cannot find required symbol.
         * However, _GLOBAL_OFFSET_TABLE_ is no longer needed in final output.
         * So, drop .got.plt section during conversion to plain binary format.
         *
         * Please check build32.mk for more details.
         */
        /* *(.got.plt) */
  }
}
