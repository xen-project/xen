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

  /* Dynamic linkage sections.  Collected simply so we can check they're empty. */
  .got : {
        *(.got)
  }
  .got.plt : {
        *(.got.plt)
  }
  .igot.plt : {
        *(.igot.plt)
  }
  .iplt : {
        *(.iplt)
  }
  .plt : {
        *(.plt)
  }
  .rel : {
        *(.rel.*)
  }
}

ASSERT(SIZEOF(.got) == 0,         ".got non-empty")
/*
 * At least GNU ld 2.30 and earlier fail to discard the generic part of
 * .got.plt when no actual entries were allocated. Permit this case alongside
 * the section being empty.
 */
ASSERT(SIZEOF(.got.plt) == 0 ||
       SIZEOF(.got.plt) == 3 * 4, "unexpected .got.plt size")
ASSERT(SIZEOF(.igot.plt) == 0,    ".igot.plt non-empty")
ASSERT(SIZEOF(.iplt) == 0,        ".iplt non-empty")
ASSERT(SIZEOF(.plt) == 0,         ".plt non-empty")
ASSERT(SIZEOF(.rel) == 0,         "leftover relocations")
