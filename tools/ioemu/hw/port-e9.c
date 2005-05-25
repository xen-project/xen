/*
 * QEMU Port 0xe9 hack
 *
 * Copyright (c) 2000-2004 E. Marty, the bochs team, D. Decotigny
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#include "vl.h"
#include "exec-all.h"

static void bochs_e9_write(void *opaque, uint32_t address, uint32_t data)
{
    fputc(data, logfile); 
}

static uint32_t bochs_e9_read(void *opaque, uint32_t address)
{
    return 0xE9;
}

void port_e9_init ()
{
    register_ioport_write(0xe9, 1, 1, bochs_e9_write, NULL);
    register_ioport_read (0xe9, 1, 1, bochs_e9_read,  NULL);
}


