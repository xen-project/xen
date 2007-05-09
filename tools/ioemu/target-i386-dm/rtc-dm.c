/*
 * QEMU MC146818 RTC emulation
 * 
 * Copyright (c) 2003-2004 Fabrice Bellard
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "vl.h"

// #define DEBUG_CMOS

struct RTCState {
    uint8_t cmos_data[128];
    uint8_t cmos_index;
};

static inline int to_bcd(RTCState *s, int a)
{
    return ((a / 10) << 4) | (a % 10);
}

void rtc_set_memory(RTCState *s, int addr, int val)
{
    if (addr >= 0 && addr <= 127)
        s->cmos_data[addr] = val;
}

static void cmos_ioport_write(void *opaque, uint32_t addr, uint32_t data)
{
    RTCState *s = opaque;

    if ((addr & 1) == 0) {
        s->cmos_index = data & 0x7f;
    } else {
#ifdef DEBUG_CMOS
        printf("cmos: write index=0x%02x val=0x%02x\n",
               s->cmos_index, data);
#endif        
        s->cmos_data[s->cmos_index] = data;
    }
}

static uint32_t cmos_ioport_read(void *opaque, uint32_t addr)
{
    RTCState *s = opaque;
    int ret;
    if ((addr & 1) == 0) {
        return 0xff;
    } else {
        ret = s->cmos_data[s->cmos_index];
#ifdef DEBUG_CMOS
        printf("cmos: read index=0x%02x val=0x%02x\n",
               s->cmos_index, ret);
#endif
        return ret;
    }
}

static void rtc_save(QEMUFile *f, void *opaque)
{
    RTCState *s = opaque;

    qemu_put_buffer(f, s->cmos_data, 128);
    qemu_put_8s(f, &s->cmos_index);
}

static int rtc_load(QEMUFile *f, void *opaque, int version_id)
{
    RTCState *s = opaque;

    if (version_id != 1)
        return -EINVAL;

    qemu_get_buffer(f, s->cmos_data, 128);
    qemu_get_8s(f, &s->cmos_index);

    return 0;
}

RTCState *rtc_init(int base, int irq)
{
    RTCState *s;
    time_t ti;
    struct tm *tm;
    int val;

    s = qemu_mallocz(sizeof(RTCState));
    if (!s)
        return NULL;

/* PC cmos mappings */
#define REG_IBM_CENTURY_BYTE        0x32
#define REG_IBM_PS2_CENTURY_BYTE    0x37
    time(&ti);
    tm = gmtime(&ti);		/* XXX localtime and update from guest? */
    val = to_bcd(s, (tm->tm_year / 100) + 19);
    rtc_set_memory(s, REG_IBM_CENTURY_BYTE, val);
    rtc_set_memory(s, REG_IBM_PS2_CENTURY_BYTE, val);

    register_ioport_write(base, 2, 1, cmos_ioport_write, s);
    register_ioport_read(base, 2, 1, cmos_ioport_read, s);

    register_savevm("mc146818rtc", base, 1, rtc_save, rtc_load, s);
    return s;
}

void rtc_set_date(RTCState *s, const struct tm *tm) {}
