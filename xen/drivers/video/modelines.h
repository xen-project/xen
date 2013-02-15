/*
 * xen/drivers/video/modelines.h
 *
 * Timings for many popular monitor resolutions
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 1999 by The XFree86 Project, Inc.
 * Copyright (c) 2013 Citrix Systems
 */

#ifndef _XEN_MODLINES_H
#define _XEN_MODLINES_H

struct modeline {
    const char* mode;  /* in the form 1280x1024@60 */
    uint32_t pixclock; /* Khz */
    uint32_t xres;
    uint32_t hfront;   /* horizontal front porch in pixels */
    uint32_t hsync;    /* horizontal sync pulse in pixels */
    uint32_t hback;    /* horizontal back porch in pixels */
    uint32_t yres;
    uint32_t vfront;   /* vertical front porch in lines */
    uint32_t vsync;    /* vertical sync pulse in lines */
    uint32_t vback;    /* vertical back  porch in lines */
};

struct modeline __initdata videomodes[] = {
    { "640x480@60",   25175,  640,  16,   96,   48,   480,  11,   2,    31 },
    { "640x480@72",   31500,  640,  24,   40,   128,  480,  9,    3,    28 },
    { "640x480@75",   31500,  640,  16,   96,   48,   480,  11,   2,    32 },
    { "640x480@85",   36000,  640,  32,   48,   112,  480,  1,    3,    25 },
    { "800x600@56",   38100,  800,  32,   128,  128,  600,  1,    4,    14 },
    { "800x600@60",   40000,  800,  40,   128,  88 ,  600,  1,    4,    23 },
    { "800x600@72",   50000,  800,  56,   120,  64 ,  600,  37,   6,    23 },
    { "800x600@75",   49500,  800,  16,   80,   160,  600,  1,    2,    21 },
    { "800x600@85",   56250,  800,  32,   64,   152,  600,  1,    3,    27 },
    { "1024x768@60",  65000,  1024, 24,   136,  160,  768,  3,    6,    29 },
    { "1024x768@70",  75000,  1024, 24,   136,  144,  768,  3,    6,    29 },
    { "1024x768@75",  78750,  1024, 16,   96,   176,  768,  1,    3,    28 },
    { "1024x768@85",  94500,  1024, 48,   96,   208,  768,  1,    3,    36 },
    { "1280x1024@60", 108000, 1280, 48,   112,  248,  1024, 1,    3,    38 },
    { "1280x1024@75", 135000, 1280, 16,   144,  248,  1024, 1,    3,    38 },
    { "1280x1024@85", 157500, 1280, 64,   160,  224,  1024, 1,    3,    44 },
    { "1400x1050@60", 122610, 1400, 88,   152,  240,  1050, 1,    3,    33 },
    { "1400x1050@75", 155850, 1400, 96,   152,  248,  1050, 1,    3,    42 },
    { "1600x1200@60", 162000, 1600, 64,   192,  304,  1200, 1,    3,    46 },
    { "1600x1200@65", 175500, 1600, 64,   192,  304,  1200, 1,    3,    46 },
    { "1600x1200@70", 189000, 1600, 64,   192,  304,  1200, 1,    3,    46 },
    { "1600x1200@75", 202500, 1600, 64,   192,  304,  1200, 1,    3,    46 },
    { "1600x1200@85", 229500, 1600, 64,   192,  304,  1200, 1,    3,    46 },
    { "1792x1344@60", 204800, 1792, 128,  200,  328,  1344, 1,    3,    46 },
    { "1792x1344@75", 261000, 1792, 96,   216,  352,  1344, 1,    3,    69 },
    { "1856x1392@60", 218300, 1856, 96,   224,  352,  1392, 1,    3,    43 },
    { "1856x1392@75", 288000, 1856, 128,  224,  352,  1392, 1,    3,    104 },
    { "1920x1200@75", 193160, 1920, 128,  208,  336,  1200, 1,    3,    38 },
    { "1920x1440@60", 234000, 1920, 128,  208,  344,  1440, 1,    3,    56 },
    { "1920x1440@75", 297000, 1920, 144,  224,  352,  1440, 1,    3,    56 },
};

#endif
