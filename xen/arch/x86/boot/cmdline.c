/*
 * Copyright (c) 2015, 2016 Oracle and/or its affiliates. All rights reserved.
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
 *
 * strlen(), strncmp(), strchr(), strspn() and strcspn() were copied from
 * Linux kernel source (linux/lib/string.c).
 */

/*
 * This entry point is entered from xen/arch/x86/boot/head.S with:
 *   - 0x4(%esp) = &cmdline,
 *   - 0x8(%esp) = &early_boot_opts.
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  cmdline_parse_early      \n"
    );

#include <xen/kconfig.h>
#include "defs.h"
#include "video.h"

/* Keep in sync with trampoline.S:early_boot_opts label! */
typedef struct __packed {
    u8 skip_realmode;
    u8 opt_edd;
    u8 opt_edid;
    u8 padding;
    u16 boot_vid_mode;
    u16 vesa_width;
    u16 vesa_height;
    u16 vesa_depth;
} early_boot_opts_t;

/*
 * Space and TAB are obvious delimiters. However, I am
 * adding "\n" and "\r" here too. Just in case when
 * crazy bootloader/user puts them somewhere.
 */
static const char delim_chars_comma[] = ", \n\r\t";

#define delim_chars	(delim_chars_comma + 1)

static size_t strlen(const char *s)
{
    const char *sc;

    for ( sc = s; *sc != '\0'; ++sc )
        /* nothing */;
    return sc - s;
}

static int strncmp(const char *cs, const char *ct, size_t count)
{
    unsigned char c1, c2;

    while ( count )
    {
        c1 = *cs++;
        c2 = *ct++;
        if ( c1 != c2 )
            return c1 < c2 ? -1 : 1;
        if ( !c1 )
            break;
        count--;
    }
    return 0;
}

static char *strchr(const char *s, int c)
{
    for ( ; *s != (char)c; ++s )
        if ( *s == '\0' )
            return NULL;
    return (char *)s;
}

static size_t strspn(const char *s, const char *accept)
{
    const char *p;
    const char *a;
    size_t count = 0;

    for ( p = s; *p != '\0'; ++p )
    {
        for ( a = accept; *a != '\0'; ++a )
        {
            if ( *p == *a )
                break;
        }
        if ( *a == '\0' )
            return count;
        ++count;
    }
    return count;
}

static size_t strcspn(const char *s, const char *reject)
{
    const char *p;
    const char *r;
    size_t count = 0;

    for ( p = s; *p != '\0'; ++p )
    {
        for ( r = reject; *r != '\0'; ++r )
        {
            if ( *p == *r )
                return count;
        }
        ++count;
    }
    return count;
}

static unsigned int strtoui(const char *s, const char *stop, const char **next)
{
    char base = 10, l;
    unsigned long long res = 0;

    if ( *s == '0' )
      base = (tolower(*++s) == 'x') ? (++s, 16) : 8;

    for ( ; *s != '\0'; ++s )
    {
        if ( stop && strchr(stop, *s) )
            goto out;

        if ( *s < '0' || (*s > '7' && base == 8) )
        {
            res = UINT_MAX;
            goto out;
        }

        l = tolower(*s);

        if ( *s > '9' && (base != 16 || l < 'a' || l > 'f') )
        {
            res = UINT_MAX;
            goto out;
        }

        res *= base;
        res += (l >= 'a') ? (l - 'a' + 10) : (*s - '0');

        if ( res >= UINT_MAX )
        {
            res = UINT_MAX;
            goto out;
        }
    }

 out:
    if ( next )
      *next = s;

    return res;
}

static int strmaxcmp(const char *cs, const char *ct, const char *_delim_chars)
{
    return strncmp(cs, ct, max(strcspn(cs, _delim_chars), strlen(ct)));
}

static int strsubcmp(const char *cs, const char *ct)
{
    return strncmp(cs, ct, strlen(ct));
}

static const char *find_opt(const char *cmdline, const char *opt, bool arg)
{
    size_t lc, lo;

    lo = strlen(opt);

    for ( ; ; )
    {
        cmdline += strspn(cmdline, delim_chars);

        if ( *cmdline == '\0' )
            return NULL;

        if ( !strmaxcmp(cmdline, "--", delim_chars) )
            return NULL;

        lc = strcspn(cmdline, delim_chars);

        if ( !strncmp(cmdline, opt, arg ? lo : max(lc, lo)) )
            return cmdline + lo;

        cmdline += lc;
    }
}

static bool skip_realmode(const char *cmdline)
{
    return find_opt(cmdline, "no-real-mode", false) || find_opt(cmdline, "tboot=", true);
}

static u8 edd_parse(const char *cmdline)
{
    const char *c;

    c = find_opt(cmdline, "edd=", true);

    if ( !c )
        return 0;

    if ( !strmaxcmp(c, "off", delim_chars) )
        return 2;

    return !strmaxcmp(c, "skipmbr", delim_chars);
}

static u8 edid_parse(const char *cmdline)
{
    const char *c;

    c = find_opt(cmdline, "edid=", true);

    if ( !c )
        return 0;

    if ( !strmaxcmp(c, "force", delim_chars) )
        return 2;

    return !strmaxcmp(c, "no", delim_chars);
}

static u16 rows2vmode(unsigned int rows)
{
    switch ( rows )
    {
    case 25:
        return VIDEO_80x25;

    case 28:
        return VIDEO_80x28;

    case 30:
        return VIDEO_80x30;

    case 34:
        return VIDEO_80x34;

    case 43:
        return VIDEO_80x43;

    case 50:
        return VIDEO_80x50;

    case 60:
        return VIDEO_80x60;

    default:
        return ASK_VGA;
    }
}

static void vga_parse(const char *cmdline, early_boot_opts_t *ebo)
{
    const char *c;
    unsigned int tmp, vesa_depth, vesa_height, vesa_width;

    c = find_opt(cmdline, "vga=", true);

    if ( !c )
        return;

    ebo->boot_vid_mode = ASK_VGA;

    if ( !strmaxcmp(c, "current", delim_chars_comma) )
        ebo->boot_vid_mode = VIDEO_CURRENT_MODE;
    else if ( !strsubcmp(c, "text-80x") )
    {
        c += strlen("text-80x");
        ebo->boot_vid_mode = rows2vmode(strtoui(c, delim_chars_comma, NULL));
    }
    else if ( !strsubcmp(c, "gfx-") )
    {
        vesa_width = strtoui(c + strlen("gfx-"), "x", &c);

        if ( vesa_width > U16_MAX )
            return;

        /*
         * Increment c outside of strtoui() because otherwise some
         * compiler may complain with following message:
         * warning: operation on 'c' may be undefined.
         */
        ++c;
        vesa_height = strtoui(c, "x", &c);

        if ( vesa_height > U16_MAX )
            return;

        vesa_depth = strtoui(++c, delim_chars_comma, NULL);

        if ( vesa_depth > U16_MAX )
            return;

        ebo->vesa_width = vesa_width;
        ebo->vesa_height = vesa_height;
        ebo->vesa_depth = vesa_depth;
        ebo->boot_vid_mode = VIDEO_VESA_BY_SIZE;
    }
    else if ( !strsubcmp(c, "mode-") )
    {
        tmp = strtoui(c + strlen("mode-"), delim_chars_comma, NULL);

        if ( tmp > U16_MAX )
            return;

        ebo->boot_vid_mode = tmp;
    }
}

void __stdcall cmdline_parse_early(const char *cmdline, early_boot_opts_t *ebo)
{
    if ( !cmdline )
        return;

    ebo->skip_realmode = skip_realmode(cmdline);
    ebo->opt_edd = edd_parse(cmdline);
    ebo->opt_edid = edid_parse(cmdline);

    if ( IS_ENABLED(CONFIG_VIDEO) )
        vga_parse(cmdline, ebo);
}
