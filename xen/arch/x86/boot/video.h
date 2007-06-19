#ifndef __BOOT_VIDEO_H__
#define __BOOT_VIDEO_H__

/*
 * Video modes numbered by menu position -- NOT RECOMMENDED because of lack
 * of compatibility when extending the table. These are between 0x00 and 0xff.
 */
#define VIDEO_FIRST_MENU    0x0000

/* VESA BIOS video modes (VESA number + 0x0200) */
#define VIDEO_FIRST_VESA    0x0200

/* Special video modes */
#define VIDEO_FIRST_SPECIAL 0x0f00
#define VIDEO_80x25         0x0f00
#define VIDEO_80x50         0x0f01
#define VIDEO_80x43         0x0f02
#define VIDEO_80x28         0x0f03
#define VIDEO_CURRENT_MODE  0x0f04
#define VIDEO_80x30         0x0f05
#define VIDEO_80x34         0x0f06
#define VIDEO_80x60         0x0f07
#define VIDEO_LAST_SPECIAL  0x0f08

#define ASK_VGA             0xfffd
#define VIDEO_VESA_BY_SIZE  0xffff

/* The "recalculate timings" flag */
#define VIDEO_RECALC        0x8000

#endif /* __BOOT_VIDEO_H__ */
