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

#ifndef __ASSEMBLY__
struct boot_video_info {
    uint8_t  orig_x;             /* 0x00 */
    uint8_t  orig_y;             /* 0x01 */
    uint8_t  orig_video_mode;    /* 0x02 */
    uint8_t  orig_video_cols;    /* 0x03 */
    uint8_t  orig_video_lines;   /* 0x04 */
    uint8_t  orig_video_isVGA;   /* 0x05 */
    uint16_t orig_video_points;  /* 0x06 */

    /* VESA graphic mode -- linear frame buffer */
    uint32_t capabilities;       /* 0x08 */
    uint16_t lfb_linelength;     /* 0x0c */
    uint16_t lfb_width;          /* 0x0e */
    uint16_t lfb_height;         /* 0x10 */
    uint16_t lfb_depth;          /* 0x12 */
    uint32_t lfb_base;           /* 0x14 */
    uint32_t lfb_size;           /* 0x18 */
    union {
        struct {
            uint8_t  red_size;   /* 0x1c */
            uint8_t  red_pos;    /* 0x1d */
            uint8_t  green_size; /* 0x1e */
            uint8_t  green_pos;  /* 0x1f */
            uint8_t  blue_size;  /* 0x20 */
            uint8_t  blue_pos;   /* 0x21 */
            uint8_t  rsvd_size;  /* 0x22 */
            uint8_t  rsvd_pos;   /* 0x23 */
        };
        struct boot_video_colors {
            uint8_t  rgbr[8];
        } colors;
    };
    struct {
        uint16_t seg;            /* 0x24 */
        uint16_t off;            /* 0x26 */
    } vesapm;
    uint16_t vesa_attrib;        /* 0x28 */
};

extern struct boot_video_info boot_vid_info;
#endif /* __ASSEMBLY__ */

#endif /* __BOOT_VIDEO_H__ */
