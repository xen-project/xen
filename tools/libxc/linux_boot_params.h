#ifndef __LINUX_BOOT_PARAMS_H__
#define __LINUX_BOOT_PARAMS_H__

#include <asm/types.h>

#define E820MAX	32

struct mem_map {
    int nr_map;
    struct entry {
        unsigned long long addr;	/* start of memory segment */
        unsigned long long size;	/* size of memory segment */
        unsigned long type;		/* type of memory segment */
#define E820_RAM        1
#define E820_RESERVED   2
#define E820_ACPI       3 /* usable as RAM once ACPI tables have been read */
#define E820_NVS        4

        unsigned long caching_attr;    /* used by hypervisor */
#define MEMMAP_UC	0
#define MEMMAP_WC	1
#define MEMMAP_WT	4
#define MEMMAP_WP	5
#define MEMMAP_WB	6

    }map[E820MAX];
};

struct e820entry {
	unsigned long long addr;	/* start of memory segment */
	unsigned long long size;	/* size of memory segment */
	unsigned long type;		/* type of memory segment */
};

struct e820map {
    int nr_map;
    struct e820entry map[E820MAX];
};

struct drive_info_struct { __u8 dummy[32]; }; 

struct sys_desc_table { 
    __u16 length; 
    __u8 table[318]; 
}; 

struct screen_info {
    unsigned char  orig_x;		/* 0x00 */
    unsigned char  orig_y;		/* 0x01 */
    unsigned short dontuse1;		/* 0x02 -- EXT_MEM_K sits here */
    unsigned short orig_video_page;	/* 0x04 */
    unsigned char  orig_video_mode;	/* 0x06 */
    unsigned char  orig_video_cols;	/* 0x07 */
    unsigned short unused2;		/* 0x08 */
    unsigned short orig_video_ega_bx;	/* 0x0a */
    unsigned short unused3;		/* 0x0c */
    unsigned char  orig_video_lines;	/* 0x0e */
    unsigned char  orig_video_isVGA;	/* 0x0f */
    unsigned short orig_video_points;	/* 0x10 */
    
    /* VESA graphic mode -- linear frame buffer */
    unsigned short lfb_width;		/* 0x12 */
    unsigned short lfb_height;		/* 0x14 */
    unsigned short lfb_depth;		/* 0x16 */
    unsigned long  lfb_base;		/* 0x18 */
    unsigned long  lfb_size;		/* 0x1c */
    unsigned short dontuse2, dontuse3;	/* 0x20 -- CL_MAGIC and CL_OFFSET here */
    unsigned short lfb_linelength;	/* 0x24 */
    unsigned char  red_size;		/* 0x26 */
    unsigned char  red_pos;		/* 0x27 */
    unsigned char  green_size;		/* 0x28 */
    unsigned char  green_pos;		/* 0x29 */
    unsigned char  blue_size;		/* 0x2a */
    unsigned char  blue_pos;		/* 0x2b */
    unsigned char  rsvd_size;		/* 0x2c */
    unsigned char  rsvd_pos;		/* 0x2d */
    unsigned short vesapm_seg;		/* 0x2e */
    unsigned short vesapm_off;		/* 0x30 */
    unsigned short pages;		/* 0x32 */
					/* 0x34 -- 0x3f reserved for future expansion */
};

struct screen_info_overlap { 
    __u8 reserved1[2]; /* 0x00 */ 
    __u16 ext_mem_k; /* 0x02 */ 
    __u8 reserved2[0x20 - 0x04]; /* 0x04 */ 
    __u16 cl_magic; /* 0x20 */ 
#define CL_MAGIC_VALUE 0xA33F 
    __u16 cl_offset; /* 0x22 */ 
    __u8 reserved3[0x40 - 0x24]; /* 0x24 */ 
}; 


struct apm_bios_info {
    __u16 version;
    __u16  cseg;
    __u32   offset;
    __u16  cseg_16;
    __u16  dseg;
    __u16  flags;
    __u16  cseg_len;
    __u16  cseg_16_len;
    __u16  dseg_len;
};
 
struct linux_boot_params { 
    union { /* 0x00 */ 
       struct screen_info info; 
       struct screen_info_overlap overlap; 
    } screen; 
 
    struct apm_bios_info apm_bios_info; /* 0x40 */ 
    __u8 reserved4[0x80 - 0x54]; /* 0x54 */ 
    struct drive_info_struct drive_info; /* 0x80 */ 
    struct sys_desc_table sys_desc_table; /* 0xa0 */ 
    __u32 alt_mem_k; /* 0x1e0 */ 
    __u8 reserved5[4]; /* 0x1e4 */ 
    __u8 e820_map_nr; /* 0x1e8 */ 
    __u8 reserved6[8]; /* 0x1e9 */ 
    __u8 setup_sects; /* 0x1f1 */ 
    __u16 mount_root_rdonly; /* 0x1f2 */ 
    __u16 syssize; /* 0x1f4 */ 
    __u16 swapdev; /* 0x1f6 */ 
    __u16 ramdisk_flags; /* 0x1f8 */ 
#define RAMDISK_IMAGE_START_MASK 0x07FF 
#define RAMDISK_PROMPT_FLAG 0x8000 
#define RAMDISK_LOAD_FLAG 0x4000 
    __u16 vid_mode; /* 0x1fa */ 
    __u16 root_dev; /* 0x1fc */ 
    __u8 reserved9[1]; /* 0x1fe */ 
    __u8 aux_device_info; /* 0x1ff */ 
    /* 2.00+ */ 
    __u8 reserved10[2]; /* 0x200 */ 
    __u8 header_magic[4]; /* 0x202 */ 
    __u16 protocol_version; /* 0x206 */ 
    __u8 reserved11[8]; /* 0x208 */ 
    __u8 loader_type; /* 0x210 */ 
#define LOADER_TYPE_LOADLIN 1 
#define LOADER_TYPE_BOOTSECT_LOADER 2 
#define LOADER_TYPE_SYSLINUX 3 
#define LOADER_TYPE_ETHERBOOT 4 
#define LOADER_TYPE_UNKNOWN 0xFF 
    __u8 loader_flags; /* 0x211 */ 
    __u8 reserved12[2]; /* 0x212 */ 
    __u32 code32_start; /* 0x214 */ 
    __u32 initrd_start; /* 0x218 */ 
    __u32 initrd_size; /* 0x21c */ 
    __u8 reserved13[4]; /* 0x220 */ 
    /* 2.01+ */ 
    __u16 heap_end_ptr; /* 0x224 */ 
    __u8 reserved14[2]; /* 0x226 */ 
    /* 2.02+ */ 
    __u32 cmd_line_ptr; /* 0x228 */ 
    /* 2.03+ */ 
    __u32 ramdisk_max; /* 0x22c */ 
    __u8 reserved15[0x2d0 - 0x230]; /* 0x230 */ 
    struct e820entry e820_map[E820MAX]; /* 0x2d0 */ 
    __u64 shared_info; /* 0x550 */
    __u8 padding[0x800 - 0x558]; /* 0x558 */ 
    __u8 cmd_line[0x800]; /* 0x800 */
} __attribute__((packed)); 

#endif /* __LINUX_BOOT_PARAMS_H__ */
