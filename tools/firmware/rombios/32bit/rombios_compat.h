#ifndef ROMBIOS_COMPAT
#define ROMBIOS_COMPAT

/*
 * Compatibility functions and structures for transitioning between
 * 16 bit Bochs BIOS and 32 bit BIOS code.
 */

#define ADDR_FROM_SEG_OFF(seg, off)  (void *)((((uint32_t)(seg)) << 4) + (off))

typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;

typedef uint8_t  Bit8u;
typedef uint16_t Bit16u;
typedef uint32_t Bit32u;

#define SetCF(x)   (x)->u.r8.flagsl |= 0x01
#define SetZF(x)   (x)->u.r8.flagsl |= 0x40
#define ClearCF(x) (x)->u.r8.flagsl &= 0xfe
#define ClearZF(x) (x)->u.r8.flagsl &= 0xbf
#define GetCF(x)   ((x)->u.r8.flagsl & 0x01)

#define SET_CF()     *FLAGS |= 0x0001
#define CLEAR_CF()   *FLAGS &= 0xfffe
#define GET_CF()     (*FLAGS & 0x0001)

#define SET_ZF()     *FLAGS |= 0x0040
#define CLEAR_ZF()   *FLAGS &= 0xffbf


typedef struct {
 union {
  struct {
    Bit32u edi, esi, ebp, esp;
    Bit32u ebx, edx, ecx, eax;
    } r32;
  struct {
    Bit16u di, filler1, si, filler2, bp, filler3, sp, filler4;
    Bit16u bx, filler5, dx, filler6, cx, filler7, ax, filler8;
    } r16;
  struct {
    Bit32u filler[4];
    Bit8u  bl, bh;
    Bit16u filler1;
    Bit8u  dl, dh;
    Bit16u filler2;
    Bit8u  cl, ch;
    Bit16u filler3;
    Bit8u  al, ah;
    Bit16u filler4;
    } r8;
  } u;
} __attribute__((packed)) pushad_regs_t;



static inline Bit32u read_dword(Bit16u seg, Bit16u off)
{
	uint32_t *addr = (uint32_t *)ADDR_FROM_SEG_OFF(seg,off);
	return *addr;
}

static inline Bit16u read_word(Bit16u seg, Bit16u off)
{
	uint16_t *addr = (uint16_t *)ADDR_FROM_SEG_OFF(seg,off);
	return *addr;
}

static inline Bit8u read_byte(Bit16u seg, Bit16u off)
{
	uint8_t *addr = (uint8_t *)ADDR_FROM_SEG_OFF(seg,off);
	return *addr;
}

static inline void write_dword(Bit16u seg, Bit16u off, Bit32u val)
{
	uint32_t *addr = (uint32_t *)ADDR_FROM_SEG_OFF(seg,off);
	*addr = val;
}

static inline void write_word(Bit16u seg, Bit16u off, Bit16u val)
{
	uint16_t *addr = (uint16_t *)ADDR_FROM_SEG_OFF(seg,off);
	*addr = val;
}

static inline void write_byte(Bit16u seg, Bit16u off, Bit8u val)
{
	uint8_t *addr = (uint8_t *)ADDR_FROM_SEG_OFF(seg,off);
	*addr = val;
}

#define X(idx, ret, fn, args...) ret fn (args);
#include "32bitprotos.h"
#undef X

#endif
