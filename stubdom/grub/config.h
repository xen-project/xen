#include <stdio.h>
#undef putchar
#include <ctype.h>
#include <string.h>
#include <kernel.h>
#define debug _debug
#define grub_halt(a) do_exit()
#define printf grub_printf
void kexec(void *kernel, long kernel_size, void *module, long module_size, char *cmdline, unsigned long flags);
struct fbfront_dev *fb_open(void *fb, int width, int height, int depth);
void fb_close(void);
void pv_boot (void);
