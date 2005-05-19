/*
 *  qemu user main
 * 
 *  Copyright (c) 2003 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "qemu.h"

#define DEBUG_LOGFILE "/tmp/qemu.log"

#ifdef __APPLE__
#include <crt_externs.h>
# define environ  (*_NSGetEnviron())
#endif

static const char *interp_prefix = CONFIG_QEMU_PREFIX;

#if defined(__i386__) && !defined(CONFIG_STATIC)
/* Force usage of an ELF interpreter even if it is an ELF shared
   object ! */
const char interp[] __attribute__((section(".interp"))) = "/lib/ld-linux.so.2";
#endif

/* for recent libc, we add these dummy symbols which are not declared
   when generating a linked object (bug in ld ?) */
#if (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 3)) && !defined(CONFIG_STATIC)
long __preinit_array_start[0];
long __preinit_array_end[0];
long __init_array_start[0];
long __init_array_end[0];
long __fini_array_start[0];
long __fini_array_end[0];
#endif

/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long x86_stack_size = 512 * 1024;

void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
/* timers for rdtsc */

#if defined(__i386__)

int64_t cpu_get_real_ticks(void)
{
    int64_t val;
    asm volatile ("rdtsc" : "=A" (val));
    return val;
}

#elif defined(__x86_64__)

int64_t cpu_get_real_ticks(void)
{
    uint32_t low,high;
    int64_t val;
    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
}

#else

static uint64_t emu_time;

int64_t cpu_get_real_ticks(void)
{
    return emu_time++;
}

#endif

#ifdef TARGET_I386
/***********************************************************/
/* CPUX86 core interface */

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_real_ticks();
}

void cpu_loop()
{
}
#endif

void usage(void)
{
    printf("qemu-" TARGET_ARCH " version " QEMU_VERSION ", Copyright (c) 2003-2004 Fabrice Bellard\n"
           "usage: qemu-" TARGET_ARCH " [-h] [-d opts] [-L path] [-s size] program [arguments...]\n"
           "Linux CPU emulator (compiled for %s emulation)\n"
           "\n"
           "-h           print this help\n"
           "-L path      set the elf interpreter prefix (default=%s)\n"
           "-s size      set the stack size in bytes (default=%ld)\n"
           "\n"
           "debug options:\n"
#ifdef USE_CODE_COPY
           "-no-code-copy   disable code copy acceleration\n"
#endif
           "-l options   activate log (logfile=%s)\n"
           "-p xen port number\n",
           "-d xen domain id\n",
           TARGET_ARCH,
           interp_prefix, 
           x86_stack_size,
           DEBUG_LOGFILE);
    _exit(1);
}

/* XXX: currently only used for async signals (see signal.c) */
CPUState *global_env;
/* used only if single thread */
CPUState *cpu_single_env = NULL;

/* used to free thread contexts */
TaskState *first_task_state;

int main(int argc, char **argv)
{
    const char *filename;
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    TaskState ts1, *ts = &ts1;
    CPUState *env;
    int optind;
    const char *r;
    
    if (argc <= 1)
        usage();

    /* init debug */
    cpu_set_log_filename(DEBUG_LOGFILE);
    cpu_set_log(0);

    optind = 1;
    for(;;) {
        if (optind >= argc)
            break;
        r = argv[optind];
        if (r[0] != '-')
            break;
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        } else if (!strcmp(r, "l")) {
            int mask;
            CPULogItem *item;

	    if (optind >= argc)
		break;
            
	    r = argv[optind++];
            mask = cpu_str_to_log_mask(r);
            if (!mask) {
                printf("Log items (comma separated):\n");
                for(item = cpu_log_items; item->mask != 0; item++) {
                    printf("%-10s %s\n", item->name, item->help);
                }
                exit(1);
            }
            cpu_set_log(mask);
        } else if (!strcmp(r, "s")) {
            r = argv[optind++];
            x86_stack_size = strtol(r, (char **)&r, 0);
            if (x86_stack_size <= 0)
                usage();
            if (*r == 'M')
                x86_stack_size *= 1024 * 1024;
            else if (*r == 'k' || *r == 'K')
                x86_stack_size *= 1024;
        } else if (!strcmp(r, "L")) {
            interp_prefix = argv[optind++];
        } else if (!strcmp(r, "p")) {
            qemu_host_page_size = atoi(argv[optind++]);
            if (qemu_host_page_size == 0 ||
                (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
                fprintf(stderr, "page size must be a power of two\n");
                exit(1);
            }
        } else 
#ifdef USE_CODE_COPY
        if (!strcmp(r, "no-code-copy")) {
            code_copy_enabled = 0;
        } else 
#endif
        {
            usage();
        }
    }
    if (optind >= argc)
        usage();
    filename = argv[optind];

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    /* NOTE: we need to init the CPU at this stage to get
       qemu_host_page_size */
    env = cpu_init();

    global_env = env;

    /* build Task State */
    memset(ts, 0, sizeof(TaskState));
    env->opaque = ts;
    ts->used = 1;
    env->user_mode_only = 1;

    cpu_loop(env);
    /* never exits */
    return 0;
}
