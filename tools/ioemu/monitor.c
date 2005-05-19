/*
 * QEMU monitor
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
#include <dirent.h>

//#define DEBUG
//#define DEBUG_COMPLETION

#ifndef offsetof
#define offsetof(type, field) ((size_t) &((type *)0)->field)
#endif

/*
 * Supported types:
 * 
 * 'F'          filename
 * 'B'          block device name
 * 's'          string (accept optional quote)
 * 'i'          integer
 * '/'          optional gdb-like print format (like "/10x")
 *
 * '?'          optional type (for 'F', 's' and 'i')
 *
 */

typedef struct term_cmd_t {
    const char *name;
    const char *args_type;
    void (*handler)();
    const char *params;
    const char *help;
} term_cmd_t;

static CharDriverState *monitor_hd;

static term_cmd_t term_cmds[];
static term_cmd_t info_cmds[];

static char term_outbuf[1024];
static int term_outbuf_index;

static void monitor_start_input(void);

void term_flush(void)
{
    if (term_outbuf_index > 0) {
	if(monitor_hd)
        qemu_chr_write(monitor_hd, term_outbuf, term_outbuf_index);
	else
	    fwrite(term_outbuf, term_outbuf_index, 1, stderr);
        term_outbuf_index = 0;
    }
}

/* flush at every end of line or if the buffer is full */
void term_puts(const char *str)
{
    int c;
    for(;;) {
        c = *str++;
        if (c == '\0')
            break;
        term_outbuf[term_outbuf_index++] = c;
        if (term_outbuf_index >= sizeof(term_outbuf) ||
            c == '\n')
            term_flush();
    }
}

void term_vprintf(const char *fmt, va_list ap)
{
    char buf[4096];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    term_puts(buf);
}

void term_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    term_vprintf(fmt, ap);
    va_end(ap);
}

static int compare_cmd(const char *name, const char *list)
{
    const char *p, *pstart;
    int len;
    len = strlen(name);
    p = list;
    for(;;) {
        pstart = p;
        p = strchr(p, '|');
        if (!p)
            p = pstart + strlen(pstart);
        if ((p - pstart) == len && !memcmp(pstart, name, len))
            return 1;
        if (*p == '\0')
            break;
        p++;
    }
    return 0;
}

static void do_quit(void)
{
    extern int domid;
    extern FILE* logfile;
    char destroy_cmd[20];
    sprintf(destroy_cmd, "xm destroy %d", domid);
    if (system(destroy_cmd) == -1)
        fprintf(logfile, "%s failed.!\n", destroy_cmd);
    exit(0);
}

static term_cmd_t term_cmds[] = {
    { "q|quit", "", do_quit,
      "", "quit the emulator" },
    { NULL, NULL, }, 
};

#define MAX_ARGS 16

static void monitor_handle_command(const char *cmdline)
{
    const char *p, *pstart, *typestr;
    char *q;
    int c, nb_args, len, i;
    term_cmd_t *cmd;
    char cmdname[256];
    void *str_allocated[MAX_ARGS];
    void *args[MAX_ARGS];

#ifdef DEBUG
    term_printf("command='%s'\n", cmdline);
#endif
    
    /* extract the command name */
    p = cmdline;
    q = cmdname;
    while (isspace(*p))
        p++;
    if (*p == '\0')
        return;
    pstart = p;
    while (*p != '\0' && *p != '/' && !isspace(*p))
        p++;
    len = p - pstart;
    if (len > sizeof(cmdname) - 1)
        len = sizeof(cmdname) - 1;
    memcpy(cmdname, pstart, len);
    cmdname[len] = '\0';
    
    /* find the command */
    for(cmd = term_cmds; cmd->name != NULL; cmd++) {
        if (compare_cmd(cmdname, cmd->name)) 
            goto found;
    }
    term_printf("unknown command: '%s'\n", cmdname);
    return;
 found:

    for(i = 0; i < MAX_ARGS; i++)
        str_allocated[i] = NULL;
    
    /* parse the parameters */
    typestr = cmd->args_type;
    nb_args = 0;
    for(;;) {
        c = *typestr;
        if (c == '\0')
            break;
        typestr++;
        switch(c) {
        /* TODO: add more commands we need here to support vmx device model */
        case 'F':
        case 'B':
        case 's':
        case '/':
        case 'i':
        case '-':
        default:
            term_printf("%s: unknown type '%c', we only support quit command now.\n", cmdname, c);
            goto fail;
        }
    }
    /* check that all arguments were parsed */
    while (isspace(*p))
        p++;
    if (*p != '\0') {
        term_printf("%s: extraneous characters at the end of line\n", 
                    cmdname);
        goto fail;
    }

    switch(nb_args) {
    case 0:
        cmd->handler();
        break;
    case 1:
        cmd->handler(args[0]);
        break;
    case 2:
        cmd->handler(args[0], args[1]);
        break;
    case 3:
        cmd->handler(args[0], args[1], args[2]);
        break;
    case 4:
        cmd->handler(args[0], args[1], args[2], args[3]);
        break;
    case 5:
        cmd->handler(args[0], args[1], args[2], args[3], args[4]);
        break;
    case 6:
        cmd->handler(args[0], args[1], args[2], args[3], args[4], args[5]);
        break;
    default:
        term_printf("unsupported number of arguments: %d\n", nb_args);
        goto fail;
    }
 fail:
    for(i = 0; i < MAX_ARGS; i++)
        qemu_free(str_allocated[i]);
    return;
}

static int term_can_read(void *opaque)
{
    return 128;
}

static void term_read(void *opaque, const uint8_t *buf, int size)
{
    int i;
    for(i = 0; i < size; i++)
        readline_handle_byte(buf[i]);
}

static void monitor_start_input(void);

static void monitor_handle_command1(void *opaque, const char *cmdline)
{
    monitor_handle_command(cmdline);
    monitor_start_input();
}

static void monitor_start_input(void)
{
    readline_start("(VTXen) ", 0, monitor_handle_command1, NULL);
}

void monitor_init(CharDriverState *hd, int show_banner)
{
    monitor_hd = hd;
    if (show_banner) {
        term_printf("VMX device model. type 'q' to exit\n");
    }
    qemu_chr_add_read_handler(hd, term_can_read, term_read, NULL);
    monitor_start_input();
}
