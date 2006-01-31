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

static void help_cmd1(term_cmd_t *cmds, const char *prefix, const char *name)
{
    term_cmd_t *cmd;

    for(cmd = cmds; cmd->name != NULL; cmd++) {
        if (!name || !strcmp(name, cmd->name))
            term_printf("%s%s %s -- %s\n", prefix, cmd->name, cmd->params, cmd->help);
    }
}

static void help_cmd(const char *name)
{
    if (name && !strcmp(name, "info")) {
        help_cmd1(info_cmds, "info ", NULL);
    } else {
        help_cmd1(term_cmds, "", name);
        if (name && !strcmp(name, "log")) {
            CPULogItem *item;
            term_printf("Log items (comma separated):\n");
            term_printf("%-10s %s\n", "none", "remove all logs");
            for(item = cpu_log_items; item->mask != 0; item++) {
                term_printf("%-10s %s\n", item->name, item->help);
            }
        }
    }
}

static void do_help(const char *name)
{
    help_cmd(name);
}

static void do_commit(void)
{
    int i;

    for (i = 0; i < MAX_DISKS; i++) {
        if (bs_table[i]) {
            bdrv_commit(bs_table[i]);
        }
    }
}

static void do_info(const char *item)
{
    term_cmd_t *cmd;

    if (!item)
        goto help;
    for(cmd = info_cmds; cmd->name != NULL; cmd++) {
        if (compare_cmd(item, cmd->name))
            goto found;
    }
 help:
    help_cmd("info");
    return;
 found:
    cmd->handler();
}

static void do_info_version(void)
{
  term_printf("%s\n", QEMU_VERSION);
}

static void do_info_network(void)
{
    int i, j;
    NetDriverState *nd;

    for(i = 0; i < nb_nics; i++) {
        nd = &nd_table[i];
        term_printf("%d: ifname=%s macaddr=", i, nd->ifname);
        for(j = 0; j < 6; j++) {
            if (j > 0)
                term_printf(":");
            term_printf("%02x", nd->macaddr[j]);
        }
        term_printf("\n");
    }
}

static void do_info_block(void)
{
    bdrv_info();
}

static void do_info_history (void)
{
    int i;
    const char *str;

    i = 0;
    for(;;) {
        str = readline_get_history(i);
        if (!str)
            break;
        term_printf("%d: '%s'\n", i, str);
        i++;
    }
}

extern void destroy_hvm_domain(void);
static void do_quit(void)
{
    destroy_hvm_domain();
    exit(0);
}

typedef struct {
    int keycode;
    const char *name;
} KeyDef;

static const KeyDef key_defs[] = {
    { 0x2a, "shift" },
    { 0x36, "shift_r" },
    
    { 0x38, "alt" },
    { 0xb8, "alt_r" },
    { 0x1d, "ctrl" },
    { 0x9d, "ctrl_r" },

    { 0xdd, "menu" },

    { 0x01, "esc" },

    { 0x02, "1" },
    { 0x03, "2" },
    { 0x04, "3" },
    { 0x05, "4" },
    { 0x06, "5" },
    { 0x07, "6" },
    { 0x08, "7" },
    { 0x09, "8" },
    { 0x0a, "9" },
    { 0x0b, "0" },
    { 0x0e, "backspace" },

    { 0x0f, "tab" },
    { 0x10, "q" },
    { 0x11, "w" },
    { 0x12, "e" },
    { 0x13, "r" },
    { 0x14, "t" },
    { 0x15, "y" },
    { 0x16, "u" },
    { 0x17, "i" },
    { 0x18, "o" },
    { 0x19, "p" },

    { 0x1c, "ret" },

    { 0x1e, "a" },
    { 0x1f, "s" },
    { 0x20, "d" },
    { 0x21, "f" },
    { 0x22, "g" },
    { 0x23, "h" },
    { 0x24, "j" },
    { 0x25, "k" },
    { 0x26, "l" },

    { 0x2c, "z" },
    { 0x2d, "x" },
    { 0x2e, "c" },
    { 0x2f, "v" },
    { 0x30, "b" },
    { 0x31, "n" },
    { 0x32, "m" },
    
    { 0x39, "spc" },
    { 0x3a, "caps_lock" },
    { 0x3b, "f1" },
    { 0x3c, "f2" },
    { 0x3d, "f3" },
    { 0x3e, "f4" },
    { 0x3f, "f5" },
    { 0x40, "f6" },
    { 0x41, "f7" },
    { 0x42, "f8" },
    { 0x43, "f9" },
    { 0x44, "f10" },
    { 0x45, "num_lock" },
    { 0x46, "scroll_lock" },

    { 0x56, "<" },

    { 0x57, "f11" },
    { 0x58, "f12" },

    { 0xb7, "print" },

    { 0xc7, "home" },
    { 0xc9, "pgup" },
    { 0xd1, "pgdn" },
    { 0xcf, "end" },

    { 0xcb, "left" },
    { 0xc8, "up" },
    { 0xd0, "down" },
    { 0xcd, "right" },

    { 0xd2, "insert" },
    { 0xd3, "delete" },
    { 0, NULL },
};

static int get_keycode(const char *key)
{
    const KeyDef *p;

    for(p = key_defs; p->name != NULL; p++) {
        if (!strcmp(key, p->name))
            return p->keycode;
    }
    return -1;
}

static void do_send_key(const char *string)
{
    char keybuf[16], *q;
    uint8_t keycodes[16];
    const char *p;
    int nb_keycodes, keycode, i;
    
    nb_keycodes = 0;
    p = string;
    while (*p != '\0') {
        q = keybuf;
        while (*p != '\0' && *p != '-') {
            if ((q - keybuf) < sizeof(keybuf) - 1) {
                *q++ = *p;
            }
            p++;
        }
        *q = '\0';
        keycode = get_keycode(keybuf);
        if (keycode < 0) {
            term_printf("unknown key: '%s'\n", keybuf);
            return;
        }
        keycodes[nb_keycodes++] = keycode;
        if (*p == '\0')
            break;
        p++;
    }
    /* key down events */
    for(i = 0; i < nb_keycodes; i++) {
        keycode = keycodes[i];
        if (keycode & 0x80)
            kbd_put_keycode(0xe0);
        kbd_put_keycode(keycode & 0x7f);
    }
    /* key up events */
    for(i = nb_keycodes - 1; i >= 0; i--) {
        keycode = keycodes[i];
        if (keycode & 0x80)
            kbd_put_keycode(0xe0);
        kbd_put_keycode(keycode | 0x80);
    }
}


static int eject_device(BlockDriverState *bs, int force)
{
    if (bdrv_is_inserted(bs)) {
        if (!force) {
            if (!bdrv_is_removable(bs)) {
                term_printf("device is not removable\n");
                return -1;
            }
            if (bdrv_is_locked(bs)) {
                term_printf("device is locked\n");
                return -1;
            }
        }
        bdrv_close(bs);
    }
    return 0;
}

static void do_eject(int force, const char *filename)
{
    BlockDriverState *bs;

    bs = bdrv_find(filename);
    if (!bs) {
        term_printf("device not found\n");
        return;
    }
    eject_device(bs, force);
}

static void do_change(const char *device, const char *filename)
{
    BlockDriverState *bs;
#if 0
    int i;
    char password[256];
#endif

    bs = bdrv_find(device);
    if (!bs) {
        term_printf("device not found\n");
        return;
    }
    if (eject_device(bs, 0) < 0)
        return;
    bdrv_open(bs, filename, 0);
#if 0
    if (bdrv_is_encrypted(bs)) {
        term_printf("%s is encrypted.\n", device);
        for(i = 0; i < 3; i++) {
            monitor_readline("Password: ", 1, password, sizeof(password));
            if (bdrv_set_key(bs, password) == 0)
                break;
            term_printf("invalid password\n");
        }
    }
#endif
}

static void do_screen_dump(const char *filename)
{
    vga_screen_dump(filename);
}

static void do_log(const char *items)
{
    int mask;

    if (!strcmp(items, "none")) {
        mask = 0;
    } else {
        mask = cpu_str_to_log_mask(items);
        if (!mask) {
            help_cmd("log");
            return;
        }
    }
    cpu_set_log(mask);
}

static term_cmd_t term_cmds[] = {
    { "help|?", "s?", do_help,
      "[cmd]", "show the help" },
    { "commit", "", do_commit,
      "", "commit changes to the disk images (if -snapshot is used)" },
    { "info", "s?", do_info,
      "subcommand", "show various information about the system state" },
    { "q|quit", "", do_quit,
      "", "quit the emulator" },
    { "eject", "-fB", do_eject,
      "[-f] device", "eject a removable media (use -f to force it)" },
    { "change", "BF", do_change,
      "device filename", "change a removable media" },
    { "screendump", "F", do_screen_dump,
      "filename", "save screen into PPM image 'filename'" },
    { "log", "s", do_log,
      "item1[,...]", "activate logging of the specified items to '/tmp/qemu.log'" },
    { "q|quit", "", do_quit,
      "", "quit the emulator" },
    { "sendkey", "s", do_send_key, 
      "keys", "send keys to the VM (e.g. 'sendkey ctrl-alt-f1')" },
    { NULL, NULL, }, 
};

static term_cmd_t info_cmds[] = {
    { "version", "", do_info_version,
      "", "show the version of qemu" },
    { "network", "", do_info_network,
      "", "show the network state" },
    { "block", "", do_info_block,
      "", "show the block devices" },
    { "history", "", do_info_history,
      "", "show the command line history", },
    { "irq", "", irq_info,
      "", "show the interrupts statistics (if available)", },
    { "pic", "", pic_info,
      "", "show i8259 (PIC) state", },
    { "pci", "", pci_info,
      "", "show PCI info", },
    { "hvmiopage", "", sp_info,
      "", "show HVM device model shared page info", },
    { NULL, NULL, },
};

static int get_str(char *buf, int buf_size, const char **pp)
{
    const char *p;
    char *q;
    int c;

    q = buf;
    p = *pp;
    while (isspace(*p))
        p++;
    if (*p == '\0') {
    fail:
        *q = '\0';
        *pp = p;
        return -1;
    }
    if (*p == '\"') {
        p++;
        while (*p != '\0' && *p != '\"') {
            if (*p == '\\') {
                p++;
                c = *p++;
                switch(c) {
                case 'n':
                    c = '\n';
                    break;
                case 'r':
                    c = '\r';
                    break;
                case '\\':
                case '\'':
                case '\"':
                    break;
                default:
                    qemu_printf("unsupported escape code: '\\%c'\n", c);
                    goto fail;
                }
                if ((q - buf) < buf_size - 1) {
                    *q++ = c;
                }
            } else {
                if ((q - buf) < buf_size - 1) {
                    *q++ = *p;
                }
                p++;
            }
        }
        if (*p != '\"') {
            qemu_printf("unterminated string\n");
            goto fail;
        }
        p++;
    } else {
        while (*p != '\0' && !isspace(*p)) {
            if ((q - buf) < buf_size - 1) {
                *q++ = *p;
            }
            p++;
        }
    }
    *q = '\0';
    *pp = p;
    return 0;
}

#define MAX_ARGS 16

static void monitor_handle_command(const char *cmdline)
{
    const char *p, *pstart, *typestr;
    char *q;
    int c, nb_args, len, i;
    term_cmd_t *cmd;
    char cmdname[256];
    char buf[1024];
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
        case 'F':
        case 'B':
        case 's':
            {
                int ret;
                char *str;

                while (isspace(*p))
                    p++;
                if (*typestr == '?') {
                    typestr++;
                    if (*p == '\0') {
                        /* no optional string: NULL argument */
                        str = NULL;
                        goto add_str;
                    }
                }
                ret = get_str(buf, sizeof(buf), &p);
                if (ret < 0) {
                    switch(c) {
                    case 'F':
                        term_printf("%s: filename expected\n", cmdname);
                        break;
                    case 'B':
                        term_printf("%s: block device name expected\n", cmdname);
                        break;
                    default:
                        term_printf("%s: string expected\n", cmdname);
                        break;
                    }
                    goto fail;
                }
                str = qemu_malloc(strlen(buf) + 1);
                strcpy(str, buf);
                str_allocated[nb_args] = str;
            add_str:
                if (nb_args >= MAX_ARGS) {
                error_args:
                    term_printf("%s: too many arguments\n", cmdname);
                    goto fail;
                }
                args[nb_args++] = str;
            }
            break;
        case '-':
            {
                int has_option;
                /* option */
                
                c = *typestr++;
                if (c == '\0')
                    goto bad_type;
                while (isspace(*p)) 
                    p++;
                has_option = 0;
                if (*p == '-') {
                    p++;
                    if (*p != c) {
                        term_printf("%s: unsupported option -%c\n", 
                                    cmdname, *p);
                        goto fail;
                    }
                    p++;
                    has_option = 1;
                }
                if (nb_args >= MAX_ARGS)
                    goto error_args;
                args[nb_args++] = (void *)has_option;
            }
            break;
        /* TODO: add more commands we need here to support hvm device model */
        case '/':
        case 'i':
        default:
        bad_type:
            term_printf("%s: unknown type '%c',not support now.\n", cmdname, c);
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
    readline_start("(HVMXen) ", 0, monitor_handle_command1, NULL);
}

void monitor_init(CharDriverState *hd, int show_banner)
{
    monitor_hd = hd;
    if (show_banner) {
        term_printf("HVM device model. type 'q' to exit\n");
    }
    qemu_chr_add_read_handler(hd, term_can_read, term_read, NULL);
    monitor_start_input();
}
