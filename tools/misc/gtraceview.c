/*
 * gtraceview.c: list Cx events in a ncurse way to help find abnormal behaviour.
 * Copyright (c) 2009, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <xenctrl.h>
#include <xen/trace.h>

/* get curses header from configure */
#include INCLUDE_CURSES_H

/********** MACROS **********/
#define MAX_CPU_NR  32
#define MAX_MODE_NR 16
#define MAX_STRING_LEN 1024

/********** STRUCTURE DEFINITIONS **********/
enum {
    FLAG_FUZZY = 0,
    FLAG_LEVEL,
    FLAG_EDGE,
    FLAG_UNKNOWN,
    NR_FLAGS
};

struct string {
    int len;
    char str[MAX_STRING_LEN+1];
};

int num_of_cpus(void);
void string_nr_addch(struct string *str, int nr, char ch)
{
    int i;
    for (i = 0; i < nr; i++)
        str->str[str->len++] = ch;
    str->str[str->len] = '\0';
}

int string_print(struct string *str, char *fmt, ...)
{
    va_list ap;
    int l = 0;

    va_start(ap, fmt);
    l = vsprintf(str->str + str->len, fmt, ap);
    va_end(ap);
    str->len += l;
    str->str[str->len] = '\0';
    return l;
}

struct cpu {
    unsigned char cx;
    // unsigned char cx_prev;
    unsigned char flag;
    unsigned char irqs[4];
    unsigned int expected;
    unsigned int predicted;
};

struct state {
    uint64_t tsc;
    struct cpu cpu[MAX_CPU_NR];
};

struct mode {
    const char *name;
    int offset;
    int width;
    int row;
    int scroll_h;
    struct state *state;
    int state_nr;
    uint64_t time_scale;
    uint64_t start_time;
    int cpu_bitmap[MAX_CPU_NR];
    int initialized;
    int (*init)(void);
    void (*show)(void);
    void (*exit)(void);
};

/* simplified xentrace record */
struct rec {
    uint64_t tsc;
    int cpu;
    unsigned int expected;
    unsigned int predicted;
    unsigned char cx;
    unsigned char irqs[4];
};

/********** FORWARD DECLARATION **********/
void show_help(void);
void show_version(void);
int load_file(char *fname);
void crt_init(void);
int mode_init(void);
void mode_show(void);

/* event mode handler */
int event_mode_init(void);
void event_mode_show(void);
void event_mode_exit(void);

/* time mode handler */
int time_mode_init(void);
int time_mode_rebuild(uint64_t start_time, uint64_t time_scale);

/********** GLOBAL VARIABLES **********/
/* store simplified xentrace data */
struct rec *data;
int64_t data_nr, data_cur;
/* store max cx state number and cpu number */
int max_cx_num = -1, max_cpu_num = -1;
int is_irq_enabled = -1;
int is_menu_gov_enabled = -1;
int is_link = 0;
uint64_t tsc2us = 2793UL;

struct rec *data_evt;
struct rec *evt[MAX_CPU_NR];
int evt_len[MAX_CPU_NR];

int cur_row = 0;
struct mode modes[] = {
    {
        .name = "Event",
        .init = event_mode_init,
        .show = event_mode_show,
        .exit = event_mode_exit,
    },
    {
        .name = "Time",
        .init = time_mode_init,
        /* use the same show and exit with event mode */
        .show = event_mode_show,
        .exit = event_mode_exit,
    },
};
struct mode *this = NULL;

/* hand-crafted min() */
static inline int min(int a, int b)
{
    return a < b ? a : b;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void choose_cpus(void);
void help_screen(void);
int main(int argc, char *argv[])
{
    char *fname = NULL;
    int arg;
    int quit = 0;
    uint64_t s_time = 0;
    uint64_t last_tsc = 0;

    for (arg = 1; arg < argc; arg++) {
        if (!strcmp(argv[arg], "--version")) {
            show_version();
            exit(EXIT_SUCCESS);
        } else if (!strcmp(argv[arg], "--help")) {
            show_help();
            exit(EXIT_SUCCESS);
        } else {
            /* assume it's a file */
            fname = argv[arg];
            break;
        }
    }

    if (!fname) {
        show_help();
        exit(EXIT_FAILURE);
    }

    if (load_file(fname))
        exit(EXIT_FAILURE);

    if (!data_cur) {
        fprintf(stderr, "file %s doesn't contain any valid record\n", fname);
        exit(EXIT_FAILURE);
    }

    if (mode_init())
        exit(EXIT_FAILURE);

    crt_init();

    cur_row = 1;
    this = &modes[0];
    while (!quit) {
        int ch;

        clear();
        this->show();
        ch = getch();
        switch (ch) {
        case '!':
            is_link = !is_link;
            break;
        case 'u':
            move(LINES-1, 0);
            clrtoeol();
            printw("us = ? TSCs (default: 2793):");
            echo();
            curs_set(1);
            scanw("%"PRIu64, &tsc2us);
            curs_set(0);
            noecho();
            if (tsc2us <= 0)
                tsc2us = 2793UL;
            break;
        case '/':
            move(LINES-1, 0);
            clrtoeol();
            printw("Input start time:");
            echo();
            curs_set(1);
            scanw("%"PRIu64, &s_time);
            curs_set(0);
            noecho();
            if (s_time >= this->state[0].tsc &&
                s_time <= this->state[this->state_nr-1].tsc) {
                int i = 0;
                while (i < this->state_nr &&
                       this->state[i].tsc < s_time)
                    i++;
                this->row = i;
                cur_row = 1;
            }
            break;
        case '+':
            if (!strcmp(this->name, "Time")) {
                this->time_scale -= this->time_scale/10;
                this->start_time = this->state[this->row+cur_row-1].tsc - (cur_row-1)*this->time_scale;
                if (this->start_time < data[0].tsc)
                    this->start_time = data[0].tsc;
                time_mode_rebuild(this->start_time, this->time_scale);
            }
            break;
        case '-':
            if (!strcmp(this->name, "Time")) {
                this->time_scale += this->time_scale/10;
                this->start_time = this->state[this->row+cur_row-1].tsc - (cur_row-1)*this->time_scale;
                if (this->start_time < data[0].tsc)
                    this->start_time = data[0].tsc;
                time_mode_rebuild(this->start_time, this->time_scale);
            }
            break;
        case KEY_RESIZE:
            break;
        case KEY_UP:
            if (--cur_row < 1) {
                cur_row = 1;
                if (--this->row < 0)
                    this->row = 0;
            }
            break;
        case KEY_DOWN:
            if (++cur_row > LINES-2) {
                cur_row = LINES-2;
                this->row = min(this->state_nr-LINES+2, this->row+1);
            }
            break;
        case KEY_LEFT:
            this->scroll_h -= 3;
            if (this->scroll_h < 0)
                this->scroll_h = 0;
            break;
        case KEY_RIGHT:
            this->scroll_h += 3;
            if (this->scroll_h >= this->width*num_of_cpus())
                this->scroll_h = this->width*num_of_cpus();
            break;
        case KEY_HOME:
            cur_row = 1;
            this->row = 0;
            break;
        case KEY_END:
            cur_row = LINES-2;
            this->row = this->state_nr-LINES+2;
            break;
        case KEY_NPAGE:
            this->row = min(this->state_nr-LINES+2, this->row+20);
            break;
        case KEY_PPAGE:
            if (this->row >= 20)
                this->row -= 20;
            break;
        case KEY_F(2):
            /* change to another mode */
            if (is_link)
            last_tsc = this->state[this->row+cur_row-1].tsc;

            if (this == &modes[sizeof(modes)/sizeof(modes[0])-1])
                this = &modes[0];
            else
                this++;
            clear();
            if (is_link) {
                if (!strcmp(this->name, "Time")) {
                    this->start_time = last_tsc - (cur_row-1)*this->time_scale;
                    if (this->start_time < data[0].tsc)
                        this->start_time = data[0].tsc;
                    time_mode_rebuild(this->start_time, this->time_scale);
                } else if (!strcmp(this->name, "Event")) {
                    int x;
                    for (x = 0; x < this->state_nr && this->state[x].tsc < last_tsc; x++)
                        ;
                    this->row = x-(cur_row-1);
                }
            }
            break;
        case KEY_F(3):
            if (!strcmp(this->name, "Time")) {
                /* only meaningful in Time mode */
                move(LINES-1, 0);
                clrtoeol();
                printw("Input time scale and start time:");
                echo();
                curs_set(1);
                scanw("%"PRIu64" %"PRIu64,
                      &this->time_scale, &this->start_time);
                curs_set(0);
                noecho();
                time_mode_rebuild(this->start_time,
                                  this->time_scale);
            }
            break;
        case KEY_F(4):
            /* quit */
            quit = 1;
            break;
        case KEY_F(5):
            /* choose which CPUs to display */
            choose_cpus();
            break;
        case 'h':
            help_screen();
            break;
        }
    }

    exit(EXIT_SUCCESS);
}
/* used for qsort() */
static int evt_data_cmp(const void *_a, const void *_b)
{
    struct rec *a = (struct rec *)_a;
    struct rec *b = (struct rec *)_b;
    if (a->cpu == b->cpu)
        return a->tsc > b->tsc ? 1 : -1;
    return a->cpu > b->cpu ? 1 : -1;
}

static int data_cmp(const void *_a, const void *_b)
{
    struct rec *a = (struct rec *)_a;
    struct rec *b = (struct rec *)_b;
    return a->tsc > b->tsc ? 1 : -1;
}

/* load file and make them a list of records
 * update these following variables:
 *   data, data_cur, data_nr
 *   max_cpu_num, max_cx_num
 */
int load_file(char *fname)
{
    /* file descriptor for raw xentrace file */
    int fd;
    /* current cpu during xentrace data parse */
    int cur_cpu = -1;
    int i;

    fd = open(fname, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "file %s cannot open\n", fname);
        return 1;
    }

    /* the initial number is 1024,
     * and when it overflows, this number doubles.
     */
    data_nr = 1024;
    data_cur = 0;
    data = malloc(sizeof(struct rec) * data_nr);
    if (!data) {
        fprintf(stderr, "not enough memory\n");
        close(fd);
        return 1;
    }

    while (1) {
        struct t_rec rec;
        ssize_t ret, size;

        ret = read(fd, &rec, sizeof(uint32_t));
        if (!ret)
            break;
        if (ret != sizeof(uint32_t)) {
            fprintf(stderr, "reading header error\n");
            break;
        }

        size = 0;
        if (rec.cycles_included)
            size += sizeof(uint64_t);
        size += sizeof(uint32_t) * rec.extra_u32;

        ret = read(fd, (char *)&rec + sizeof(uint32_t), size);
        if (!ret && size)
            break;
        if (ret != size) {
            fprintf(stderr, "reading data error\n");
            break;
        }

        if (rec.event == 0x1f003) {
            /* cpu change event */
            cur_cpu = 0;
            if (rec.extra_u32 > 0)
                cur_cpu = rec.u.nocycles.extra_u32[0];
            continue;
        } else if (!rec.cycles_included ||
                   (rec.event != TRC_PM_IDLE_ENTRY &&
                    rec.event != TRC_PM_IDLE_EXIT &&
                    rec.event != TRC_PM_FREQ_CHANGE)) {
            continue;
        }

        /* add one record */
        if (data_cur == data_nr) {
            data_nr <<= 1;
            if (data_nr < 0) {
                fprintf(stderr, "too many entries\n");
                close(fd);
                return 1;
            }
            data = realloc(data, sizeof(struct rec) * data_nr);
            if (!data) {
                fprintf(stderr, "not enough memory\n");
                close(fd);
                return 1;
            }
        }
        data[data_cur].tsc = rec.u.cycles.cycles_hi;
        data[data_cur].tsc <<= 32;
        data[data_cur].tsc |= rec.u.cycles.cycles_lo;
        data[data_cur].cpu = cur_cpu;
        /* extra_u32[1] is omitted, as it's pm ticks. */
        if (rec.event == TRC_PM_IDLE_ENTRY) {
            data[data_cur].cx = rec.u.cycles.extra_u32[0];
            if (rec.extra_u32 >= 4) {
                data[data_cur].expected = rec.u.cycles.extra_u32[2];
                data[data_cur].predicted = rec.u.cycles.extra_u32[3];
                is_menu_gov_enabled = 1;
            } else
                is_menu_gov_enabled = 0;
        } else if (rec.event == TRC_PM_IDLE_EXIT) {
            /* IDLE_EXIT default to C0 */
            data[data_cur].cx = 0;
            /* store the reasons why it exits */
            if (rec.extra_u32 == 6) {
                data[data_cur].irqs[0] = rec.u.cycles.extra_u32[2];
                data[data_cur].irqs[1] = rec.u.cycles.extra_u32[3];
                data[data_cur].irqs[2] = rec.u.cycles.extra_u32[4];
                data[data_cur].irqs[3] = rec.u.cycles.extra_u32[5];
                is_irq_enabled = 1;
            } else
                is_irq_enabled = 0;
        } else {
            /* FREQ CHANGE */
        }

        /* update max info */
        if (data[data_cur].cx > max_cx_num)
            max_cx_num = data[data_cur].cx;
        if (data[data_cur].cpu > max_cpu_num)
            max_cpu_num = data[data_cur].cpu;

        data_cur++;
    }
    close(fd);

    data_evt = malloc(sizeof(struct rec) * data_cur);
    memcpy(data_evt, data, sizeof(struct rec) * data_cur);

    qsort(data_evt, data_cur, sizeof(struct rec), evt_data_cmp);
    for (i = 0; i < max_cpu_num; i++) {
        evt_len[i] = 0;
        evt[i] = NULL;
    }
    for (i = data_cur-1; i >= 0; i--) {
        evt[data_evt[i].cpu] = data_evt+i;
        evt_len[data_evt[i].cpu]++;
    }

    /* sort data array according to TSC time line */
    qsort(data, data_cur, sizeof(struct rec), data_cmp);

    max_cpu_num++;
    max_cx_num++;

    return 0;
}

void show_version(void)
{
    printf("gtraceview - (C) 2009 Intel Corporation\n");
}

void show_help(void)
{
    show_version();
    printf("gtraceview <trace.data> [--version] [--help]\n");
    printf("  trace.data   raw data got by "
           "'xentrace -e 0x80f000 trace.dat'\n");
    printf("  --version    show version information\n");
    printf("  --help       show this message\n");
    printf("For more help messages, please press 'h' in the window\n");
}

void crt_done(void)
{
    curs_set(1);
    endwin();
}

void help_screen(void)
{
    clear();
    mvprintw(0, 0, "    HELP SCREEN");
    mvprintw(1, 0, "1. LEFT and RIGHT arrow key to move off-screen outputs");
    mvprintw(2, 0, "2. UP and DOWN arrow key to move the highlighted line");
    mvprintw(3, 0, "3. F2 to switch between Event and Time mode");
    mvprintw(4, 0, "4. '/' to search the TSC stamp");
    mvprintw(5, 0, "5. '+' to zoom in and '-' to zoom out");
    mvprintw(6, 0, "6. F3 to set start time and time manually");
    mvprintw(7, 0, "7. F4 to quit");
    mvprintw(8, 0, "8. F5 to select which CPUs we want to see");
    mvprintw(9, 0, "9. Irq exit reason shown on Cx exit record (patch needed)");
    mvprintw(10, 0, "10. Menu governor criteria shown on bottom line (patch needed)");
    mvprintw(11, 0, "11. PAGEDOWN, PAGEUP, HOME and END to navigate");
    mvprintw(12, 0, "12. 'h' to show this screen");
    mvprintw(13, 0, "13. 'u' to edit how many TSCs is a us unit");

    mvprintw(LINES-1, 0, "Press any key to continue...");
    getch();
}

void crt_init(void)
{
    char *term;

    initscr();
    noecho();
    nonl();
    intrflush(stdscr, false);
    keypad(stdscr, true);
    curs_set(0);
    /* hook exit() */
    atexit(crt_done);
    /* we love colorful screens :-) */
    start_color();
    init_pair(1, COLOR_BLACK, COLOR_CYAN);
    init_pair(2, COLOR_BLACK, COLOR_GREEN);
    init_pair(3, COLOR_BLACK, COLOR_RED);

    /* some term tunings */
    term = getenv("TERM");
    if (!strcmp(term, "xterm") ||
        !strcmp(term, "xterm-color") ||
        !strcmp(term, "vt220")) {
        define_key("\033[1~", KEY_HOME);
        define_key("\033[4~", KEY_END);
        define_key("\033OP", KEY_F(1));
        define_key("\033OQ", KEY_F(2));
        define_key("\033OR", KEY_F(3));
        define_key("\033OS", KEY_F(4));
        define_key("\033[11~", KEY_F(1));
        define_key("\033[12~", KEY_F(2));
        define_key("\033[13~", KEY_F(3));
        define_key("\033[14~", KEY_F(4));
        define_key("\033[[D", KEY_LEFT);
    }
}

void nr_addch(int nr, int ch)
{
    int i;
    int y, x;
    getyx(stdscr, y, x);
    for (i = 0; i < nr; i++) {
        if (x == COLS-1)
            break;
        addch(ch);
    }
}

int event_mode_init(void)
{
    int i, j;
    struct state *state;
    int index;
    struct cpu cur_state[MAX_CPU_NR];

    if (this->initialized)
        free(this->state);
    state =  malloc(sizeof(struct state) * data_cur);
    if (!state)
        return 1;
    this->state = state;
    this->row = 0;
    this->width = 9;
    this->offset = 33;
    this->scroll_h = 0;

    /* otherwise, respect cpu_bitmap[] */
    if (!this->initialized) {
        this->initialized = 1;
        for (i = 0; i < max_cpu_num; i++)
            this->cpu_bitmap[i] = 1;
    }

    for (i = 0; i < max_cpu_num; i++)
        if (this->cpu_bitmap[i])
            cur_state[i].flag = FLAG_UNKNOWN;

    for (i = 0, index = 0; i < data_cur; i++) {
        /* data[i] */
        int cpu = data[i].cpu;
        if (cpu < 0)
            continue;
        if (!this->cpu_bitmap[cpu])
            continue;

        /* TODO: use the same structure */
        /* copy cx, expected, predicted and irqs */
        cur_state[cpu].cx = data[i].cx;
        cur_state[cpu].expected = data[i].expected;
        cur_state[cpu].predicted = data[i].predicted;
        memcpy(cur_state[cpu].irqs, data[i].irqs,
               sizeof(unsigned char) * 4);
        /* as long as it comes here,
         * it means that we have an event.
         */
        cur_state[cpu].flag = FLAG_EDGE;

        state[index].tsc = data[i].tsc;
        for (j = 0; j < max_cpu_num; j++) {
            if (!this->cpu_bitmap[j])
                continue;

            /* copy cx, irqs and flags */
            state[index].cpu[j].cx = cur_state[j].cx;
            state[index].cpu[j].expected = cur_state[j].expected;
            state[index].cpu[j].predicted = cur_state[j].predicted;
            memcpy(state[index].cpu[j].irqs, cur_state[j].irqs,
                   sizeof(unsigned char) * 4);
            state[index].cpu[j].flag = cur_state[j].flag;

            /* chage flag in cur_state accordingly */
            if (cur_state[j].flag == FLAG_EDGE)
                cur_state[j].flag = FLAG_LEVEL;
        }
        index++;
    }

    this->state_nr = index;
    return 0;
}

static inline int len_of_number(uint64_t n)
{
    int l = 0;
    if (!n)
        return 1;
    do {
        l++;
        n /= 10;
    } while (n);
    return l;
}

static inline void display_number(uint64_t n, int l)
{
    static char sym[] = { ' ', 'K', 'M', 'G', 'T' };
    int nr = 0;

    if (len_of_number(n) <= l) {
        nr_addch(l-len_of_number(n), ' ');
        printw("%"PRIu64, n);
        return;
    }
    do {
        n /= 1000UL;
        nr++;
    } while (len_of_number(n) > l-1);
    nr_addch(l-1-len_of_number(n), ' ');
    printw("%"PRIu64, n);
    nr_addch(1, sym[nr]);
}

void draw_cpu_state(struct string *s, struct cpu *c, int width)
{
    int cx = c->cx;
    int flag = c->flag;

    switch (flag) {
    case FLAG_FUZZY:
        string_nr_addch(s, max_cx_num, '#');
        string_nr_addch(s, width-max_cx_num, ' ');
        break;
    case FLAG_UNKNOWN:
        string_nr_addch(s, 1, '?');
        string_nr_addch(s, width-1, ' ');
        break;
    case FLAG_LEVEL:
        string_nr_addch(s, cx, ' ');
        string_nr_addch(s, 1, '|');
        string_nr_addch(s, width-1-cx, ' ');
        break;
    case FLAG_EDGE:
        if (cx > 0) {
            /* ENTRY */
            string_nr_addch(s, 1, '>');
            string_nr_addch(s, cx-1, '-');
            string_nr_addch(s, 1, '+');
            string_nr_addch(s, width-cx-1, ' ');
        } else {
            /* EXIT */
            string_nr_addch(s, 1, '<');
            if (is_irq_enabled == 1) {
                int k, len = 0;
                for (k = 0; k < 4; k++) {
                    unsigned char irq = c->irqs[k];
                    if (irq) {
                        string_print(s, "%02x", irq);
                        len += 2;
                    }
                }
                if (len > 0)
                    string_nr_addch(s, width-len-1, ' ');
                else {
                    string_print(s, "noirq");
                    string_nr_addch(s, width-1-5, ' ');
                }
            } else {
                string_nr_addch(s, 1, '-');
                string_nr_addch(s, width-2, ' ');
            }
        }
        break;
    }
}

void event_mode_show(void)
{
    struct state *state = this->state;
    struct string s;
    int idx = this->row;
    int idx_hl = 0;
    int i, j, l;

    /* draw headline */
    s.len = 0;
    move(0, 0);
    attron(COLOR_PAIR(2));
    nr_addch(this->offset, ' ');
    for (i = 0; i < max_cpu_num; i++) {
        if (this->cpu_bitmap[i]) {
            string_print(&s, "CPU%d", i);
            string_nr_addch(&s, this->width-len_of_number(i)-3, ' ');
        }
    }
    mvaddnstr(0, this->offset, s.str+this->scroll_h,
              MIN(s.len-this->scroll_h, this->width*num_of_cpus()));
    attroff(COLOR_PAIR(2));

    /* draw body */
    for (i = 1; i < LINES-1; i++, idx++) {
        move(i, 0);
        /* highlight the current row */
        if (i == cur_row) {
            attron(COLOR_PAIR(1));
            idx_hl = idx;
        }

        if (idx >= this->state_nr) {
            /* do not show this line */
            nr_addch(this->offset+this->width*num_of_cpus(), ' ');
        } else {
            if (!strcmp(this->name, "Event")) {
                uint64_t delta = 0;
                if (idx)
                    delta = (state[idx].tsc - state[idx-1].tsc)/tsc2us;
                printw("%20"PRIu64"(", state[idx].tsc);
                display_number(delta, 8);
                printw("us) ");
            } else if (!strcmp(this->name, "Time")) {
                printw("%20"PRIu64" ", state[idx].tsc);
            }

            s.len = 0;
            for (j = 0; j < max_cpu_num; j++) {
                /* draw cpu state */
                if (this->cpu_bitmap[j])
                    draw_cpu_state(&s, &state[idx].cpu[j], this->width);
            }
            /* draw the line accordingly */
            mvaddnstr(i, this->offset, s.str+this->scroll_h,
                      MIN(s.len-this->scroll_h, this->width*num_of_cpus()));
        }
        /* pair of the highlight logics */
        if (i == cur_row)
            attroff(COLOR_PAIR(1));
    }

    /* draw tail line */
    attron(COLOR_PAIR(2));
    s.len = 0;
    l = 0;
    l += string_print(&s, "%s Mode [%sLINKED]", this->name, is_link ? "" : "NOT ");
    if (!strcmp(this->name, "Time")) {
#if 0
        l += string_print(&s, " [%"PRIu64":%"PRIu64"]",
                          this->start_time, this->time_scale);
#endif
        l += string_print(&s, " [%"PRIu64"]",
                          this->time_scale);
    }
    if (is_menu_gov_enabled == 1) {
        for (i = 0; i < max_cpu_num; i++) {
            if (this->cpu_bitmap[i] &&
                state[idx_hl].cpu[i].flag == FLAG_EDGE &&
                state[idx_hl].cpu[i].cx > 0)
                l += string_print(&s, " (CPU%d,%lu,%lu)",
                                  i,
                                  state[idx_hl].cpu[i].expected,
                                  state[idx_hl].cpu[i].predicted);
        }
    }
    /* add cx exit residency info */
    for (i = 0; i < max_cpu_num; i++) {
        if (this->cpu_bitmap[i] &&
            state[idx_hl].cpu[i].flag == FLAG_EDGE &&
            state[idx_hl].cpu[i].cx == 0) {
            uint64_t tsc = state[idx_hl].tsc;
            int k;

            k = 0;
            while (k < evt_len[i] &&
                   evt[i][k].tsc < tsc)
                k++;
            k--;
            if (k >= 0 && k+1 < evt_len[i] && evt[i][k].cx > 0) {
                l += string_print(&s, " (CPU%d, %"PRIu64"us)",
                                  i,
                                  (evt[i][k+1].tsc - evt[i][k].tsc)/tsc2us);
            }
        }
    }

    string_nr_addch(&s, this->offset+this->width*num_of_cpus()-l, ' ');
    mvaddstr(LINES-1, 0, s.str);
    attroff(COLOR_PAIR(2));
    refresh();
}

void event_mode_exit(void)
{
    free(this->state);
    this->initialized = 0;
}

void mode_exit(void)
{
    int nr = sizeof(modes)/sizeof(modes[0]);
    int i;

    for (i = 0; i < nr; i++) {
        this = &modes[i];
        if (this->initialized)
            this->exit();
    }
}

int mode_init(void)
{
    int nr = sizeof(modes)/sizeof(modes[0]);
    int i, r = 0;

    for (i = 0; i < nr; i++) {
        this = &modes[i];
        this->initialized = 0;
        r += this->init();
    }

    this = &modes[0];

    /* hook into exit */
    atexit(mode_exit);

    return r;
}

int time_mode_rebuild(uint64_t start_time, uint64_t time_scale)
{
    int i, j;
    struct cpu cur_state[MAX_CPU_NR];
    uint64_t tsc = start_time;
    struct state *state;
    uint64_t number, temp = 0;
    int state_cur = 0;

    for (i = 0; i < max_cpu_num; i++)
        cur_state[i].flag = FLAG_UNKNOWN;

    /* allocate spaces, it may be huge... */
    if (time_scale)
        temp = (data[data_cur-1].tsc - start_time)/time_scale;
    number = 10000UL;
    if (temp < number)
        number = temp;
    number += 2;
    state = malloc(sizeof(struct state) * number);
    if (!state)
        return 1;
    free(this->state);
    this->state = state;
    this->width = 9;
    this->row = 0;

    /* determine the current Cx state */
    /* check [data[0].tsc, tsc) */
    i = 0;
    while (i < data_cur && data[i].tsc < tsc) {
        int cpu = data[i].cpu;
        cur_state[cpu].cx = data[i].cx;
        cur_state[cpu].flag = FLAG_LEVEL;
        i++;
    }
    while (i < data_cur && state_cur < number) {
        int num[MAX_CPU_NR];
        int last_idx[MAX_CPU_NR];

#if 0
        printf("XXXXX %d tsc: %"PRIu64" data[i].tsc: %"PRIu64"\n",
               i, tsc, data[i].tsc);
#endif
        /* ensure they are zero */
        memset(num, 0, sizeof(int) * MAX_CPU_NR);
        memset(last_idx, 0, sizeof(int) * MAX_CPU_NR);

        /* check [tsc, tsc+time_scale) */
        while (i < data_cur && data[i].tsc < tsc+time_scale) {
            int cpu = data[i].cpu;
            num[cpu]++;
            last_idx[cpu] = i;
            i++;
        }
        /* TODO */
        if (i >= data_cur)
            break;
        for (j = 0; j < max_cpu_num; j++) {
            if (num[j] == 1) {
                /* only one event, it's an edge*/
                cur_state[j].cx = data[last_idx[j]].cx;
                cur_state[j].flag = FLAG_EDGE;
            } else if (num[j] > 1) {
                /* more than one event, it's fuzzy */
                cur_state[j].cx = data[last_idx[j]].cx;
                cur_state[j].flag = FLAG_FUZZY;
            } else if (cur_state[j].flag == FLAG_FUZZY) {
                /* no event, fuzzy state can't be passed down
                 * notice that cx is set in the fuzzy state,
                 * it's not changed here afterwards.
                 */
                cur_state[j].flag = FLAG_LEVEL;
            }
        }

        /* copy tsc */
        state[state_cur].tsc = tsc;
        for (j = 0; j < max_cpu_num; j++) {
            /* copy cx and flag */
            state[state_cur].cpu[j].cx = cur_state[j].cx;
            state[state_cur].cpu[j].flag = cur_state[j].flag;

            /* update flag in cur_state */
            if (cur_state[j].flag == FLAG_EDGE) {
                cur_state[j].flag = FLAG_LEVEL;
                if (cur_state[j].cx == 0) {
                    /* EXIT */
                    /* copy irqs conditionally */
                    memcpy(state[state_cur].cpu[j].irqs,
                           data[last_idx[j]].irqs,
                           sizeof(unsigned char) * 4);
                } else {
                    /* ENTRY */
                    state[state_cur].cpu[j].expected =
                        data[last_idx[j]].expected;
                    state[state_cur].cpu[j].predicted =
                        data[last_idx[j]].predicted;
                }
            }
        }
        state_cur++;
        tsc += time_scale;
    }
    this->state_nr = state_cur;
    this->row = 0;

    return 0;
}

int time_mode_init(void)
{
    int i;
    this->offset = 21;
    this->scroll_h = 0;
    this->time_scale = (data[data_cur-1].tsc -data[0].tsc)/10000UL;
    this->start_time = data[0].tsc;
    for (i = 0; i < max_cpu_num; i++)
        this->cpu_bitmap[i] = 1;
    return time_mode_rebuild(this->start_time,
                             this->time_scale);
}

void choose_cpus(void)
{
    int i;
    int temp_row = 1;
    int ch;

    clear();
    mvprintw(0, 0, "How many CPUs to track? Press space to toggle. Press 'q' or 'Q' to quit.");

    while (1) {
        for (i = 0; i < max_cpu_num; i++) {
            if (temp_row == i+1)
                attron(COLOR_PAIR(2));
            mvprintw(i+1, 0, "[%s] CPU%d", this->cpu_bitmap[i] ? "x" : " ", i);
            if (temp_row == i+1)
                attroff(COLOR_PAIR(2));
        }
        ch = getch();
        switch (ch) {
        case KEY_UP:
            if (--temp_row < 1)
                temp_row = 1;
            break;
        case KEY_DOWN:
            if (++temp_row > max_cpu_num)
                temp_row = max_cpu_num;
            break;
        case ' ':
            this->cpu_bitmap[temp_row-1] = !this->cpu_bitmap[temp_row-1];
            break;
        case 'q':
        case 'Q':
            if (num_of_cpus() >= 1) {
                if (!strcmp(this->name, "Event"))
                    this->init();
                return;
            }
            /* fallthrough */
        case KEY_F(4):
            exit(EXIT_SUCCESS);
        }
    }
}

int num_of_cpus(void)
{
    int i, nr = 0;
    for (i = 0; i < max_cpu_num; i++)
        if (this->cpu_bitmap[i])
            nr++;
    return nr;
}

