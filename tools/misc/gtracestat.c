/*
 * gtracestat.c: list the statistics information for a dumped xentrace file.
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
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <xenctrl.h>
#include <xen/trace.h>

#define CHECK_DUP_CX 0

/********** MACROS **********/
#define MAX_CPU_NR  32
#define MAX_CX_NR   8
#define MAX_MODE_NR 16
#define MAX_PX_NR	100

/* simplified xentrace record */
struct rec {
    uint64_t tsc;
    int cpu;
    unsigned char cx;
    unsigned char irqs[4];
    unsigned int predicted;
    unsigned int expected;
    int px;
};

/********** FORWARD DECLARATION **********/
void show_help(void);
void show_version(void);
int load_file(char *fname);
void do_digest(uint64_t start, uint64_t end, uint64_t scale);
void do_breakevents(void);
void do_count(void);
void do_px_count(void);
void do_maxmin(void);
void do_average(void);
void do_cstate(uint64_t start, uint64_t end);
void do_exp_ratio(void);
void do_exp_pred(void);

/********** GLOBAL VARIABLES **********/
/* store simplified xentrace data */
struct rec *data;
int64_t data_nr, data_cur;
/* store max cx state number and cpu number */
int max_cx_num = -1, max_cpu_num = -1;
int px_freq_table[MAX_PX_NR];
int max_px_num = 0;

int is_menu_gov_enabled = 0;

/* user specified translation unit */
uint64_t tsc2ms = 2793000UL;
uint64_t tsc2us = 2793UL;
uint64_t tsc2phase = 55800000UL;

/* each cpu column width */
int width = 0;

/* digest mode variables */
struct rec *evt[MAX_CPU_NR];
int evt_len[MAX_CPU_NR];

/* hand-crafted min() */
static inline uint64_t min(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}
static inline uint64_t max(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

int is_px = 0;

int main(int argc, char *argv[])
{
    char *fname = NULL;
    /* operation flags */
    int is_breakevents = 0;
    int is_count = 0;
    int is_maxmin = 0;
    int is_average = 0;
    int is_digest = 0;
    int is_exp_ratio = 0;
    int is_exp = 0;
    uint64_t start_time = 0;
    uint64_t time_scale = 0;
    uint64_t end_time = 0;

    struct option  long_options [] = {
        /* short options are listed correspondingly */
        { "version", 0, NULL, 'v' },
        { "help", 0, NULL, 'h' },
        /* list Cx entires one by one */
        { "digest", 0, NULL, 'd' },
        /* ignored when digest is disabled */
        { "start", 1, NULL, 's' },
        { "end", 1, NULL, 'e' },
        { "scale", 1, NULL, 'l' },
        /* give summary about breakevents info */
        { "breakevents", 0, NULL, 'b' },
        { "count", 0, NULL, 'c' },
        { "average", 0, NULL, 'a' },
        /* list max/min residency for each Cx */
        { "maxmin", 0, NULL, 'm' },
        { "tsc2us", 1, NULL, 'u' },
        { "px", 0, NULL, 'p' },
        { "tsc2phase", 1, NULL, 'n' },
        { "exp-ratio", 0, NULL, 'z' },
        { "exp-pred", 0, NULL, 'x' },
        { NULL, 0, NULL, 0 },
    };

    if ( argc == 1 ) {
        show_help();
        exit(EXIT_SUCCESS);
    }
    while (1) {
        int ch, opt_idx;
        ch = getopt_long(argc, argv, "vhds:e:l:bcmau:pn:zx",
                         long_options, &opt_idx);
        if (ch == -1)
            break;
        switch (ch) {
        case 'v':
            show_version();
            exit(EXIT_SUCCESS);
        case 'h':
            show_help();
            exit(EXIT_SUCCESS);
        case 'p':
            is_px = 1;
            break;
        case 'x':
            is_exp = 1;
            break;
        case 'z':
            is_exp_ratio = 1;
            break;
        case 'n':
            tsc2phase = atoll(optarg);
            if (tsc2phase <= 0)
                tsc2phase = 55800000UL;
            break;
        case 'd':
            is_digest = 1;
            break;
        case 's':
            start_time = atoll(optarg);
            break;
        case 'e':
            end_time = atoll(optarg);
            break;
        case 'l':
            time_scale = atoll(optarg);
            break;
        case 'b':
            is_breakevents = 1;
            break;
        case 'c':
            is_count = 1;
            break;
        case 'm':
            is_maxmin = 1;
            break;
        case 'a':
            is_average = 1;
            break;
        case 'u':
            tsc2us = atoll(optarg);
            tsc2ms = tsc2us * 1000UL;
            break;
        case '?':
        default:
            show_help();
            exit(EXIT_FAILURE);
        }
    }

    if (argc - optind > 1) {
        printf("Multiple file specified?\n");
        show_help();
        exit(EXIT_FAILURE);
    }
    fname = argv[optind];

    if (load_file(fname))
        exit(EXIT_FAILURE);

    width = 10;
    if (is_digest) {
        /* if people not specify the time related number,
         * use the default one from the record.
         */
        if (!start_time)
            start_time = data[0].tsc;
        if (!end_time)
            end_time = data[data_cur-1].tsc;
        if (!time_scale)
            time_scale = 10UL * tsc2ms;	/* default: 10 ms */
        do_digest(start_time, end_time, time_scale);
    }

    if (is_breakevents)
        do_breakevents();

    if (is_count && !is_px)
        do_count();
    if (is_count && is_px)
        do_px_count();

    if (is_maxmin)
        do_maxmin();

    if (is_average)
        do_average();

    if (is_exp_ratio)
        do_exp_ratio();

    if (is_exp)
        do_exp_pred();

    exit(EXIT_SUCCESS);
}

/* used for qsort() */
/* sort by cpu first, then by tsc */
static int data_cmp(const void *_a, const void *_b)
{
    struct rec *a = (struct rec *)_a;
    struct rec *b = (struct rec *)_b;
    if (a->cpu == b->cpu)
        return a->tsc > b->tsc ? 1 : -1;
    return a->cpu > b->cpu ? 1 : -1;
}

/* load file and make them a list of records
 * update these following variables:
 *   data, data_cur, data_nr
 *   max_cpu_num, max_cx_num
 */
#define LIST_PX 0
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
            /* we care about only idle events now */
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
        if (is_px) {
            if (rec.event != TRC_PM_FREQ_CHANGE)
                continue;
            /* FREQ_CHANGE */
            if (rec.u.cycles.extra_u32[0] ==
                rec.u.cycles.extra_u32[1])
                continue;
            data[data_cur].px = rec.u.cycles.extra_u32[1];
            for (i = 0; i < max_px_num; i++)
                if (px_freq_table[i] == data[data_cur].px)
                    break;
            if (i == max_px_num)
                px_freq_table[max_px_num++] = data[data_cur].px;
        } else {
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
                data[data_cur].irqs[0] = rec.u.cycles.extra_u32[2];
                data[data_cur].irqs[1] = rec.u.cycles.extra_u32[3];
                data[data_cur].irqs[2] = rec.u.cycles.extra_u32[4];
                data[data_cur].irqs[3] = rec.u.cycles.extra_u32[5];
            } else
                continue;
            /* update max info */
            if (data[data_cur].cx > max_cx_num)
                max_cx_num = data[data_cur].cx;
        }

        if (data[data_cur].cpu > max_cpu_num)
            max_cpu_num = data[data_cur].cpu;

        data_cur++;
    }
    close(fd);

    /* sort data array according to TSC time line */
    qsort(data, data_cur, sizeof(struct rec), data_cmp);

    max_cpu_num++;
    max_cx_num++;

    for (i = 0; i < max_cpu_num; i++) {
        evt_len[i] = 0;
        evt[i] = NULL;
    }
    for (i = data_cur-1; i >= 0; i--) {
        evt[data[i].cpu] = data+i;
        evt_len[data[i].cpu]++;
    }
#if CHECK_DUP_CX
    int xx, yy;
    int err = 0;
    printf("Checking %s...\n", fname);
    for (xx = 0; xx < max_cpu_num; xx++) {
        //	printf("............ CPU %d .............\n", xx);
        for (yy = 0; yy+1 < evt_len[xx]; yy++)
            if ( evt[xx][yy].cx > 0 && evt[xx][yy+1].cx > 0) {
                printf("same witht next one %"PRIu64" %d %d\n",
                       evt[xx][yy].tsc, evt[xx][yy].cpu, evt[xx][yy].cx);
                err++;
            }
    }
    exit(err);
#endif
#if LIST_PX
    int x, y;
    for (x = 0; x < max_cpu_num; x++) {
        printf("CPU%d**************************************\n", x);
        for (y = 0; y+1 < evt_len[x]; y++) {
            printf("[%dHz]: phase: %d\n",
                   evt[x][y].px,
                   (int)((evt[x][y+1].tsc - evt[x][y].tsc)/tsc2phase));
        }
    }
#endif
    return 0;
}

void show_version(void)
{
    printf("gtracestat - (C) 2009-2011 Intel Corporation\n");
}

void show_help(void)
{
    show_version();
    printf("gtracestat <trace.data> [-vhdselbcmau]\n");
    printf("  trace.data       raw data got by 'xentrace -e 0x80f000 trace.dat'\n");
    printf("  -v / --version   show version message\n");
    printf("  -h / --help      show this message\n");
    printf("  -d / --digest    digest mode, more variables to specify.\n");
    printf("  -s / --start <start_time> specify start time (only in digest mode)\n");
    printf("  -e / --end <end_time>     specify end time (only in digest mode)\n");
    printf("  -l / --scale <scale>      specify time scale (only in digest mode)\n");
    printf("  -b / --breakevents give breakevents summary info\n");
    printf("  -c / --count       give count summary info\n");
    printf("  -a / --average     give total/average residency info\n");
    printf("  -m / --maxmin      show man/min residency summary info\n");
    printf("  -u / --tsc2us <tsc-per-us> specify how many tsc is a us unit\n");
    printf("  -p / --px          operate on Px entries\n");
    printf("  -n / --tsc2phase <tsc-per-phase> specify how many tsc is a phase unit (only in px)\n");
    printf("  -z / --exp-ratio   show the ratio of early break events\n");
    printf("  -x / --exp-pred    show the ratio of expected / predicted in Cx entry\n");
}

static inline int len_of_number(uint64_t n)
{
    int l = 0;
    do {
        l++;
        n /= 10;
    } while (n);
    return l;
}

/* determine the cx at time t
 * take advantage of evt and evt_len.
 */
int determine_cx(int c, uint64_t t)
{
    int i;

    i = 0;
    while (i < evt_len[c] && evt[c][i].tsc <= t)
        i++;
    /* if there are any events happening,
     * it must be in a Cx state now.
     */
    if (i)
        return evt[c][i-1].cx;
    /* look forward to see whether it will enter
     * a Cx state, if so, it must be in C0 state.
     * we can't determine a Cx state from exit event.
     */
    if (i < evt_len[c] && evt[c][i].cx > 0)
        return 0;
    return -1;
}

/* c - cpu
 * t - start time
 * s - scale
 * cx_i - number of cx index
 * cx_r - residency of each cx entry
 */
int process(int c, uint64_t t, uint64_t s, int *cx_i, uint64_t *cx_r)
{
    int cx;
    uint64_t len;
    int i, n;

    cx = determine_cx(c, t);
    i = 0;
    while (i < evt_len[c] && evt[c][i].tsc < t)
        i++;
    n = 0;
    if (cx >= 0 && i < evt_len[c]) {
        cx_i[n] = cx;
        cx_r[n] = evt[c][i].tsc - t;
        if (cx_r[n])
            n++;
    }
    while (i < evt_len[c] && evt[c][i].tsc < t+s) {
        /* we are now at [t, t+s) */
        cx = evt[c][i].cx;
        len = min((i+1 < evt_len[c] ? evt[c][i+1].tsc : t+s), t+s)
            - evt[c][i].tsc;

        cx_i[n] = cx;
        cx_r[n] = len;
        n++;

        i++;
    }

    return n;
}

void nr_putchar(int nr, int ch)
{
    int i;
    for (i = 0; i < nr; i++)
        putchar(ch);
}

#define MAX_INTERVAL_ENTRY	1000
/* process period [start_time, start_time + time_scale) */
void single_digest(uint64_t start_time, uint64_t time_scale)
{
    int cpu;
    int cx_i[MAX_CPU_NR][MAX_INTERVAL_ENTRY];
    uint64_t cx_r[MAX_CPU_NR][MAX_INTERVAL_ENTRY];
    int cx_n[MAX_CPU_NR];
    int max_n;

    memset(cx_i, 0, sizeof(int) * MAX_CPU_NR * MAX_INTERVAL_ENTRY);
    memset(cx_r, 0, sizeof(uint64_t) * MAX_CPU_NR * MAX_INTERVAL_ENTRY);
    memset(cx_n, 0, sizeof(int) * MAX_CPU_NR);

    max_n = 0;
    for (cpu = 0; cpu < max_cpu_num; cpu++) {
        cx_n[cpu] = process(cpu, start_time, time_scale, cx_i[cpu], cx_r[cpu]);
        if (cx_n[cpu] > max_n)
            max_n = cx_n[cpu];
    }

    /* means how many lines will be consumed */
    while (--max_n >= 0) {
        for (cpu = 0; cpu < max_cpu_num; cpu++) {
            if (cx_n[cpu] > 0) {
                int i;
                /* find the available cx index */
                for (i = 0; i < MAX_INTERVAL_ENTRY && cx_i[cpu][i] == -1; i++)
                    ;
                if (i < MAX_INTERVAL_ENTRY) {
                    int len;
                    /* print it */
                    len= printf("C%d,%"PRIu64".%d", cx_i[cpu][i],
                                cx_r[cpu][i]/tsc2ms,
                                (unsigned int)(cx_r[cpu][i]/(tsc2ms/10))%10);
                    nr_putchar(width-len, ' ');

                    cx_i[cpu][i] = -1;
                } else
                    nr_putchar(width, ' ');

                cx_n[cpu]--;
            } else
                nr_putchar(width, ' ');
        }
        nr_putchar(1, '\n');
    }
}

void do_digest(uint64_t start, uint64_t end, uint64_t scale)
{
    int i;
    uint64_t ms = 0;
    uint64_t delta_ms = scale / tsc2ms;

    for (i = 0; i < max_cpu_num; i++) {
        int len = 0;
        len = printf("CPU%d", i);
        nr_putchar(width-len, ' ');
    }
    nr_putchar(1, '\n');
    while (start < end) {
        /* print --- xxx ms --- line */
        int off = (max_cpu_num * width - len_of_number(ms) - 2)/2;
        nr_putchar(off, '-');
        off += printf("%"PRIu64"ms", ms);
        off += printf(" (%"PRIu64")", start);
        nr_putchar(max_cpu_num * width-off, '-');
        nr_putchar(1, '\n');
        /* print each digest entries */
        single_digest(start, scale);

        start += scale;
        ms += delta_ms;
    }
}

/* [min, max) */
struct cond_rec {
    uint64_t min;
    uint64_t max;
    uint64_t cnt;
    uint64_t res;
};

void cond_rec_init(struct cond_rec *r, uint64_t min, uint64_t max)
{
    r->min = min;
    r->max = max;
    r->cnt = 0;
}

void cond_rec_inc(uint64_t cur, struct cond_rec *r)
{
    if (r->min <= cur && cur < r->max) {
        r->cnt++;
        r->res += cur;
    }
}

/* c	- current cpu to scan
 * cx	- cx state to track
 * a	- conditonal array
 * n	- how many entries there are
 */
void do_count_per_cpu(int c, int cx, struct cond_rec *a, int n)
{
    int i;
    /* find Cx entry first */
    i = 0;
    while (i < evt_len[c] && evt[c][i].cx == 0)
        i++;
    /* check evt[c][i] and evt[c][i+1] */
    while (i + 1 < evt_len[c]) {
        if (evt[c][i].cx == cx) {
            uint64_t len = evt[c][i+1].tsc - evt[c][i].tsc;
            int j;
            /* check for each condition */
            for (j = 0; j < n; j++)
                cond_rec_inc(len, a+j);
        }
        i++;
    }
}

struct cond_rec *make_cond_rec(uint64_t *a, int n)
{
    int i;
    struct cond_rec *t = malloc(sizeof(struct cond_rec) * (n+1));
    if (!t)
        return NULL;
    for (i = 0; i < n; i++) {
        t[i].max = a[i];
        t[i+1].min = a[i];
        t[i].cnt = 0;
        t[i].res = 0;
    }
    t[0].min = 0;
    t[n].max = (uint64_t) -1;
    t[n].cnt = 0;
    t[n].res = 0;

    return t;
}

uint64_t max_res[MAX_CPU_NR][MAX_CX_NR];
uint64_t min_res[MAX_CPU_NR][MAX_CX_NR];
uint64_t max_tm[MAX_CPU_NR][MAX_CX_NR];
uint64_t min_tm[MAX_CPU_NR][MAX_CX_NR];

void do_maxmin_per_cpu(int c)
{
    int i;
    /* find Cx entry first */
    i = 0;
    while (i < evt_len[c] && evt[c][i].cx == 0)
        i++;
    /* check evt[c][i] and evt[c][i+1] */
    while (i + 1 < evt_len[c]) {
        int cx = evt[c][i].cx;
        uint64_t len = evt[c][i+1].tsc - evt[c][i].tsc;
        if (len > max_res[c][cx]) {
            max_res[c][cx] = len;
            max_tm[c][cx] = evt[c][i].tsc;
        }
        if (len < min_res[c][cx]) {
            min_res[c][cx] = len;
            min_tm[c][cx] = evt[c][i].tsc;
        }
        i++;
    }
}

void do_maxmin(void)
{
    int i, j;
    /* init */
    for (i = 0; i < max_cpu_num; i++)
        for (j = 0; j < max_cx_num; j++) {
            max_res[i][j] = 0;
            min_res[i][j] = (uint64_t) -1;
        }

    for (i = 0; i < max_cpu_num; i++)
        do_maxmin_per_cpu(i);

    for (i = 0; i < max_cpu_num; i++) {
        printf("********* CPU%d *********\n", i);
        for (j = 0; j < max_cx_num; j++)
            if (max_res[i][j] == 0)
                printf("     not found                 ");
            else
                printf("%7"PRIu64"us (%15"PRIu64")    ", max_res[i][j]/tsc2us, max_tm[i][j]);
        printf("\n");
        for (j = 0; j < max_cx_num; j++)
            if (max_res[i][j] == 0)
                printf("     not found                 ");
            else
                printf("%7"PRIu64"us (%15"PRIu64")    ", min_res[i][j]/tsc2us, min_tm[i][j]);
        printf("\n\n");
    }
}

void do_count(void)
{
    uint64_t scale[100] = { 50UL, 100UL, 200UL, 400UL, 800UL, 1000UL };
    int a;
    int scale_len = 6;
    int len = 0;
    int i, j;

    printf("Please input the period:  (Ctrl+D to quit)\n");
    printf("The default is: 50 100 200 400 800 1000\n"
           "(unit is us, DO NOT specify ZERO as any entry, keep entries in INCREASING order.)\n");
    while (scanf("%d", &a) == 1) {
        scale[len++] = a;
        scale_len = len;
    }
    for (i = 0; i < scale_len; i++)
        scale[i] = scale[i] * tsc2us;

    for (i = 0; i < max_cpu_num; i++) {
        struct cond_rec *r[MAX_CX_NR];
        uint64_t sum[MAX_CX_NR];
        int k;

        printf("********** CPU%d *********\n", i);
        for (j = 0; j < max_cx_num; j++) {
            r[j] = make_cond_rec(scale, scale_len);
            if (!r[j])
                continue;
            do_count_per_cpu(i, j, r[j], scale_len+1);

            /* print */
            sum[j] = 0;
            for (k = 0; k < scale_len+1; k++)
                sum[j] += r[j][k].cnt;
            if (sum[j] == 0)
                sum[j] = 1;
        }
        printf("                              ");
        for (j = 0; j < max_cx_num; j++)
            printf("         C%d          ", j);
        printf("\n");
        for (k = 0; k < scale_len+1; k++) {
            if (k == scale_len)
                printf("%5"PRIu64" us ->   MAX us:", r[0][k].min/tsc2us);
            else
                printf("%5"PRIu64" us -> %5"PRIu64" us:",
                       r[0][k].min/tsc2us, r[0][k].max/tsc2us);
            for (j = 0; j < max_cx_num; j++)
                printf("    %10"PRIu64" (%5.2f%%)",
                       r[j][k].cnt, 100.0 * (double) r[j][k].cnt / (double)sum[j]);
            printf("\n");
        }
        for (j = 0; j < max_cx_num; j++)
            free(r[j]);
    }
}

static void do_px_count_per_cpu(int c, int px, struct cond_rec *cond, int n)
{
    int i, j;
    uint64_t len;

    i = 0;
    while (i+1 < evt_len[c]) {
        if (evt[c][i].px == px) {
            len = evt[c][i+1].tsc - evt[c][i].tsc;
            /* check each condition */
            for (j = 0; j < n; j++)
                cond_rec_inc(len, cond+j);
        }
        i++;
    }
}

void do_px_count(void)
{
    int a[100];
    uint64_t scale[100];
    int n, i, c, j;

    printf("Please input phases series: (Ctrl+D to quit)\n");
    printf("The default is 1, 2, 4, 8, 16, 32.\n");
    printf("Please be in increasing order.\n");
    scale[0] = tsc2phase;
    scale[1] = 2 * tsc2phase;
    scale[2] = 4 * tsc2phase;
    scale[3] = 8 * tsc2phase;
    scale[4] = 16 * tsc2phase;
    scale[5] = 32 * tsc2phase;
    n = 0;
    while (scanf("%d", &a[n]) == 1)
        n++;
    if (n) {
        for (i = 0; i < n; i++)
            scale[i] = a[i] * tsc2phase;
    } else
        n = 6;
    for (c = 0; c < max_cpu_num; c++) {
        struct cond_rec *p[MAX_PX_NR];
        int k;

        printf("***** CPU%d *****\n", c);
        for (i = 0; i < max_px_num; i++) {
            p[i] = make_cond_rec(scale, n);
            if (!p[i])
                continue;
            do_px_count_per_cpu(c, px_freq_table[i], p[i], n+1);
        }
        /* print */
        nr_putchar(16, ' ');
        for (j = 0; j < max_px_num; j++)
            printf("P%d\t", px_freq_table[j]);
        printf("\n");
        for (k = 0; k < n+1; k++) {
            if (k == n)
                printf("%5"PRIu64" ->  MAX : ", p[0][k].min/tsc2phase);
            else
                printf("%5"PRIu64" -> %5"PRIu64": ",
                       p[0][k].min/tsc2phase, p[0][k].max/tsc2phase);
            for (j = 0; j < max_px_num; j++) {
                printf("%"PRIu64"\t", p[j][k].cnt);
            }
            printf("\n");
        }
        printf("---\n");
        printf("Count:          ");
        for (j = 0; j < max_px_num; j++) {
            int sum = 0;
            for (k = 0; k < n+1; k++) {
                sum += (int)p[j][k].cnt;
            }
            /* print count */
            printf("%d\t", sum);
        }
        printf("\nAverage:        ");
        for (j = 0; j < max_px_num; j++) {
            int sum = 0;
            int s_res = 0;
            for (k = 0; k < n+1; k++) {
                sum += (int)p[j][k].cnt;
                s_res += (int)(p[j][k].res/tsc2phase);
            }
            /* print average */
            if (sum == 0)
                sum = 1;
            printf("%.1f\t", (double)s_res/(double)sum);
        }
        printf("\nTotal:          ");
        for (j = 0; j < max_px_num; j++) {
            int s_res = 0;
            for (k = 0; k < n+1; k++) {
                s_res += (int)(p[j][k].res/tsc2phase);
            }
            /* print total */
            printf("%d\t", s_res);
        }
        printf("\n");
    }
}

void do_breakevents(void)
{
    int br[MAX_CPU_NR][257];
    float pc[MAX_CPU_NR][257];
    int i, j, k, l;

    memset(br, 0, sizeof(int) * MAX_CPU_NR * 257);
    memset(pc, 0, sizeof(int) * MAX_CPU_NR * 257);

    for (i = 0; i < max_cpu_num; i++) {
        int sum = 0;
        for (j = 0; j < evt_len[i]; j++) {
            if (evt[i][j].cx == 0) {
                /* EXIT */
                /* collect breakevents information */
                int xx = 0;
                for (k = 0; k < 4; k++) {
                    int irq = evt[i][j].irqs[k];
                    if (irq) {
                        br[i][irq]++;
                        sum++;
                        xx++;
                    }
                }
                if (!xx) {
                    br[i][256]++;
                    sum++;
                }
            }
        }
        for (j = 0; j < 257; j++)
            pc[i][j] = 100.0 * br[i][j]/sum;
    }
    /* print the results */
    width = 13;
    printf("      ");
    for (i = 0; i < max_cpu_num; i++) {
        l = 0;
        l += printf("CPU%d", i);
        nr_putchar(width-l, ' ');
    }
    printf("\n");

    for (j = 0; j < 257; j++) {
        int n = 0;
        for (i = 0; i < max_cpu_num; i++)
            if (br[i][j])
                n++;
        if (n) {
            if (j == 256)
                printf("[N/A] ");
            else
                printf("[%03x] ", j);
            for (i = 0; i < max_cpu_num; i++) {
                if (br[i][j]) {
                    l = 0;
                    l += printf("%.1f%%,%d ", pc[i][j], br[i][j]);
                    nr_putchar(width-l, ' ');
                } else {
                    nr_putchar(width, ' ');
                }
            }
            printf("\n");
        }
    }
}

void single_cstate(int c, uint64_t t, uint64_t e,
                   uint64_t *a,
                   uint64_t *max_res,
                   uint64_t *min_res,
                   uint64_t *num);
void do_cstate(uint64_t start, uint64_t end)
{
    uint64_t cxtime[MAX_CX_NR];
    uint64_t max_res[MAX_CX_NR];
    uint64_t min_res[MAX_CX_NR];
    uint64_t num[MAX_CX_NR];
    int i, j;

    width = 20;
    printf("       ");
    for (i = 0; i < max_cx_num; i++) {
        int l = printf("C%d", i);
        nr_putchar(width-l, ' ');
    }
    printf("\n");

    for (i = 0; i < max_cpu_num; i++) {
        uint64_t sum = 0;
        single_cstate(i, start, end, cxtime, max_res, min_res, num);
        printf("CPU%2d ", i);
        for (j = 0; j < max_cx_num; j++)
            sum += cxtime[i];
        for (j = 0; j < max_cx_num; j++) {
            int l = printf("%.1f%%, %"PRIu64".%d, %"PRIu64".%d, %"PRIu64,
                           100.0 * cxtime[j]/sum,
                           max_res[j]/tsc2ms,
                           (unsigned int)(max_res[j]/(tsc2ms/10))%10,
                           min_res[j]/tsc2ms,
                           (unsigned int)(min_res[j]/(tsc2ms/10))%10,
                           cxtime[j]/num[j]/tsc2ms);
            nr_putchar(width - l, ' ');
        }
    }
}

void single_cstate(int c, uint64_t t, uint64_t e,
                   uint64_t *a,
                   uint64_t *max_res,
                   uint64_t *min_res,
                   uint64_t *num)
{
    int cx;
    int i;
    int first = 1;

    for (i = 0; i < max_cx_num; i++) {
        a[i] = 0;
        max_res[i] = 0;
        min_res[i] = (uint64_t) -1;
        num[i] = 0;
    }

    cx = determine_cx(c, t);
    i = 0;
    while (i < evt_len[c] && evt[c][i].tsc <= t)
        i++;
    for (; i+1 < evt_len[c] && evt[c][i].tsc <= e; i++) {
        int cxidx = evt[c][i].cx;
        uint64_t delta;

        if (first && cx >= 0) {
            /* Partial Cx, only once */
            first = 0;

            cxidx = cx;
            delta = evt[c][i].tsc - max(evt[c][i-1].tsc, t);
            a[cxidx] += delta;
            num[cxidx]++;

            /* update min and max residency */
            if (delta > max_res[cxidx])
                max_res[cxidx] = delta;
            if (delta < min_res[cxidx])
                min_res[cxidx] = delta;
        }
        delta = evt[c][i+1].tsc - evt[c][i].tsc;
        a[cxidx] += delta;
        num[cxidx]++;

        /* update min and max residency */
        if (delta > max_res[cxidx])
            max_res[cxidx] = delta;
        if (delta < min_res[cxidx])
            min_res[cxidx] = delta;
    }
}

void do_average_per_cpu(int c)
{
    int i;
    uint64_t tot[MAX_CX_NR] = { 0 };
    uint64_t cnt[MAX_CX_NR] = { 0 };
    uint64_t sum = 0;

    /* find Cx entry first */
    i = 0;
    while (i < evt_len[c] && evt[c][i].cx == 0)
        i++;
    /* check evt[c][i] and evt[c][i+1] */
    while (i + 1 < evt_len[c]) {
        uint64_t len = evt[c][i+1].tsc - evt[c][i].tsc;
        int cx = evt[c][i].cx;
        tot[cx] += len;
        cnt[cx]++;
        sum += len;
        i++;
    }
    /* prevent divide zero error */
    if (!sum)
        sum = 1;
    /* print */
    printf("CPU%d:\tResidency(ms)\t\tAvg Res(ms)\n", c);
    for (i = 0; i < max_cx_num; i++) {
        /* prevent divide zero error */
        if (!cnt[i])
            cnt[i] = 1;
        printf("  C%d\t%"PRIu64"\t(%6.2f%%)\t%.2f\n", i,
               tot[i]/tsc2ms, 100.0 * tot[i] / (double)sum,
               (double)tot[i]/cnt[i]/tsc2ms );
    }
    printf("\n");
}

void do_average(void)
{
    int i;

    for (i = 0; i < max_cpu_num; i++)
        do_average_per_cpu(i);
}

static void do_exp_ratio_per_cpu(int c)
{
    int i;
    uint64_t expected[MAX_CX_NR] = { 0 }, sum[MAX_CX_NR] = { 0 };

    i = 0;
    while (i < evt_len[c] && evt[c][i].cx == 0)
        i++;
    /* check evt[c][i] and evt[c][i+1] */
    while (i + 1 < evt_len[c]) {
        uint64_t len;
        int cx;

        if ((evt[c][i].cx == 0 && evt[c][i+1].cx == 0) ||
            (evt[c][i].cx > 0 && evt[c][i+1].cx > 0)) {
            i++;
            continue;
        }
        len = evt[c][i+1].tsc - evt[c][i].tsc;
        cx = evt[c][i].cx;
        if (cx > 0) {
            if ((len/tsc2us) <= evt[c][i].expected)
                expected[cx]++;
            sum[cx]++;
        }

        i++;
    }
    printf("********** CPU%d **********\n", c);
    for (i = 1; i < max_cx_num; i++) {
        if (sum[i] == 0)
            printf("C%d\t0\t0\t00.00%%\n", i);
        else
            printf("C%d\t%"PRIu64"\t%"PRIu64"\t%4.2f%%\n",
                   i, expected[i], sum[i], 100.0 * (double)expected[i]/(double)sum[i]);
    }
}

void do_exp_ratio(void)
{
    int i;

    if (!is_menu_gov_enabled) {
        printf("The file seems doesn't consists the expected/predicted information.\n");
        return;
    }

    printf("Cx\tearly\ttot\tratio(%%)\n");
    for (i = 0; i < max_cpu_num; i++)
        do_exp_ratio_per_cpu(i);
}

static void do_exp_pred_per_cpu(int c)
{
    int i;
    uint64_t expected[MAX_CX_NR] = { 0 }, sum[MAX_CX_NR] = { 0 };

    i = 0;
    while (i < evt_len[c] && evt[c][i].cx == 0)
        i++;
    /* check evt[c][i] and evt[c][i+1] */
    while (i + 1 < evt_len[c]) {
        int cx;

        if ((evt[c][i].cx == 0 && evt[c][i+1].cx == 0) ||
            (evt[c][i].cx > 0 && evt[c][i+1].cx > 0)) {
            i++;
            continue;
        }
        cx = evt[c][i].cx;
        if (cx > 0) {
            if (evt[c][i].expected <= evt[c][i].predicted)
                expected[cx]++;
            sum[cx]++;
        }

        i++;
    }
    printf("********** CPU%d **********\n", c);
    for (i = 1; i < max_cx_num; i++) {
        if (sum[i] == 0)
            printf("C%d\t0\t0\t00.00%%\n", i);
        else
            printf("C%d\t%"PRIu64"\t%"PRIu64"\t%4.2f%%\n",
                   i, expected[i], sum[i], 100.0 * (double)expected[i]/(double)sum[i]);
    }
}

void do_exp_pred(void)
{
    int i;

    if (!is_menu_gov_enabled) {
        printf("The file seems doesn't consists the expected/predicted information.\n");
        return;
    }

    printf("Cx\texp\ttot\tratio(%%)\n");
    for (i = 0; i < max_cpu_num; i++)
        do_exp_pred_per_cpu(i);
}

