/****************************************************************
 * secpol_tool.c
 *
 * Copyright (C) 2005 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Stefan Berger <stefanb@watson.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * sHype policy management tool. This code runs in a domain and
 *     manages the Xen security policy by interacting with the
 *     Xen access control module via a /proc/xen/privcmd proc-ioctl,
 *     which is translated into a acm_op hypercall into Xen.
 *
 * indent -i4 -kr -nut
 */


#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#include <xen/acm.h>
#include <xen/acm_ops.h>
#include <xen/linux/privcmd.h>

#define PERROR(_m, _a...) \
fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a ,	\
                errno, strerror(errno))

static inline int do_policycmd(int xc_handle, unsigned int cmd,
                               unsigned long data)
{
    return ioctl(xc_handle, cmd, data);
}

static inline int do_xen_hypercall(int xc_handle,
                                   privcmd_hypercall_t * hypercall)
{
    return do_policycmd(xc_handle,
                        IOCTL_PRIVCMD_HYPERCALL,
                        (unsigned long) hypercall);
}

static inline int do_acm_op(int xc_handle, acm_op_t * op)
{
    int ret = -1;
    privcmd_hypercall_t hypercall;

    op->interface_version = ACM_INTERFACE_VERSION;

    hypercall.op = __HYPERVISOR_acm_op;
    hypercall.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(*op)) != 0)
    {
        PERROR("Could not lock memory for Xen policy hypercall");
        goto out1;
    }

    if ((ret = do_xen_hypercall(xc_handle, &hypercall)) < 0)
    {
        if (errno == EACCES)
            fprintf(stderr, "ACM operation failed -- need to"
                    " rebuild the user-space tool set?\n");
        goto out2;
    }

  out2:(void) munlock(op, sizeof(*op));
  out1:return ret;
}

/*************************** DUMPS *******************************/

void acm_dump_chinesewall_buffer(void *buf, int buflen)
{

    struct acm_chwall_policy_buffer *cwbuf =
        (struct acm_chwall_policy_buffer *) buf;
    domaintype_t *ssids, *conflicts, *running_types, *conflict_aggregate;
    int i, j;


    if (htonl(cwbuf->policy_code) != ACM_CHINESE_WALL_POLICY)
    {
        printf("CHINESE WALL POLICY CODE not found ERROR!!\n");
        return;
    }
    printf("\n\nChinese Wall policy:\n");
    printf("====================\n");
    printf("Policy version= %x.\n", ntohl(cwbuf->policy_version));
    printf("Max Types     = %x.\n", ntohl(cwbuf->chwall_max_types));
    printf("Max Ssidrefs  = %x.\n", ntohl(cwbuf->chwall_max_ssidrefs));
    printf("Max ConfSets  = %x.\n", ntohl(cwbuf->chwall_max_conflictsets));
    printf("Ssidrefs Off  = %x.\n", ntohl(cwbuf->chwall_ssid_offset));
    printf("Conflicts Off = %x.\n",
           ntohl(cwbuf->chwall_conflict_sets_offset));
    printf("Runing T. Off = %x.\n",
           ntohl(cwbuf->chwall_running_types_offset));
    printf("C. Agg. Off   = %x.\n",
           ntohl(cwbuf->chwall_conflict_aggregate_offset));
    printf("\nSSID To CHWALL-Type matrix:\n");

    ssids = (domaintype_t *) (buf + ntohl(cwbuf->chwall_ssid_offset));
    for (i = 0; i < ntohl(cwbuf->chwall_max_ssidrefs); i++)
    {
        printf("\n   ssidref%2x:  ", i);
        for (j = 0; j < ntohl(cwbuf->chwall_max_types); j++)
            printf("%02x ",
                   ntohs(ssids[i * ntohl(cwbuf->chwall_max_types) + j]));
    }
    printf("\n\nConfict Sets:\n");
    conflicts =
        (domaintype_t *) (buf + ntohl(cwbuf->chwall_conflict_sets_offset));
    for (i = 0; i < ntohl(cwbuf->chwall_max_conflictsets); i++)
    {
        printf("\n   c-set%2x:    ", i);
        for (j = 0; j < ntohl(cwbuf->chwall_max_types); j++)
            printf("%02x ",
                   ntohs(conflicts
                         [i * ntohl(cwbuf->chwall_max_types) + j]));
    }
    printf("\n");

    printf("\nRunning\nTypes:         ");
    if (ntohl(cwbuf->chwall_running_types_offset))
    {
        running_types =
            (domaintype_t *) (buf +
                              ntohl(cwbuf->chwall_running_types_offset));
        for (i = 0; i < ntohl(cwbuf->chwall_max_types); i++)
        {
            printf("%02x ", ntohs(running_types[i]));
        }
        printf("\n");
    } else {
        printf("Not Reported!\n");
    }
    printf("\nConflict\nAggregate Set: ");
    if (ntohl(cwbuf->chwall_conflict_aggregate_offset))
    {
        conflict_aggregate =
            (domaintype_t *) (buf +
                              ntohl(cwbuf->chwall_conflict_aggregate_offset));
        for (i = 0; i < ntohl(cwbuf->chwall_max_types); i++)
        {
            printf("%02x ", ntohs(conflict_aggregate[i]));
        }
        printf("\n\n");
    } else {
        printf("Not Reported!\n");
    }
}

void acm_dump_ste_buffer(void *buf, int buflen)
{

    struct acm_ste_policy_buffer *stebuf =
        (struct acm_ste_policy_buffer *) buf;
    domaintype_t *ssids;
    int i, j;


    if (ntohl(stebuf->policy_code) != ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY) {
        printf("SIMPLE TYPE ENFORCEMENT POLICY CODE not found ERROR!!\n");
        return;
    }
    printf("\nSimple Type Enforcement policy:\n");
    printf("===============================\n");
    printf("Policy version= %x.\n", ntohl(stebuf->policy_version));
    printf("Max Types     = %x.\n", ntohl(stebuf->ste_max_types));
    printf("Max Ssidrefs  = %x.\n", ntohl(stebuf->ste_max_ssidrefs));
    printf("Ssidrefs Off  = %x.\n", ntohl(stebuf->ste_ssid_offset));
    printf("\nSSID To STE-Type matrix:\n");

    ssids = (domaintype_t *) (buf + ntohl(stebuf->ste_ssid_offset));
    for (i = 0; i < ntohl(stebuf->ste_max_ssidrefs); i++)
    {
        printf("\n   ssidref%2x: ", i);
        for (j = 0; j < ntohl(stebuf->ste_max_types); j++)
            printf("%02x ", ntohs(ssids[i * ntohl(stebuf->ste_max_types) + j]));
    }
    printf("\n\n");
}

void acm_dump_policy_buffer(void *buf, int buflen)
{
    struct acm_policy_buffer *pol = (struct acm_policy_buffer *) buf;

    printf("\nPolicy dump:\n");
    printf("============\n");
    printf("PolicyVer = %x.\n", ntohl(pol->policy_version));
    printf("Magic     = %x.\n", ntohl(pol->magic));
    printf("Len       = %x.\n", ntohl(pol->len));
    printf("Primary   = %s (c=%x, off=%x).\n",
           ACM_POLICY_NAME(ntohl(pol->primary_policy_code)),
           ntohl(pol->primary_policy_code),
           ntohl(pol->primary_buffer_offset));
    printf("Secondary = %s (c=%x, off=%x).\n",
           ACM_POLICY_NAME(ntohl(pol->secondary_policy_code)),
           ntohl(pol->secondary_policy_code),
           ntohl(pol->secondary_buffer_offset));
    switch (ntohl(pol->primary_policy_code))
    {
    case ACM_CHINESE_WALL_POLICY:
        acm_dump_chinesewall_buffer(buf +
                                    ntohl(pol->primary_buffer_offset),
                                    ntohl(pol->len) -
                                    ntohl(pol->primary_buffer_offset));
        break;

    case ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY:
        acm_dump_ste_buffer(buf + ntohl(pol->primary_buffer_offset),
                            ntohl(pol->len) -
                            ntohl(pol->primary_buffer_offset));
        break;

    case ACM_NULL_POLICY:
        printf("Primary policy is NULL Policy (n/a).\n");
        break;

    default:
        printf("UNKNOWN POLICY!\n");
    }

    switch (ntohl(pol->secondary_policy_code))
    {
    case ACM_CHINESE_WALL_POLICY:
        acm_dump_chinesewall_buffer(buf +
                                    ntohl(pol->secondary_buffer_offset),
                                    ntohl(pol->len) -
                                    ntohl(pol->secondary_buffer_offset));
        break;

    case ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY:
        acm_dump_ste_buffer(buf + ntohl(pol->secondary_buffer_offset),
                            ntohl(pol->len) -
                            ntohl(pol->secondary_buffer_offset));
        break;

    case ACM_NULL_POLICY:
        printf("Secondary policy is NULL Policy (n/a).\n");
        break;

    default:
        printf("UNKNOWN POLICY!\n");
    }
}

/*************************** set policy ****************************/

int acm_domain_set_chwallpolicy(void *bufstart, int buflen)
{
#define CWALL_MAX_SSIDREFS      	6
#define CWALL_MAX_TYPES             10
#define CWALL_MAX_CONFLICTSETS		2

    struct acm_chwall_policy_buffer *chwall_bin_pol =
        (struct acm_chwall_policy_buffer *) bufstart;
    domaintype_t *ssidrefs, *conflicts;
    int ret = 0;
    int j;

    chwall_bin_pol->chwall_max_types = htonl(CWALL_MAX_TYPES);
    chwall_bin_pol->chwall_max_ssidrefs = htonl(CWALL_MAX_SSIDREFS);
    chwall_bin_pol->policy_code = htonl(ACM_CHINESE_WALL_POLICY);
    chwall_bin_pol->policy_version = htonl(ACM_CHWALL_VERSION);
    chwall_bin_pol->chwall_ssid_offset =
        htonl(sizeof(struct acm_chwall_policy_buffer));
    chwall_bin_pol->chwall_max_conflictsets =
        htonl(CWALL_MAX_CONFLICTSETS);
    chwall_bin_pol->chwall_conflict_sets_offset =
        htonl(ntohl(chwall_bin_pol->chwall_ssid_offset) +
              sizeof(domaintype_t) * CWALL_MAX_SSIDREFS * CWALL_MAX_TYPES);
    chwall_bin_pol->chwall_running_types_offset = 0;    /* not set */
    chwall_bin_pol->chwall_conflict_aggregate_offset = 0;       /* not set */
    ret += sizeof(struct acm_chwall_policy_buffer);
    /* now push example ssids into the buffer (max_ssidrefs x max_types entries) */
    /* check buffer size */
    if ((buflen - ret) <
        (CWALL_MAX_TYPES * CWALL_MAX_SSIDREFS * sizeof(domaintype_t)))
        return -1;              /* not enough space */

    ssidrefs = (domaintype_t *) (bufstart +
                          ntohl(chwall_bin_pol->chwall_ssid_offset));
    memset(ssidrefs, 0,
           CWALL_MAX_TYPES * CWALL_MAX_SSIDREFS * sizeof(domaintype_t));

    /* now set type j-1 for ssidref i+1 */
    for (j = 0; j <= CWALL_MAX_SSIDREFS; j++)
        if ((0 < j) && (j <= CWALL_MAX_TYPES))
            ssidrefs[j * CWALL_MAX_TYPES + j - 1] = htons(1);

    ret += CWALL_MAX_TYPES * CWALL_MAX_SSIDREFS * sizeof(domaintype_t);
    if ((buflen - ret) <
        (CWALL_MAX_CONFLICTSETS * CWALL_MAX_TYPES * sizeof(domaintype_t)))
        return -1;              /* not enough space */

    /* now the chinese wall policy conflict sets */
    conflicts = (domaintype_t *) (bufstart +
                                  ntohl(chwall_bin_pol->
                                        chwall_conflict_sets_offset));
    memset((void *) conflicts, 0,
           CWALL_MAX_CONFLICTSETS * CWALL_MAX_TYPES *
           sizeof(domaintype_t));
    /* just 1 conflict set [0]={2,3}, [1]={1,5,6} */
    if (CWALL_MAX_TYPES > 3)
    {
        conflicts[2] = htons(1);
        conflicts[3] = htons(1);        /* {2,3} */
        conflicts[CWALL_MAX_TYPES + 1] = htons(1);
        conflicts[CWALL_MAX_TYPES + 5] = htons(1);
        conflicts[CWALL_MAX_TYPES + 6] = htons(1);      /* {0,5,6} */
    }
    ret += sizeof(domaintype_t) * CWALL_MAX_CONFLICTSETS * CWALL_MAX_TYPES;
    return ret;
}

int acm_domain_set_stepolicy(void *bufstart, int buflen)
{
#define STE_MAX_SSIDREFS        6
#define STE_MAX_TYPES  	        5

    struct acm_ste_policy_buffer *ste_bin_pol =
        (struct acm_ste_policy_buffer *) bufstart;
    domaintype_t *ssidrefs;
    int j, ret = 0;

    ste_bin_pol->ste_max_types = htonl(STE_MAX_TYPES);
    ste_bin_pol->ste_max_ssidrefs = htonl(STE_MAX_SSIDREFS);
    ste_bin_pol->policy_code = htonl(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY);
    ste_bin_pol->policy_version = htonl(ACM_STE_VERSION);
    ste_bin_pol->ste_ssid_offset =
        htonl(sizeof(struct acm_ste_policy_buffer));
    ret += sizeof(struct acm_ste_policy_buffer);
    /* check buffer size */
    if ((buflen - ret) <
        (STE_MAX_TYPES * STE_MAX_SSIDREFS * sizeof(domaintype_t)))
        return -1;              /* not enough space */

    ssidrefs =
        (domaintype_t *) (bufstart + ntohl(ste_bin_pol->ste_ssid_offset));
    memset(ssidrefs, 0,
           STE_MAX_TYPES * STE_MAX_SSIDREFS * sizeof(domaintype_t));
    /* all types 1 for ssidref 1 */
    for (j = 0; j < STE_MAX_TYPES; j++)
        ssidrefs[1 * STE_MAX_TYPES + j] = htons(1);
    /* now set type j-1 for ssidref j */
    for (j = 0; j < STE_MAX_SSIDREFS; j++)
        if ((0 < j) && (j <= STE_MAX_TYPES))
            ssidrefs[j * STE_MAX_TYPES + j - 1] = htons(1);
    ret += STE_MAX_TYPES * STE_MAX_SSIDREFS * sizeof(domaintype_t);
    return ret;
}

#define MAX_PUSH_BUFFER 	16384
u8 push_buffer[MAX_PUSH_BUFFER];

int acm_domain_setpolicy(int xc_handle)
{
    int ret;
    struct acm_policy_buffer *bin_pol;
    acm_op_t op;

    /* future: read policy from file and set it */
    bin_pol = (struct acm_policy_buffer *) push_buffer;
    bin_pol->policy_version = htonl(ACM_POLICY_VERSION);
    bin_pol->magic = htonl(ACM_MAGIC);
    bin_pol->primary_policy_code = htonl(ACM_CHINESE_WALL_POLICY);
    bin_pol->secondary_policy_code =
        htonl(ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY);

    bin_pol->len = htonl(sizeof(struct acm_policy_buffer));
    bin_pol->primary_buffer_offset = htonl(ntohl(bin_pol->len));
    ret =
        acm_domain_set_chwallpolicy(push_buffer +
                                    ntohl(bin_pol->primary_buffer_offset),
                                    MAX_PUSH_BUFFER -
                                    ntohl(bin_pol->primary_buffer_offset));
    if (ret < 0)
    {
        printf("ERROR creating chwallpolicy buffer.\n");
        return -1;
    }
    bin_pol->len = htonl(ntohl(bin_pol->len) + ret);
    bin_pol->secondary_buffer_offset = htonl(ntohl(bin_pol->len));
    ret = acm_domain_set_stepolicy(push_buffer +
                                 ntohl(bin_pol->secondary_buffer_offset),
                                 MAX_PUSH_BUFFER -
                                 ntohl(bin_pol->secondary_buffer_offset));
    if (ret < 0)
    {
        printf("ERROR creating chwallpolicy buffer.\n");
        return -1;
    }
    bin_pol->len = htonl(ntohl(bin_pol->len) + ret);

    /* dump it and then push it down into xen/acm */
    acm_dump_policy_buffer(push_buffer, ntohl(bin_pol->len));

    op.cmd = ACM_SETPOLICY;
    op.interface_version = ACM_INTERFACE_VERSION;
    op.u.setpolicy.pushcache = (void *) push_buffer;
    op.u.setpolicy.pushcache_size = ntohl(bin_pol->len);
    ret = do_acm_op(xc_handle, &op);

    if (ret)
        printf("ERROR setting policy. Use 'xm dmesg' to see details.\n");
    else
        printf("Successfully changed policy.\n");

    return ret;
}

/******************************* get policy ******************************/

#define PULL_CACHE_SIZE		8192
u8 pull_buffer[PULL_CACHE_SIZE];
int acm_domain_getpolicy(int xc_handle)
{
    acm_op_t op;
    int ret;

    memset(pull_buffer, 0x00, sizeof(pull_buffer));
    op.cmd = ACM_GETPOLICY;
    op.interface_version = ACM_INTERFACE_VERSION;
    op.u.getpolicy.pullcache = (void *) pull_buffer;
    op.u.getpolicy.pullcache_size = sizeof(pull_buffer);
    ret = do_acm_op(xc_handle, &op);
    /* dump policy  */
    acm_dump_policy_buffer(pull_buffer, sizeof(pull_buffer));
    return ret;
}

/************************ load binary policy ******************************/

int acm_domain_loadpolicy(int xc_handle, const char *filename)
{
    struct stat mystat;
    int ret, fd;
    off_t len;
    u8 *buffer;

    if ((ret = stat(filename, &mystat)))
    {
        printf("File %s not found.\n", filename);
        goto out;
    }

    len = mystat.st_size;
    if ((buffer = malloc(len)) == NULL)
    {
        ret = -ENOMEM;
        goto out;
    }
    if ((fd = open(filename, O_RDONLY)) <= 0)
    {
        ret = -ENOENT;
        printf("File %s not found.\n", filename);
        goto free_out;
    }
    if (len == read(fd, buffer, len))
    {
        acm_op_t op;
        /* dump it and then push it down into xen/acm */
        acm_dump_policy_buffer(buffer, len);
        op.cmd = ACM_SETPOLICY;
        op.interface_version = ACM_INTERFACE_VERSION;
        op.u.setpolicy.pushcache = (void *) buffer;
        op.u.setpolicy.pushcache_size = len;
        ret = do_acm_op(xc_handle, &op);

        if (ret)
            printf
                ("ERROR setting policy. Use 'xm dmesg' to see details.\n");
        else
            printf("Successfully changed policy.\n");

    } else {
        ret = -1;
    }
    close(fd);
  free_out:
    free(buffer);
  out:
    return ret;
}

/************************ dump hook statistics ******************************/
void dump_ste_stats(struct acm_ste_stats_buffer *ste_stats)
{
    printf("STE-Policy Security Hook Statistics:\n");
    printf("ste: event_channel eval_count      = %d\n",
           ntohl(ste_stats->ec_eval_count));
    printf("ste: event_channel denied_count    = %d\n",
           ntohl(ste_stats->ec_denied_count));
    printf("ste: event_channel cache_hit_count = %d\n",
           ntohl(ste_stats->ec_cachehit_count));
    printf("ste:\n");
    printf("ste: grant_table   eval_count      = %d\n",
           ntohl(ste_stats->gt_eval_count));
    printf("ste: grant_table   denied_count    = %d\n",
           ntohl(ste_stats->gt_denied_count));
    printf("ste: grant_table   cache_hit_count = %d\n",
           ntohl(ste_stats->gt_cachehit_count));
}

#define PULL_STATS_SIZE		8192
int acm_domain_dumpstats(int xc_handle)
{
    u8 stats_buffer[PULL_STATS_SIZE];
    acm_op_t op;
    int ret;
    struct acm_stats_buffer *stats;

    memset(stats_buffer, 0x00, sizeof(stats_buffer));
    op.cmd = ACM_DUMPSTATS;
    op.interface_version = ACM_INTERFACE_VERSION;
    op.u.dumpstats.pullcache = (void *) stats_buffer;
    op.u.dumpstats.pullcache_size = sizeof(stats_buffer);
    ret = do_acm_op(xc_handle, &op);

    if (ret < 0)
    {
        printf("ERROR dumping policy stats. Use 'xm dmesg' to see details.\n");
        return ret;
    }
    stats = (struct acm_stats_buffer *) stats_buffer;

    printf("\nPolicy dump:\n");
    printf("============\n");
    printf("Magic     = %x.\n", ntohl(stats->magic));
    printf("Len       = %x.\n", ntohl(stats->len));

    switch (ntohl(stats->primary_policy_code))
    {
    case ACM_NULL_POLICY:
        printf("NULL Policy: No statistics apply.\n");
        break;

    case ACM_CHINESE_WALL_POLICY:
        printf("Chinese Wall Policy: No statistics apply.\n");
        break;

    case ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY:
        dump_ste_stats((struct acm_ste_stats_buffer *) (stats_buffer +
                                                        ntohl(stats->
                                                              primary_stats_offset)));
        break;

    default:
        printf("UNKNOWN PRIMARY POLICY ERROR!\n");
    }

    switch (ntohl(stats->secondary_policy_code))
    {
    case ACM_NULL_POLICY:
        printf("NULL Policy: No statistics apply.\n");
        break;

    case ACM_CHINESE_WALL_POLICY:
        printf("Chinese Wall Policy: No statistics apply.\n");
        break;

    case ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY:
        dump_ste_stats((struct acm_ste_stats_buffer *) (stats_buffer +
                                                        ntohl(stats->
                                                              secondary_stats_offset)));
        break;

    default:
        printf("UNKNOWN SECONDARY POLICY ERROR!\n");
    }
    return ret;
}

/***************************** main **************************************/

void usage(char *progname)
{
    printf("Use: %s \n"
           "\t setpolicy\n"
           "\t getpolicy\n"
           "\t dumpstats\n"
           "\t loadpolicy <binary policy file>\n", progname);
    exit(-1);
}

int main(int argc, char **argv)
{

    int acm_cmd_fd, ret = 0;

    if (argc < 2)
        usage(argv[0]);

    if ((acm_cmd_fd = open("/proc/xen/privcmd", O_RDONLY)) <= 0)
    {
        printf("ERROR: Could not open xen privcmd device!\n");
        exit(-1);
    }

    if (!strcmp(argv[1], "setpolicy"))
    {
        if (argc != 2)
            usage(argv[0]);
        ret = acm_domain_setpolicy(acm_cmd_fd);
    } else if (!strcmp(argv[1], "getpolicy")) {
        if (argc != 2)
            usage(argv[0]);
        ret = acm_domain_getpolicy(acm_cmd_fd);
    } else if (!strcmp(argv[1], "loadpolicy")) {
        if (argc != 3)
            usage(argv[0]);
        ret = acm_domain_loadpolicy(acm_cmd_fd, argv[2]);
    } else if (!strcmp(argv[1], "dumpstats")) {
        if (argc != 2)
            usage(argv[0]);
        ret = acm_domain_dumpstats(acm_cmd_fd);
    } else
        usage(argv[0]);

    close(acm_cmd_fd);
    return ret;
}
