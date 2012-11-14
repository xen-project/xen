/*
 * Parse output from tmem-list and reformat to human-readable
 *
 * NOTE: NEVER delete a parse call as this file documents backwards
 * compatibility for older versions of tmem-list and we don't want to
 * accidentally reuse an old tag
 *
 * Copyright (c) 2009, Dan Magenheimer, Oracle Corp.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define BUFSIZE 4096
#define PAGE_SIZE 4096

unsigned long long parse(char *s,char *match)
{
    char *s1 = strstr(s,match);
    unsigned long long ret;

    if ( s1 == NULL )
        return 0LL;
    s1 += 2;
    if ( *s1++ != ':' )
        return 0LL;
    sscanf(s1,"%llu",&ret);
    return ret;
}

unsigned long long parse_hex(char *s,char *match)
{
    char *s1 = strstr(s,match);
    unsigned long long ret;

    if ( s1 == NULL )
        return 0LL;
    s1 += 2;
    if ( *s1++ != ':' )
        return 0LL;
    sscanf(s1,"%llx",&ret);
    return ret;
}

unsigned long long parse2(char *s,char *match1, char *match2)
{
    char match[3];
    match[0] = *match1;
    match[1] = *match2;
    match[2] = '\0';
    return parse(s,match);
}

void parse_string(char *s,char *match, char *buf, int len)
{
    char *s1 = strstr(s,match);
    int i;

    if ( s1 == NULL )
        return;
    s1 += 2;
    if ( *s1++ != ':' )
        return;
    for ( i = 0; i < len; i++ )
        *buf++ = *s1++;
}

void parse_sharers(char *s, char *match, char *buf, int len)
{
    char *s1 = strstr(s,match);
    char *b = buf;

    if ( s1 == NULL )
        return;
    while ( s1 )
    {
        s1 += 2;
        if (*s1++ != ':')
            return;
        while (*s1 >= '0' && *s1 <= '9')
            *b++ = *s1++;
        *b++ = ',';
        s1 = strstr(s1,match);
    }
    if ( b != buf )
        *--b = '\0';
}

void parse_global(char *s)
{
    unsigned long long total_ops = parse(s,"Tt");
    unsigned long long errored_ops = parse(s,"Te");
    unsigned long long failed_copies = parse(s,"Cf");
    unsigned long long alloc_failed = parse(s,"Af");
    unsigned long long alloc_page_failed = parse(s,"Pf");
    unsigned long long avail_pages = parse(s,"Ta");
    unsigned long long low_on_memory = parse(s,"Lm");
    unsigned long long evicted_pgs = parse(s,"Et");
    unsigned long long evict_attempts = parse(s,"Ea");
    unsigned long long relinq_pgs = parse(s,"Rt");
    unsigned long long relinq_attempts = parse(s,"Ra");
    unsigned long long max_evicts_per_relinq = parse(s,"Rx");
    unsigned long long total_flush_pool = parse(s,"Fp");
    unsigned long long global_eph_count = parse(s,"Ec");
    unsigned long long global_eph_max = parse(s,"Em");
    unsigned long long obj_count = parse(s,"Oc");
    unsigned long long obj_max = parse(s,"Om");
    unsigned long long rtree_node_count = parse(s,"Nc");
    unsigned long long rtree_node_max = parse(s,"Nm");
    unsigned long long pgp_count = parse(s,"Pc");
    unsigned long long pgp_max = parse(s,"Pm");
    unsigned long long page_count = parse(s,"Fc");
    unsigned long long max_page_count = parse(s,"Fm");
    unsigned long long pcd_count = parse(s,"Sc");
    unsigned long long max_pcd_count = parse(s,"Sm");
    unsigned long long pcd_tot_tze_size = parse(s,"Zt");
    unsigned long long pcd_tot_csize = parse(s,"Gz");
    unsigned long long deduped_puts = parse(s,"Gd");
    unsigned long long tot_good_eph_puts = parse(s,"Ep");

    printf("total tmem ops=%llu (errors=%llu) -- tmem pages avail=%llu\n",
           total_ops, errored_ops, avail_pages);
    printf("datastructs: objs=%llu (max=%llu) pgps=%llu (max=%llu) "
           "nodes=%llu (max=%llu) pages=%llu (max=%llu) ",
           obj_count, obj_max, pgp_count, pgp_max,
           rtree_node_count, rtree_node_max,
           page_count,max_page_count);
    if (max_pcd_count != 0 && global_eph_count != 0 && tot_good_eph_puts != 0) {
           printf("pcds=%llu (max=%llu) ",
               pcd_count,max_pcd_count);
           printf("deduped: avg=%4.2f%% (curr=%4.2f%%) ",
                   ((deduped_puts*1.0)/tot_good_eph_puts)*100,
                   (1.0-(pcd_count*1.0)/global_eph_count)*100);
    }
    if (pcd_count != 0)
    {
           if (pcd_tot_tze_size && (pcd_tot_tze_size < pcd_count*PAGE_SIZE))
               printf("tze savings=%4.2f%% ",
                   (1.0-(pcd_tot_tze_size*1.0)/(pcd_count*PAGE_SIZE))*100);
           if (pcd_tot_csize && (pcd_tot_csize < pcd_count*PAGE_SIZE))
               printf("compression savings=%4.2f%% ",
                   (1.0-(pcd_tot_csize*1.0)/(pcd_count*PAGE_SIZE))*100);
    }
    printf("\n");
    printf("misc: failed_copies=%llu alloc_failed=%llu alloc_page_failed=%llu "
           "low_mem=%llu evicted=%llu/%llu relinq=%llu/%llu, "
           "max_evicts_per_relinq=%llu, flush_pools=%llu, "
           "eph_count=%llu, eph_max=%llu\n",
           failed_copies, alloc_failed, alloc_page_failed, low_on_memory,
           evicted_pgs, evict_attempts, relinq_pgs, relinq_attempts,
           max_evicts_per_relinq, total_flush_pool,
           global_eph_count, global_eph_max);
}

#define PARSE_CYC_COUNTER(s,x,prefix) unsigned long long \
   x##_count = parse2(s,prefix,"n"), \
   x##_sum_cycles = parse2(s,prefix,"t"), \
   x##_max_cycles = parse2(s,prefix,"x"), \
   x##_min_cycles = parse2(s,prefix,"m")
#define PRINTF_CYC_COUNTER(x,text) \
  if (x##_count) printf(text" avg=%llu, max=%llu, " \
  "min=%llu, samples=%llu\n", \
  x##_sum_cycles ? (x##_sum_cycles/x##_count) : 0, \
  x##_max_cycles, x##_min_cycles, x##_count)

void parse_time_stats(char *s)
{
    PARSE_CYC_COUNTER(s,succ_get,"G");
    PARSE_CYC_COUNTER(s,succ_put,"P");
    PARSE_CYC_COUNTER(s,non_succ_get,"g");
    PARSE_CYC_COUNTER(s,non_succ_put,"p");
    PARSE_CYC_COUNTER(s,flush,"F");
    PARSE_CYC_COUNTER(s,flush_obj,"O");
    PARSE_CYC_COUNTER(s,pg_copy,"C");
    PARSE_CYC_COUNTER(s,compress,"c");
    PARSE_CYC_COUNTER(s,decompress,"d");

    PRINTF_CYC_COUNTER(succ_get,"succ get cycles:");
    PRINTF_CYC_COUNTER(succ_put,"succ put cycles:");
    PRINTF_CYC_COUNTER(non_succ_get,"failed get cycles:");
    PRINTF_CYC_COUNTER(non_succ_put,"failed put cycles:");
    PRINTF_CYC_COUNTER(flush,"flush cycles:");
    PRINTF_CYC_COUNTER(flush_obj,"flush_obj cycles:");
    PRINTF_CYC_COUNTER(pg_copy,"page copy cycles:");
    PRINTF_CYC_COUNTER(compress,"compression cycles:");
    PRINTF_CYC_COUNTER(decompress,"decompression cycles:");
}

void parse_client(char *s)
{
    unsigned long cli_id = parse(s,"CI");
    unsigned long weight = parse(s,"ww");
    unsigned long cap = parse(s,"ca");
    unsigned long compress = parse(s,"co");
    unsigned long frozen = parse(s,"fr");
    unsigned long long eph_count = parse(s,"Ec");
    unsigned long long max_eph_count = parse(s,"Em");
    unsigned long long compressed_pages = parse(s,"cp");
    unsigned long long compressed_sum_size = parse(s,"cb");
    unsigned long long compress_poor = parse(s,"cn");
    unsigned long long compress_nomem = parse(s,"cm");
    unsigned long long total_cycles = parse(s,"Tc");
    unsigned long long succ_eph_gets = parse(s,"Ge");
    unsigned long long succ_pers_puts = parse(s,"Pp");
    unsigned long long succ_pers_gets = parse(s,"Gp");

    printf("domid%lu: weight=%lu,cap=%lu,compress=%d,frozen=%d,"
           "total_cycles=%llu,succ_eph_gets=%llu,"
           "succ_pers_puts=%llu,succ_pers_gets=%llu,"
           "eph_count=%llu,max_eph=%llu,"
           "compression ratio=%lu%% (samples=%llu,poor=%llu,nomem=%llu)\n",
           cli_id, weight, cap, compress?1:0, frozen?1:0,
           total_cycles, succ_eph_gets, succ_pers_puts, succ_pers_gets, 
           eph_count, max_eph_count,
           compressed_pages ?  (long)((compressed_sum_size*100LL) /
                                      (compressed_pages*PAGE_SIZE)) : 0,
           compressed_pages, compress_poor, compress_nomem);

}

void parse_pool(char *s)
{
    char pool_type[3];
    unsigned long cli_id = parse(s,"CI");
    unsigned long pool_id = parse(s,"PI");
    unsigned long long pgp_count = parse(s,"Pc");
    unsigned long long max_pgp_count = parse(s,"Pm");
    unsigned long long obj_count = parse(s,"Oc");
    unsigned long long max_obj_count = parse(s,"Om");
    unsigned long long objnode_count = parse(s,"Nc");
    unsigned long long max_objnode_count = parse(s,"Nm");
    unsigned long long good_puts = parse(s,"ps");
    unsigned long long puts = parse(s,"pt");
    unsigned long long no_mem_puts = parse(s,"px");
    unsigned long long dup_puts_flushed = parse(s,"pd");
    unsigned long long dup_puts_replaced = parse(s,"pr");
    unsigned long long found_gets = parse(s,"gs");
    unsigned long long gets = parse(s,"gt");
    unsigned long long flushs_found = parse(s,"fs");
    unsigned long long flushs = parse(s,"ft");
    unsigned long long flush_objs_found = parse(s,"os");
    unsigned long long flush_objs = parse(s,"ot");

    parse_string(s,"PT",pool_type,2);
    pool_type[2] = '\0';
    if (pool_type[1] == 'S')
        return; /* no need to repeat print data for shared pools */
    printf("domid%lu,id%lu[%s]:pgp=%llu(max=%llu) obj=%llu(%llu) "
           "objnode=%llu(%llu) puts=%llu/%llu/%llu(dup=%llu/%llu) "
           "gets=%llu/%llu(%llu%%) "
           "flush=%llu/%llu flobj=%llu/%llu\n",
           cli_id, pool_id, pool_type,
           pgp_count, max_pgp_count, obj_count, max_obj_count,
           objnode_count, max_objnode_count,
           good_puts, puts, no_mem_puts, 
           dup_puts_flushed, dup_puts_replaced,
           found_gets, gets,
           gets ? (found_gets*100LL)/gets : 0,
           flushs_found, flushs, flush_objs_found, flush_objs);

}

void parse_shared_pool(char *s)
{
    char pool_type[3];
    char buf[BUFSIZE];
    unsigned long pool_id = parse(s,"PI");
    unsigned long long uid0 = parse_hex(s,"U0");
    unsigned long long uid1 = parse_hex(s,"U1");
    unsigned long long pgp_count = parse(s,"Pc");
    unsigned long long max_pgp_count = parse(s,"Pm");
    unsigned long long obj_count = parse(s,"Oc");
    unsigned long long max_obj_count = parse(s,"Om");
    unsigned long long objnode_count = parse(s,"Nc");
    unsigned long long max_objnode_count = parse(s,"Nm");
    unsigned long long good_puts = parse(s,"ps");
    unsigned long long puts = parse(s,"pt");
    unsigned long long no_mem_puts = parse(s,"px");
    unsigned long long dup_puts_flushed = parse(s,"pd");
    unsigned long long dup_puts_replaced = parse(s,"pr");
    unsigned long long found_gets = parse(s,"gs");
    unsigned long long gets = parse(s,"gt");
    unsigned long long flushs_found = parse(s,"fs");
    unsigned long long flushs = parse(s,"ft");
    unsigned long long flush_objs_found = parse(s,"os");
    unsigned long long flush_objs = parse(s,"ot");

    parse_string(s,"PT",pool_type,2);
    pool_type[2] = '\0';
    parse_sharers(s,"SC",buf,BUFSIZE);
    printf("poolid=%lu[%s] uuid=%llx.%llx, shared-by:%s: "
           "pgp=%llu(max=%llu) obj=%llu(%llu) "
           "objnode=%llu(%llu) puts=%llu/%llu/%llu(dup=%llu/%llu) "
           "gets=%llu/%llu(%llu%%) "
           "flush=%llu/%llu flobj=%llu/%llu\n",
           pool_id, pool_type, uid0, uid1, buf,
           pgp_count, max_pgp_count, obj_count, max_obj_count,
           objnode_count, max_objnode_count,
           good_puts, puts, no_mem_puts, 
           dup_puts_flushed, dup_puts_replaced,
           found_gets, gets,
           gets ? (found_gets*100LL)/gets : 0,
           flushs_found, flushs, flush_objs_found, flush_objs);
}

int main(int ac, char **av)
{
    char *p, c;
    char buf[BUFSIZE];

    while ( (p = fgets(buf,BUFSIZE,stdin)) != NULL )
    {
        c = *p++;
        if ( *p++ != '=' )
            continue;
        switch ( c )
        {
        case 'G':
            parse_global(p);
            break;
        case 'T':
            parse_time_stats(p);
            break;
        case 'C':
            parse_client(p);
            break;
        case 'P':
            parse_pool(p);
            break;
        case 'S':
            parse_shared_pool(p);
            break;
        default:
            continue;
        }
    }
    return 0;
}
