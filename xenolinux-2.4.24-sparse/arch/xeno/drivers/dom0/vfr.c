/******************************************************************************
 * vfr.c
 *
 * Interface to the virtual firewall/router.
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <asm/xeno_proc.h>
#include <asm/hypervisor-ifs/network.h>

static struct proc_dir_entry *proc_vfr;

static unsigned char readbuf[1024];

/* Helpers, implemented at the bottom. */
u32 getipaddr(const char *buff, unsigned int len);
u16 antous(const char *buff, int len);
u64 antoull(const char *buff, int len);
int anton(const char *buff, int len);

static int vfr_read_proc(char *page, char **start, off_t off,
                         int count, int *eof, void *data)
{   
    strcpy(page, readbuf);
    *readbuf = '\0';
    *eof = 1;
    *start = page;
    return strlen(page);
}

/* The format for the vfr interface is as follows:
 *
 *  COMMAND <field>=<val> [<field>=<val> [...]]
 *
 *  where:
 *
 *  COMMAND = { ACCEPT | COUNT }
 *
 *  field=val pairs are as follows:
 *
 *  field = { srcaddr | dstaddr }
 *      val is a dot seperated, numeric IP address.
 *
 *  field = { srcport | dstport }
 *      val is a (16-bit) unsigned int
 *
 *  field = { proto }
 *      val = { IP | TCP | UDP | ARP }
 *
 */

#define isspace(_x) ( ((_x)==' ')  || ((_x)=='\t') || ((_x)=='\v') || \
		      ((_x)=='\f') || ((_x)=='\r') || ((_x)=='\n') )

static int vfr_write_proc(struct file *file, const char *buffer,
                          u_long count, void *data)
{
    network_op_t op;
    int ret, len;
    int ts, te, tl; // token start, end, and length
    int fs, fe, fl; // field.

    len = count;
    ts = te = 0;

    memset(&op, 0, sizeof(network_op_t));

    // get the command:
    while ( count && isspace(buffer[ts]) ) { ts++; count--; } // skip spaces.
    te = ts;
    while ( count && !isspace(buffer[te]) ) { te++; count--; } // command end
    if ( te <= ts ) goto bad;
    tl = te - ts;
  
    if ( strncmp(&buffer[ts], "ADD", tl) == 0 )
    {
        op.cmd = NETWORK_OP_ADDRULE;
    }
    else if ( strncmp(&buffer[ts], "DELETE", tl) == 0 )
    {
        op.cmd = NETWORK_OP_DELETERULE;
    }
    else if ( strncmp(&buffer[ts], "PRINT", tl) == 0 )
    {
        op.cmd = NETWORK_OP_GETRULELIST;
        goto doneparsing;
    }
        
    ts = te;
  
    // get the action
    while ( count && (buffer[ts] == ' ') ) { ts++; count--; } // skip spaces.
    te = ts;
    while ( count && (buffer[te] != ' ') ) { te++; count--; } // command end
    if ( te <= ts ) goto bad;
    tl = te - ts;

    if ( strncmp(&buffer[ts], "ACCEPT", tl) == 0 ) 
    {
        op.u.net_rule.action = NETWORK_ACTION_ACCEPT;
        goto keyval;
    }
    if ( strncmp(&buffer[ts], "COUNT", tl) == 0 ) 
    {
        op.u.net_rule.action = NETWORK_ACTION_COUNT;
        goto keyval;
    }
   
    // default case;
    return (len);
  

    // get the key=val pairs.
 keyval:
    while (count)
    {
        //get field
        ts = te; while ( count && isspace(buffer[ts]) ) { ts++; count--; }
        te = ts;
        while ( count && !isspace(buffer[te]) && (buffer[te] != '=') ) 
        { te++; count--; }
        if ( te <= ts )
            goto doneparsing;
        tl = te - ts;
        fs = ts; fe = te; fl = tl; // save the field markers.
        // skip "   =   " (ignores extra equals.)
        while ( count && (isspace(buffer[te]) || (buffer[te] == '=')) ) 
        { te++; count--; }
        ts = te;
        while ( count && !isspace(buffer[te]) ) { te++; count--; }
        tl = te - ts;

        if ( (fl <= 0) || (tl <= 0) ) goto bad;

        /* NB. Prefix matches must go first! */
        if (strncmp(&buffer[fs], "src", fl) == 0)
        {

            op.u.net_rule.src_dom = VIF_SPECIAL;
            op.u.net_rule.src_idx = VIF_ANY_INTERFACE;
        }
        else if (strncmp(&buffer[fs], "dst", fl) == 0)
        {
            op.u.net_rule.dst_dom = VIF_SPECIAL;
            op.u.net_rule.dst_idx = VIF_PHYSICAL_INTERFACE;
        }
        else if (strncmp(&buffer[fs], "srcaddr", fl) == 0) 
        {  
            op.u.net_rule.src_addr = getipaddr(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "dstaddr", fl) == 0)
        {    
            op.u.net_rule.dst_addr = getipaddr(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "srcaddrmask", fl) == 0) 
        {
            op.u.net_rule.src_addr_mask = getipaddr(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "dstaddrmask", fl) == 0)
        {
            op.u.net_rule.dst_addr_mask = getipaddr(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "srcport", fl) == 0)
        {
            op.u.net_rule.src_port = antous(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "dstport", fl) == 0)
        {
            op.u.net_rule.dst_port = antous(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "srcportmask", fl) == 0)
        {
            op.u.net_rule.src_port_mask = antous(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "dstportmask", fl) == 0)
        {
            op.u.net_rule.dst_port_mask = antous(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "srcdom", fl) == 0)
        {
            op.u.net_rule.src_dom = antoull(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "srcidx", fl) == 0)
        {
            op.u.net_rule.src_idx = anton(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "dstdom", fl) == 0)
        {
            op.u.net_rule.dst_dom = antoull(&buffer[ts], tl);
        }
        else if (strncmp(&buffer[fs], "dstidx", fl) == 0)
        {
            op.u.net_rule.dst_idx = anton(&buffer[ts], tl);
        }
        else if ( (strncmp(&buffer[fs], "proto", fl) == 0))
        {	
            if (strncmp(&buffer[ts], "any", tl) == 0) 
                op.u.net_rule.proto = NETWORK_PROTO_ANY; 
            if (strncmp(&buffer[ts], "ip", tl) == 0)
                op.u.net_rule.proto = NETWORK_PROTO_IP;
            if (strncmp(&buffer[ts], "tcp", tl) == 0) 
                op.u.net_rule.proto = NETWORK_PROTO_TCP;
            if (strncmp(&buffer[ts], "udp", tl) == 0)
                op.u.net_rule.proto = NETWORK_PROTO_UDP;
            if (strncmp(&buffer[ts], "arp", tl) == 0)
                op.u.net_rule.proto = NETWORK_PROTO_ARP;
        }
    }

 doneparsing:  
    ret = HYPERVISOR_network_op(&op);
    return(len);

 bad:
    return(len);
    
    
}

static int __init init_module(void)
{
    if ( !(start_info.flags & SIF_PRIVILEGED) )
        return 0;

    *readbuf = '\0';
    proc_vfr = create_xeno_proc_entry("vfr", 0600);
    if ( proc_vfr != NULL )
    {
        proc_vfr->owner      = THIS_MODULE;
        proc_vfr->nlink      = 1;
        proc_vfr->read_proc  = vfr_read_proc;
        proc_vfr->write_proc = vfr_write_proc;
        printk("Successfully installed virtual firewall/router interface\n");
    }
    return 0;
}

static void __exit cleanup_module(void)
{
    if ( proc_vfr == NULL ) return;
    remove_xeno_proc_entry("vfr");
    proc_vfr = NULL;
}

module_init(init_module);
module_exit(cleanup_module);

/* Helper functions start here: */

int anton(const char *buff, int len)
{
    int ret;
    char c;
    int sign = 1;
    
    ret = 0;

    if (len == 0) return 0;
    if (*buff == '-') { sign = -1; buff++; len--; }

    while ( (len) && ((c = *buff) >= '0') && (c <= '9') )
    {
        ret *= 10;
        ret += c - '0';
        buff++; len--;
    }

    ret *= sign;
    return ret;
}
    
u16 antous(const char *buff, int len)
{
    u16 ret;
    char c;

    ret = 0;

    while ( (len) && ((c = *buff) >= '0') && (c <= '9') )
    {
        ret *= 10;
        ret += c - '0';
        buff++; len--;
    }

    return ret;
}

u64 antoull(const char *buff, int len)
{
    u64 ret;
    char c;

    ret = 0;

    while ( (len) && ((c = *buff) >= '0') && (c <= '9') )
    {
        ret *= 10;
        ret += c - '0';
        buff++; len--;
    }

    return ret;
}

u32 getipaddr(const char *buff, unsigned int len)
{
    char c;
    u32 ret, val;

    ret = 0; val = 0;

    while ( len )
    {
        if (!((((c = *buff) >= '0') && ( c <= '9')) || ( c == '.' ) ) ) 
        {
            return(0); // malformed.
        }

        if ( c == '.' ) {
            if (val > 255) return (0); //malformed.
            ret = ret << 8; 
            ret += val;
            val = 0;
            len--; buff++;
            continue;
        }
        val *= 10;
        val += c - '0';
        buff++; len--;
    }
    ret = ret << 8;
    ret += val;

    return (ret);
}

