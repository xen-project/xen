/*
 * Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the 
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free software Foundation, Inc.,
 * 59 Temple Place, suite 330, Boston, MA 02111-1307 USA
 *
 */
#include <linux/config.h>
#include <linux/module.h>

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>

#include <asm/uaccess.h>

#include <linux/slab.h>

#include <linux/proc_fs.h>
#include <linux/string.h>

#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>

#include <sa.h>
#include "vif.h"
#include "vnet.h"
#include "varp.h"
#include "vnet_dev.h"

#include "sxpr_parser.h"
#include "iostream.h"
#include "kernel_stream.h"
#include "sys_string.h"
#include "sys_net.h"

#define MODULE_NAME "VNET"
#define DEBUG 1
#undef DEBUG
#include "debug.h"

// Functions to manage vnets.
/*

Have to rely on ethernet bridging being configured - but we can't rely
on the kernel interface being available to us (it's not exported @!$"%!).

Create a vnet N:
- create the vnet device vnetifN: using commands to /proc, kernel api
- create the vnet bridge vnetN: using brctl in user-space
- for best results something should keep track of the mapping vnet id <-> bridge name

Add vif device vifD.N to vnet N.
- domain is configured with vifD.N on bridge vnetN
- vif script adds vif to bridge using brctl
- vif script detects that the bridge is a vnet bridge and
  uses /proc commands to configure the mac on the vnet

Wouldn't be hard to add support for specifying vnet keys(s) in
the control interface.

*/

    // id         vnet id
    // security   security level
    // ciphersuite: digest, cipher, keys??
/* Security policy.
   vnet
   src: mac
   dst: mac
   coa: ip
   Map vnet x coa -> security (none, auth, conf)

   Policy, e.g.
   - same subnet x vnet
   - diff subnet x vnet
   - some subnet x vnet
   - some host addr x vnet

   (security (net local) (vnet *) (mode none))
   (security (net (not local))

   (security (addr, vnet) (local-subnet addr)       none)
   (security (addr, vnet) (not (local-subnet addr)) conf)
   (security (addr, vnet) (host 15.144.27.80)
   (security (addr, vnet) (subnet addr 15.144.24.0/24) auth)
   (security (addr, vnet) t auth)

   (security (addr local)         (mode none))
   (security (addr local/16)      (mode none))
   (security (addr 15.144.0.0/16) (mode auth))
   (security (addr 15.0.0.0/8)    (mode conf))
   (security (addr *)             (mode drop))

   ?Varp security
   Use esp too - none, auth, conf,
   Varp sends broadcasts (requests) and unicasts (replies).
   Uses UDP. Could send over ESP if needed.
   For bcast don't know where it goes, so security has to be by vnet.
   For ucast know where it goes, so could do by vnet and addr.

   Similar issue for vnets: know where unicast goes but don't know where
   bcast goes.

   Simplify: 2 levels
   local ucast
   nonlocal ucast, mcast

   (security (local none) (nonlocal conf))
   (security (local auth) (nonlocal conf))

   VARP security matches vnet security.

 */

/** @file
 *
 * Kernel interface to files in /proc.
 */

#define PROC_ROOT "/proc/"
#define PROC_ROOT_LEN 6
#define MODULE_ROOT PROC_ROOT "vnet"

enum {
    VNET_POLICY = 1,
};

typedef struct proc_dir_entry ProcEntry;
typedef struct inode Inode;
typedef struct file File;

static int proc_open_fn(struct inode *inode, File *file);
static ssize_t proc_read_fn(File *file, char *buffer, size_t count, loff_t *offset);
static ssize_t proc_write_fn(File *file, const char *buffer, size_t count, loff_t *offset) ;
//static int proc_flush_fn(File *file);
static loff_t proc_lseek_fn(File * file, loff_t offset, int orig);
static int proc_ioctl_fn(struct inode *inode, File *file, unsigned opcode, unsigned long arg);
static int proc_release_fn(struct inode *inode, File *file);

static int eval(Sxpr exp);

static int ProcEntry_has_name(ProcEntry *entry, const char *name, int namelen){
    dprintf("> name=%.*s entry=%.*s\n", namelen, name, entry->namelen, entry->name);
    if(!entry || !entry->low_ino) return FALSE;
    if(entry->namelen != namelen) return FALSE;
    return memcmp(name, entry->name, namelen) == 0;
}

// Set f->f_error on error?
// Does interface stop r/w on first error?
// Is release called after an error?
//

static struct file_operations proc_file_ops = {
    //owner:   THIS_MODULE,
    open:    proc_open_fn,
    read:    proc_read_fn,
    write:   proc_write_fn,
    //flush:   proc_flush_fn,
    llseek:  proc_lseek_fn,
    ioctl:   proc_ioctl_fn,
    release: proc_release_fn,
};

static int proc_get_parser(File *file, Parser **val){
    int err = 0;
    Parser *parser = NULL;
    parser = file->private_data;
    if(!parser){
        parser = Parser_new();
        if(!parser){
            err = -ENOMEM;
            goto exit;
        }
        file->private_data = parser;
    }
  exit:
    *val = parser;
    return err;
}

static int proc_open_fn(Inode *inode, File *file){
    // User open.
    // Return errcode or 0 on success.
    // Can stuff data in file->private_data (void*).
    // Get entry from
    //ProcEntry *entry = (ProcEntry *)inode->u.generic_ip;
    //file->private_data = NULL;
    // Check for user privilege - deny otherwise.
    // -EACCESS
    int err = 0;
    dprintf(">\n");
    file->private_data = NULL;
    return err;
}

static ssize_t proc_read_fn(File *file, char *buffer,
                            size_t count, loff_t *offset){
    // User read.
    // Copy data to user buffer, increment offset by count, return count.
    dprintf(">\n");
    count = 0;
    //if(copy_to_user(buffer, data, count)){
    //    return -EFAULT;
    //}
    //*offset += count;
    return count;
}

static ssize_t proc_write_fn(File *file, const char *buffer,
                             size_t count, loff_t *offset) {
    // User write.
    // Copy data into kernel space from buffer.
    // Increment offset by count, return count (or code).
    int err = 0;
    char *data = NULL;
    Parser *parser = NULL;

    //dprintf("> count=%d\n", count);
    err = proc_get_parser(file, &parser);
    if(err) goto exit;
    data = allocate(count);
    if(!data){
        err = -ENOMEM;
        goto exit;
    }
    err = copy_from_user(data, buffer, count);
    if(err) goto exit;
    *offset += count;
    err = Parser_input(parser, data, count);
  exit:
    deallocate(data);
    err = (err < 0 ? err : count);
    //dprintf("< err = %d\n", err);
    return err;
}

#if 0
static int proc_flush_fn(File *file){
    // User flush.
    int writing = (file->f_flags & O_ACCMODE) == O_WRONLY;
    int f_count = atomic_read(&file->f_count);
    if (writing && f_count == 1) {
        ProcEntry *pentry = (ProcEntry *)file->f_dentry->d_inode->u.generic_ip;
        // ...
    }
  return retval;
}
#endif

#ifndef SEEK_SET
enum {
    /** Offset from start. */
    SEEK_SET = 0,
    /** Offset from current position. */
    SEEK_CUR = 1,
    /** Offset from size of file. */
    SEEK_END = 2
};
#endif /* !SEEK_SET */

static loff_t proc_lseek_fn(File * file, loff_t offset, int from){
    // User lseek.
    dprintf(">\n");
    switch(from){
    case SEEK_SET:
        break;
    case SEEK_CUR:
	offset += file->f_pos;
        break;
    case SEEK_END:
	return -EINVAL;
    default:
	return -EINVAL;
    }
    if(offset < 0) return -EINVAL;    
    file->f_pos = offset;
    return offset;
}

static int proc_ioctl_fn(Inode *inode, File *file,
                         unsigned opcode, unsigned long arg){
    // User ioctl.
    dprintf(">\n");
    return 0;
}

static int proc_release_fn(Inode *inode, File *file){
    // User close.
    // Cleanup file->private_data, return errcode.
    int err = 0;
    Parser *parser = NULL;
    Sxpr obj, l;

    dprintf(">\n");
    err = proc_get_parser(file, &parser);
    if(err) goto exit;
    err = Parser_input(parser, NULL, 0);
    if(err) goto exit;
    obj = parser->val;
    objprint(iostdout, obj, 0); IOStream_print(iostdout, "\n");
    for(l = obj; CONSP(l); l = CDR(l)){
        err = eval(CAR(l));
        if(err) break;
    }
  exit:
    Parser_free(parser);
    file->private_data = NULL;
    dprintf("< err=%d\n", err);
    return err;
}

static ProcEntry *proc_fs_root = &proc_root;

static int proc_path_init(const char *path, const char **rest){
    int err = 0;

    if(!path){
        err = -EINVAL;
        goto exit;
    }
    if(*path == '/'){
        if(strncmp(PROC_ROOT, path, PROC_ROOT_LEN)){
            err = -EINVAL;
        } else {
            path += PROC_ROOT_LEN;
        }
    }
  exit:
    *rest = path;
    return err;
}


/** Parse a path relative to `dir'. If dir is null or the proc root
 * the path is relative to "/proc/", and the leading "/proc/" may be
 * supplied.
 *
 */
static ProcEntry * ProcFS_lookup(const char *path, ProcEntry *dir){
    const char *pathptr = path, *next = NULL;
    ProcEntry *entry, *result = NULL;
    int pathlen;

    if(dir && (dir != proc_fs_root)){
        entry = dir;
    } else {
        if(proc_path_init(path, &pathptr)) goto exit;
        entry = proc_fs_root;
    }
    if(!pathptr || !*pathptr) goto exit;
    while(1){
        next = strchr(pathptr, '/');
        pathlen = (next ? next - pathptr : strlen(pathptr));
        for(entry = entry->subdir; entry ; entry = entry->next) {
            if(ProcEntry_has_name(entry, pathptr, pathlen)) break;
        }
        if (!entry) break;
        if(!next){
            result = entry;
            break;
        }
        pathptr = next + 1;
    }
  exit:
    return result;
}

static ProcEntry *ProcFS_register(const char *name, ProcEntry *dir, int val){
    mode_t mode = 0;
    ProcEntry *entry;

    entry = create_proc_entry(name, mode, dir);
    if(entry){
        entry->proc_fops = &proc_file_ops;
        entry->data = (void*)val; // Whatever data we need.
    }
    return entry;
}

static ProcEntry *ProcFS_mkdir(const char *name, ProcEntry *parent){
    ProcEntry *entry = NULL;
    entry = ProcFS_lookup(name, parent);
    if(!entry){
        const char *path;
        if(proc_path_init(name, &path)) goto exit;
        entry = proc_mkdir(path, parent);
    }
  exit:
    return entry;
}

static void ProcFS_remove(const char *name, ProcEntry *parent){
    remove_proc_entry(name, parent);
}

static void ProcFS_rmrec_entry(ProcEntry *entry){
    if(entry){
        // Don't want to remove /proc itself!
        if(entry->parent == entry) return;
        while(entry->subdir){
            ProcFS_rmrec_entry(entry->subdir);
        }
        dprintf("> remove %s\n", entry->name);
        ProcFS_remove(entry->name, entry->parent);
    }
}

static void ProcFS_rmrec(const char *name, ProcEntry *parent){
    ProcEntry *entry;

    dprintf("> name=%s\n", name);
    entry = ProcFS_lookup(name, parent);
    if(entry){
        ProcFS_rmrec_entry(entry);
    }
    dprintf("<\n");
}

static int stringof(Sxpr exp, char **s){
    int err = 0;
    if(ATOMP(exp)){
        *s = atom_name(exp);
    } else if(STRINGP(exp)){
        *s = string_string(exp);
    } else {
        err = -EINVAL;
        *s = NULL;
    }
    return err;
}

static int child_string(Sxpr exp, Sxpr key, char **s){
    int err = 0;
    Sxpr val = sxpr_child_value(exp, key, ONONE);
    err = stringof(val, s);
    return err;
}

static int intof(Sxpr exp, int *v){
    int err = 0;
    char *s;
    unsigned long l;
    if(INTP(exp)){
        *v = OBJ_INT(exp);
    } else {
        err = stringof(exp, &s);
        if(err) goto exit;
        err = convert_atoul(s, &l);
        *v = (int)l;
    }
 exit:
    return err;
}

static int child_int(Sxpr exp, Sxpr key, int *v){
    int err = 0;
    Sxpr val = sxpr_child_value(exp, key, ONONE);
    err = intof(val, v);
    return err;
}

static int macof(Sxpr exp, unsigned char *v){
    int err = 0;
    char *s;
    err = stringof(exp, &s);
    if(err) goto exit;
    err = mac_aton(s, v);
  exit:
    return err;
}

static int child_mac(Sxpr exp, Sxpr key, unsigned char *v){
    int err = 0;
    Sxpr val = sxpr_child_value(exp, key, ONONE);
    err = macof(val, v);
    return err;
}

static int addrof(Sxpr exp, uint32_t *v){
    int err = 0;
    char *s;
    unsigned long w;
    err = stringof(exp, &s);
    if(err) goto exit;
    err = get_inet_addr(s, &w);
    if(err) goto exit;
    *v = (uint32_t)w;
  exit:
    return err;
}

static int child_addr(Sxpr exp, Sxpr key, uint32_t *v){
    int err = 0;
    Sxpr val = sxpr_child_value(exp, key, ONONE);
    err = addrof(val, v);
    return err;
}

/** Create a vnet.
 * It is an error if a vnet with the same id exists.
 *
 * @param vnet vnet id
 * @param security security level
 * @return 0 on success, error code otherwise
 */
static int ctrl_vnet_add(int vnet, int security){
    int err = 0;
    Vnet *vnetinfo = NULL;
    if(Vnet_lookup(vnet, &vnetinfo) == 0){
        err = -EEXIST;
        goto exit;
    }
    err = Vnet_alloc(&vnetinfo);
    if(err) goto exit;
    vnetinfo->vnet = vnet;
    vnetinfo->security = security;
    err = Vnet_create(vnetinfo);
  exit:
    if(vnetinfo) Vnet_decref(vnetinfo);
    return err;
}

/** Delete a vnet.
 *
 * @param vnet vnet id
 * @return 0 on success, error code otherwise
 */
static int ctrl_vnet_del(int vnet){
    int err = -ENOSYS;
    // Can't delete if there are any vifs on the vnet.
    //Vnet_del(vnet);
    return err;
}

/** Create an entry for a vif with the given vnet and vmac.
 *
 * @param vnet vnet id
 * @param vmac mac address
 * @return 0 on success, error code otherwise
 */
static int ctrl_vif_add(int vnet, Vmac *vmac){
    int err = 0;
    Vnet *vnetinfo = NULL;
    Vif *vif = NULL;

    dprintf(">\n");
    err = Vnet_lookup(vnet, &vnetinfo);
    if(err) goto exit;
    err = vif_add(vnet, vmac, &vif);
  exit:
    if(vnetinfo) Vnet_decref(vnetinfo);
    if(vif) vif_decref(vif);
    dprintf("< err=%d\n", err);
    return err;
}

/** Add net device 'vifname' to the bridge for 'vnet' and
 * create an entry for a vif with the given vnet and vmac.
 * This is used when device 'vifname' is a virtual device
 * connected to a vif in a vm.
 *
 * @param vifname name of device to bridge
 * @param vnet vnet id
 * @param vmac mac address
 * @return 0 on success, error code otherwise
 */
static int ctrl_vif_conn(char *vifname, int vnet, Vmac *vmac){
    int err = 0;
    Vnet *vnetinfo = NULL;
    struct net_device *vifdev = NULL;
    Vif *vif = NULL;

    dprintf("> %s\n", vifname);
    err = Vnet_lookup(vnet, &vnetinfo);
    if(err) goto exit;
    err = vif_add(vnet, vmac, &vif);
    if(err) goto exit;
    err = vnet_get_device(vifname, &vifdev);
    if(err) goto exit;
    vif->dev = vifdev;
    err = vnet_add_if(vnetinfo, vifdev);
  exit:
    if(vnetinfo) Vnet_decref(vnetinfo);
    if(vif) vif_decref(vif);
    if(vifdev) dev_put(vifdev);
    dprintf("< err=%d\n", err);
    return err;
}

/** Delete a vif.
 *
 * @param vnet vnet id
 * @param vmac mac address
 * @return 0 on success, error code otherwise
 */
static int ctrl_vif_del(int vnet, Vmac *vmac){
    int err = 0;
    Vnet *vnetinfo = NULL;
    Vif *vif = NULL;

    dprintf(">\n");
    err = Vnet_lookup(vnet, &vnetinfo);
    if(err) goto exit;
    err = vif_lookup(vnet, vmac, &vif);
    if(err) goto exit;
    if(vif->dev){
        vnet_del_if(vnetinfo, vif->dev);
        vif->dev = NULL;
    }
    vif_remove(vnet, vmac);
  exit:
    if(vnetinfo) Vnet_decref(vnetinfo);
    if(vif) vif_decref(vif);
    dprintf("< err=%d\n", err);
    return err;
}

/** (varp.print)
 */
static int eval_varp_print(Sxpr exp){
    int err = 0;
    varp_print();
    return err;
}

/** (varp.mcaddr (addr <addr>))
 */
static int eval_varp_mcaddr(Sxpr exp){
    int err =0;
    Sxpr oaddr = intern("addr");
    uint32_t addr;

    err = child_addr(exp, oaddr, &addr);
    if(err < 0) goto exit;
    varp_set_mcast_addr(addr);
  exit:
    return err;
}

/** (vnet.add (id <id>) [(security { none | auth | conf } )] )
 */
static int eval_vnet_add(Sxpr exp){
    int err = 0;
    Sxpr oid = intern("id");
    Sxpr osecurity = intern("security");
    Sxpr csecurity;
    int id;
    char *security;
    int sec;
    err = child_int(exp, oid, &id);
    if(err) goto exit;
    if(id < VNET_VIF){ 
        err = -EINVAL;
        goto exit;
    }
    csecurity = sxpr_child_value(exp, osecurity, intern("none"));
    err = stringof(csecurity, &security);
    if(err) goto exit;
    if(strcmp(security, "none")==0){
        sec = 0;
    } else if(strcmp(security, "auth")==0){
        sec = SA_AUTH;
    } else if(strcmp(security, "conf")==0){
        sec = SA_CONF;
    } else {
        err = -EINVAL;
        goto exit;
    }
    dprintf("> vnet id=%d\n", id);
    err = ctrl_vnet_add(id, sec);
 exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Delete a vnet.
 *
 * (vnet.del (id <id>))
 *
 * @param vnet vnet id
 * @return 0 on success, error code otherwise
 */
static int eval_vnet_del(Sxpr exp){
    int err = 0;
    Sxpr oid = intern("id");
    int id;

    err = child_int(exp, oid, &id);
    if(err) goto exit;
    err = ctrl_vnet_del(id);
  exit:
    return err;
}

/** (vif.add (vnet <vnet>) (vmac <macaddr>))
 */
static int eval_vif_add(Sxpr exp){
    int err = 0;
    Sxpr ovnet = intern("vnet");
    Sxpr ovmac = intern("vmac");
    int vnet;
    Vmac vmac = {};

    err = child_int(exp, ovnet, &vnet);
    if(err) goto exit;
    err = child_mac(exp, ovmac, vmac.mac);
    if(err) goto exit;
    err = ctrl_vif_add(vnet, &vmac);
  exit:
    return err;
}

/** (vif.conn (vif <name>) (vnet <id>) (vmac <mac>))
 */
static int eval_vif_conn(Sxpr exp){
    int err = 0;
    Sxpr ovif = intern("vif");
    Sxpr ovnet = intern("vnet");
    Sxpr ovmac = intern("vmac");
    char *vif = NULL;
    int vnet = 0;
    Vmac vmac = {};

    err = child_string(exp, ovif, &vif);
    if(err) goto exit;
    err = child_int(exp, ovnet, &vnet);
    if(err) goto exit;
    err = child_mac(exp, ovmac, vmac.mac);
    dprintf("> connect vif=%s vnet=%d\n", vif, vnet);
    err = ctrl_vif_conn(vif, vnet, &vmac);
 exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** (vif.del (vnet <vnet>) (vmac <macaddr>))
 */
static int eval_vif_del(Sxpr exp){
    int err = 0;
    Sxpr ovnet = intern("vnet");
    Sxpr ovmac = intern("vmac");
    int vnet;
    Vmac vmac = {};

    err = child_int(exp, ovnet, &vnet);
    if(err) goto exit;
    err = child_mac(exp, ovmac, vmac.mac);
    if(err) goto exit;
    err = ctrl_vif_del(vnet, &vmac);
  exit:
    return err;
}

typedef struct SxprEval {
    Sxpr elt;
    int (*fn)(Sxpr);
} SxprEval;

static int eval(Sxpr exp){
    int err = 0;
    SxprEval defs[] = {
        { intern("varp.print"),   eval_varp_print   },
        { intern("varp.mcaddr"),  eval_varp_mcaddr  },
        { intern("vif.add"),      eval_vif_add      },
        { intern("vif.conn"),     eval_vif_conn     },
        { intern("vif.del"),      eval_vif_del      },
        { intern("vnet.add"),     eval_vnet_add     },
        { intern("vnet.del"),     eval_vnet_del     },
        { ONONE, NULL } };
    SxprEval *def;

    dprintf(">\n");
    err = -EINVAL;
    for(def = defs; !NONEP(def->elt); def++){
        if(sxpr_elementp(exp, def->elt)){
            err = def->fn(exp);
            break;
        }
    }
    dprintf("< err=%d\n", err);
    return err;
}

void __init ProcFS_init(void){
    ProcEntry *root_entry;
    ProcEntry *policy_entry;

    dprintf(">\n");
    root_entry = ProcFS_mkdir(MODULE_ROOT, NULL);
    if(!root_entry) goto exit;
    policy_entry = ProcFS_register("policy", root_entry, VNET_POLICY);
  exit:
    dprintf("<\n");
}

void __exit ProcFS_exit(void){
    dprintf(">\n");
    ProcFS_rmrec(MODULE_ROOT, NULL);
    dprintf("<\n");
}
