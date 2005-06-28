/*
 * pdb_caml_evtchn.c
 *
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * PDB's OCaml interface library for event channels
 */

#include <xc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>


#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int xen_evtchn_bind (int evtchn_fd, int idx);
int xen_evtchn_unbind (int evtchn_fd, int idx);

int
__evtchn_open (char *filename, int major, int minor)
{
    int   evtchn_fd;
    struct stat st;
    
    /* Make sure any existing device file links to correct device. */
    if ( (lstat(filename, &st) != 0) ||
         !S_ISCHR(st.st_mode) ||
         (st.st_rdev != makedev(major, minor)) )
    {
        (void)unlink(filename);
    }

 reopen:
    evtchn_fd = open(filename, O_RDWR); 
    if ( evtchn_fd == -1 )
    {
        if ( (errno == ENOENT) &&
             ((mkdir("/dev/xen", 0755) == 0) || (errno == EEXIST)) &&
             (mknod(filename, S_IFCHR|0600, makedev(major,minor)) == 0) )
        {
            goto reopen;
        }
        return -errno;
    }

    return evtchn_fd;
}

/*
 * evtchn_open : string -> int -> int -> Unix.file_descr
 *
 * OCaml's Unix library doesn't have mknod, so it makes more sense just write
 * this in C.  This code is from Keir/Andy.
 */
value
evtchn_open (value filename, value major, value minor)
{
    CAMLparam3(filename, major, minor);

    char *myfilename = String_val(filename);
    int   mymajor = Int_val(major);
    int   myminor = Int_val(minor);
    int   evtchn_fd;

    evtchn_fd = __evtchn_open(myfilename, mymajor, myminor);

    CAMLreturn(Val_int(evtchn_fd));
}

/*
 * evtchn_bind : Unix.file_descr -> int -> unit
 */
value
evtchn_bind (value fd, value idx)
{
    CAMLparam2(fd, idx);

    int myfd = Int_val(fd);
    int myidx = Int_val(idx);

    if ( xen_evtchn_bind(myfd, myidx) < 0 )
    {
        printf("(pdb) evtchn_bind error!\n");  fflush(stdout);
        failwith("evtchn_bind error");
    }

    CAMLreturn(Val_unit);
}

/*
 * evtchn_unbind : Unix.file_descr -> int -> unit
 */
value
evtchn_unbind (value fd, value idx)
{
    CAMLparam2(fd, idx);

    int myfd = Int_val(fd);
    int myidx = Int_val(idx);

    if ( xen_evtchn_unbind(myfd, myidx) < 0 )
    {
        printf("(pdb) evtchn_unbind error!\n");  fflush(stdout);
        failwith("evtchn_unbind error");
    }

    CAMLreturn(Val_unit);
}

/*
 * evtchn_read : Unix.file_descr -> int
 */
value
evtchn_read (value fd)
{
    CAMLparam1(fd);

    u16 v;
    int bytes;
    int rc = -1;
    int myfd = Int_val(fd);

    while ( (bytes = read(myfd, &v, sizeof(v))) == -1 )
    {
        if ( errno == EINTR )  continue;
        rc = -errno;
        goto exit;
    }
    
    if ( bytes == sizeof(v) )
        rc = v;
    
 exit:
    CAMLreturn(Val_int(rc));
}


/*
 * evtchn_close : Unix.file_descr -> unit
 */
value
evtchn_close (value fd)
{
    CAMLparam1(fd);
    int myfd = Int_val(fd);

    (void)close(myfd);

    CAMLreturn(Val_unit);
}

/*
 * evtchn_unmask : Unix.file_descr -> int -> unit
 */
value
evtchn_unmask (value fd, value idx)
{
    CAMLparam1(fd);

    int myfd = Int_val(fd);
    u16 myidx = Int_val(idx);

    (void)write(myfd, &myidx, sizeof(myidx));

    CAMLreturn(Val_unit);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
