# Introduction

The goal of deprilvileging qemu is this: Even if there is a bug (for
example in qemu) which permits a domain to gain control of the device
model, the compromised device model process is prevented from
violating the system's overall security properties.  Ie, a guest
cannot "escape" from the virtualisation by using a qemu bug.

This document lists the various technical measures which we either
have taken, or plan to take to effect this goal.  Some of them are
required to be considered secure (that is, there are known attack
vectors which they close); others are "just in case" (that is, there
are no known attack vectors, but we perform the restrictions to reduce
the possibility of unknown attack vectors).

# Restrictions done

The following restrictions are currently implemented.

## Having qemu switch user

'''Description''': As mentioned above, having QEMU switch to a
non-root user, one per domain id.  Not being the root user limits what
a compromised QEMU process can do to the system, and having one user
per domain id limits what a comprimised QEMU process can do to the
QEMU processes of other VMs.

'''Implementation''': The toolstack adds the following to the qemu command-line:

    -runas <uid>:<gid>

'''How to test''':

    grep /proc/<qpid>/status [UG]id

'''Testing Status''': Not tested

## Xen library / file-descriptor restrictions

'''Description''': Close and restrict Xen-related file descriptors.
Specifically:
 * Close all xenstore-related file descriptors
 * Make sure that all open instances of `privcmd` and `evtchn` file
descriptors have had `IOCTL_PRIVCMD_RESTRICT` and
`IOCTL_EVTCHN_RESTRICT_DOMID` ioctls called on them, respectively.

'''Implementation''': Toolstack adds the following to the qemu command-line:

    -xen-domid-restrict

'''How to test''':

Use `fishdescriptor` to pull a file descriptor from a running QEMU,
then use `depriv-fd-checker` to check that it has the desired
properties, and that hypercalls which are meant to fail do fail.  (In
Debian `fishdescriptor` can be found in the binary package
`chiark-scripts`; the `depriv-fd-checker` is included in the Xen
source tree.)

'''Testing status''': Tested

## Chroot

'''Description''': Qemu runs in its own chroot, such that even if it
could call an 'open' command of some sort, there would be nothing for
it to see.

'''Implementation''': The toolstack creates a directory in the libxl "run-dir"; e.g.
`/var/run/xen/qemu-root-<domid>`

Then adds the following to the qemu command-line:

    -chroot /var/run/xen/qemu-root-<domid>
	
'''How to test''':  Check `/proc/<qpid>/root`
	
'''Tested''': Not tested

## Namespaces for unused functionality (Linux only)

'''Description''': QEMU doesn't use the functionality associated with
mount and IPC namespaces. (IPC namespaces contol non-file-based IPC
mechanisms within the kernel; unix and network sockets are not
affected by this.)  Making separate namespaces for these for QEMU
won't affect normal operation, but it does mean that even if other
restrictions fail, the process won't be able to even name system mount
points or existing non-file-based IPC descriptors to attempt to attack
them.

'''Implementation''':

In theory this could be done in QEMU (similar to -sandbox, -runas,
-chroot, and so on), but a patch doing this in QEMU was NAKed upstream
(see [qemu-namespaces]). They preferred that this was done as a setup step by
whatever executes QEMU; i.e., have the process which exec's QEMU first
call:

    unshare(CLONE_NEWNS | CLONE_NEWIPC)
	
'''How to test''':  Check `/proc/<qpid>/ns/[ipc,mnt]`

'''Tested''': Not tested

[qemu-namespaces]: https://lists.gnu.org/archive/html/qemu-devel/2017-10/msg04723.html

### Basic RLIMITs

'''Description''': A number of limits on the resources that a given
process / userid is allowed to consume.  These can limit the ability
of a compromised QEMU process to DoS domain 0 by exhausting various
resources available to it.

'''Implementation'''

Limits that can be implemented immediately without much effort:
 - RLIMIT_FSIZE` (file size) to 256KiB.

Probably not necessary but why not:
 - RLIMIT_CORE: 0
 - RLIMIT_MSGQUEUE: 0
 - RLIMIT_LOCKS: 0
 - RLIMIT_MEMLOCK: 0
 
Note: mlock() is used by QEMU only when both "realtime" and "mlock"
are specified; this does not apply to QEMU running as a Xen DM.
   
'''How to test''': Check `/proc/<qpid>/limits`

'''Tested''': Not tested

### libxl UID cleanup

'''Description''': Domain IDs are reused, and thus restricted UIDs are
reused.  If a compromised QEMU can fork (due to seccomp or
RLIMIT_NPROC limits being ineffective for some reason), it may avoid
being killed when its domain dies, then wait until the domain ID is
reused again, at which point it will have control over the domain in
question (which probably belongs to someone else).

libxl should kill all UIDs associated with a domain both when the VM
is destroyed, and before starting a VM with the same UID.

'''Implementation''': This is unnecessarily tricky.

The kill() system call can have three kinds of targets:
 - A single pid
 - A process group
 - "Every process except me to which I am allowed to send a signal" (-1)

Targeting a single pid is racy and likely to be beaten by the
following loop:

    while(1) {
        if(fork())
	    _exit(0);
    }	  

That is, by the time you've read the process list and found the
process id you want to kill, that process has exited and there is a
new process whose pid you don't know about.

Targeting a process group will be ineffective, as unprivileged
processes are allowed to make their own process groups.

kill(-1) can be used but must be done with care.  Consider the
following code, for example:

    setuid(target_uid);
    kill(-1, 9);

This looks like it will do the trick; but by setting all of the user
ids (effective, real, and saved), it opens the 'killing' process up to
being killed by the target process:

    while(1) {
        if(fork())
            _exit(0);
        else
            kill(-1, 9);
    }

Fortunately there is an assymetry we can take advantage of.  From the
POSIX spec:

> For a process to have permission to send a signal to a process
> designated by pid, unless the sending process has appropriate
> privileges, the real or effective user ID of the sending process shall
> match the real or saved set-user-ID of the receiving process.

The solution is to allocate a second "reaper" uid that is only used to kill
target processes.  We set the euid of the killing process to the `target_uid`,
but the ruid of the killing process to `reaper_uid`, leaving the suid of the
killing process as 0:

    setresuid(reaper_uid, target_uid, 0);
    kill(-1, 9);

NOTE: We cannot use `setreuid(reaper_uid, target_uid)` here, as that
will set *both* euid *and* suid to `target_uid`, making the killing
process vulnerable to the target process again.

Since this will kill all other `reaper_uid` processes as well, we must
either allocate a separate `reaper_uid` per domain, or use locking to
ensure that only one killing process is active at a time.

# Restrictions / improvements still to do

This lists potential restrictions still to do.  It is meant to be
listed in order of ease of implementation, with low-hanging fruit
first.

### Further RLIMITs

RLIMIT_AS limits the total amount of memory; but this includes the
virtual memory which QEMU uses as a mapcache.  xen-mapcache.c already
fiddles with this; it would be straightforward to make it *set* the
rlimit to what it thinks a sensible limit is.

RLIMIT_NPROC limits total number of processes or threads.  QEMU uses
threads for some devices, so this would require some thought.

Other things that would take some cleverness / changes to QEMU to
utilize due to ordering constrants:
 - RLIMIT_NOFILES (after all necessary files are opened)

## libxl: Treat QMP connection as untrusted

'''Description''': Currently libxl talks with QEMU via QMP; but its
interactions have not historically considered from a security point of
view.  For example, qmp_synchronous_send() waits for a response from
QEMU, which a compromised QEMU could simply not send (thus preventing
the toolstack from making forward progress).

'''Implementation''': Audit toolstack interactions with QEMU which
happen after the guest has started running, and assume QEMU has been
compromised.

### seccomp filtering (Linux only)

'''Description''': Turn on seccomp filtering to disable syscalls which
QEMU doesn't need. 

'''Implementation''': Enable from the command-line:

    -sandbox on,obsolete=deny,elevateprivileges=allow,spawn=deny,resourcecontrol=deny

`elevateprivileges` is currently required to allow `-runas` to work.
Removing this requirement would mean making sure that the uid change
happened before the seccomp2 call, perhaps by changing the uid before
executing QEMU.  (But this would then require other changes to create
the QMP socket, VNC socket, and so on).

It should be noted that `-sandbox` is implemented as a blacklist, not
a whitelist; that is, it disables known-unsed functionality which may
be harmful, rather than disabling all functionality except that known
to be safe and needed.  This is unfortunately necessary since qemu
doesn't know what system calls libraries might end up making.  (See
[lwn-seccomp] for a more complete discussion.)

This feature is not on by default and may not be available in all
environments.  We therefore need to either:
 1. Require that this feature be enabled to build qemu
 2. Check for `-sandbox` support at runtime before 

[lwn-seccomp]: https://lwn.net/Articles/738694/

### Disks

The chroot (and seccomp?) happens late enough such that QEMU can
initialize itself and open its disks. If you want to add a disk at run
time via or insert a CD, you can't pass a path because QEMU is
chrooted. Instead use the add-fd QMP command and use
/dev/fdset/<fdset-id> as the path.

A further layer of restriction could be to set RLIMIT_NOFILES to '0',
and hand all disks over QMP.

## Migration

When calling xen-save-devices-state, since QEMU is running in a chroot
it is not useful to pass a filename (it doesn't even have write access
inside the chroot). Instead, give it an open fd using the add-fd
mechanism.

Additionally, all the restrictions need to be applied to the qemu
started up on the post-migration side.  One issue that needs to be
solved is how to signal the toolstack on restore that qemu is ready
for the domain to be started (since this is normally done via
xenstore, and at this point the xenstore connections will have been
closed).

### Network namespacing (Linux only)

Enter QEMU into its own network namespace (in addition to mount & IPC
namespaces):

    unshare(CLONE_NEWNET);

QEMU does actually use the network namespace as a Xen DM for two
purposes: 1) To set up network tap devices 2) To open vnc connections.

#### Network

If QEMU runs in its own network namespace, it can't open the tap
device itself because the interface won't be visible outside of its
own namespace. So instead, have the toolstack open the device and pass
it as an fd on the command-line:

    -device rtl8139,netdev=tapnet0,mac=... -netdev tap,id=tapnet0,fd=<tapfd>

#### VNC

If QEMU runs in its own network namespace, it is not straightforward
to listen on a TCP socket outside of its own network namespace. One
option would be to use VNC over a UNIX socket:

    -vnc unix:/var/run/xen/vnc-<domid>

However, this would break functionality in the general case; I think
we need to have the toolstack open a socket and pass the fd to QEMU
(which requires changes to QEMU).

