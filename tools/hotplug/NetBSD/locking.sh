#
# Copyright (c) 2005 XenSource Ltd.
# Copyright (c) 2007 Red Hat
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; If not, see <http://www.gnu.org/licenses/>.
#

#
# Serialisation
#

LOCK_BASEDIR=$XEN_LOCK_DIR/xen-hotplug

_setlockfd()
{
    _lockfd=9
    _lockfile="$LOCK_BASEDIR/$1"
}


claim_lock()
{
    mkdir -p "$LOCK_BASEDIR"
    _setlockfd $1
    # The locking strategy is identical to that from with-lock-ex(1)
    # from chiark-utils, except using flock.  It has the benefit of
    # it being possible to safely remove the lockfile when done.
    # See below for a correctness proof.
    local stat
    while true; do
        eval "exec $_lockfd<> $_lockfile"
	# we can't flock $_lockfd here, as the shell closes it on exec.
	# Workaround by redirecting to 0 for the command, and flock 0 instead.
        flock -v -x 0  0<& $_lockfd|| exit 1
        local file_stat
        local fd_stat
        if fd_stat=$(stat -f '%d.%i' 0<&$_lockfd 2>/dev/null) && file_stat=$(stat -f '%d.%i' $_lockfile 2>/dev/null )
        then
            if [ "$fd_stat" = "$file_stat" ] ; then break; fi
        fi
        # Some versions of bash appear to be buggy if the same
        # $_lockfile is opened repeatedly. Close the current fd here.
        eval "exec $_lockfd<&-"
    done
}


release_lock()
{
    _setlockfd $1
    rm "$_lockfile"
}

# Protocol and correctness proof:
#
# * The lock is owned not by a process but by an open-file (informally
#   an fd).  Any process with an fd onto this open-file is a
#   lockholder and may perform the various operations; such a process
#   should only do so when its co-lockholder processes expect.  Ie, we
#   will treat all processes holding fds onto the open-file as acting
#   in concert and not distinguish between them.
#
# * You are a lockholder if
#     - You have an fd onto an open-file which
#       currently holds an exclusive flock lock on its inum
#     - and that inum is currently linked at the lockfile path
#
# * The rules are:
#     - No-one but a lockholder may unlink the lockfile path
#       (or otherwise cause it to stop referring to a file it
#       refers to).
#     - Anyone may open the lockfile with O_CREAT
#
# * The protocol for locking is:
#     - Open the file (O_CREAT)
#     - flock it
#     - fstat the fd you have open
#     - stat the lockfile path
#     - if both are equal you have the lock, otherwise try again.
#
# * Informal proof of exclusivity:
#     - No two open-files can hold an fcntl lock onto the same file
#       at the same time
#     - No two files can have the same name at the same time
#
# * Informal proof of correctness of locking protocol:
#     - After you call flock successfully no-one other than you
#       (someone with the same open-file) can stop you having
#       that flock lock.
#     - Obviously the inum you get from the fstat is fixed
#     - At the point where you call stat there are two
#       possibilities:
#         (i) the lockfile path referred to some other inum
#             in which case you have failed
#         (ii) the lockfile path referred to the same file
#             in which case at that point you were the
#             lockholder (by definition).
#
# * Informal proof that no-one else can steal the lock:
#     - After you call flock successfully no-one other than you
#       can stop you having that flock lock
#     - No-one other than the lockholder is permitted to stop
#       the path referring to a particular inum.  So if you
#       hold the lock then only you are allowed to stop the
#       path referring to the file whose flock you hold; so
#       it will continue to refer to that file.
#   That's both the conditions for being the lockholder.
#
#   Thus once you hold the lock at any instant, you will
#   continue to do so until you voluntarily stop doing so
#   (eg by unlinking the lockfile or closing the fd).
