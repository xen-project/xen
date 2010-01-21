import traceback
import sys
import os

def exception_string(e):
        (ty,v,tb) = sys.exc_info()
        return traceback.format_exception_only(ty,v)

def daemonize(prog, args, stdin_tmpfile=None):
    """Runs a program as a daemon with the list of arguments.  Returns the PID
    of the daemonized program, or returns 0 on error.
    """
    r, w = os.pipe()
    pid = os.fork()

    if pid == 0:
        os.close(r)
        w = os.fdopen(w, 'w')
        os.setsid()
        try:
            pid2 = os.fork()
        except:
            pid2 = None
        if pid2 == 0:
            os.chdir("/")
            null_fd = os.open("/dev/null", os.O_RDWR)
            if stdin_tmpfile is not None:
                os.dup2(stdin_tmpfile.fileno(), 0)
            else:
                os.dup2(null_fd, 0)
            os.dup2(null_fd, 1)
            os.dup2(null_fd, 2)
            for fd in range(3, 256):
                try:
                    os.close(fd)
                except:
                    pass
            os.execvp(prog, args)
            os._exit(1)
        else:
            w.write(str(pid2 or 0))
            w.close()
            os._exit(0)
    os.close(w)
    r = os.fdopen(r)
    daemon_pid = int(r.read())
    r.close()
    os.waitpid(pid, 0)
    return daemon_pid

# Global variable to store the sysfs mount point
sysfs_mount_point = None

PROC_MOUNTS_PATH = '/proc/mounts'

def find_sysfs_mount():
    global sysfs_mount_point

    if not sysfs_mount_point is None:
        return sysfs_mount_point

    try:
        mounts_file = open(PROC_MOUNTS_PATH, 'r')

        for line in mounts_file:
            sline = line.split()
            if len(sline) < 3:
                continue
            if sline[2] == 'sysfs':
                sysfs_mount_point= sline[1]
                break
        mounts_file.close()
        return sysfs_mount_point
    except IOError, (errno, strerr):
        raise

    return None

