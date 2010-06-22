# utility functions

import fcntl, os, subprocess

class PipeException(Exception):
    def __init__(self, message, errno):
        self.errno = errno
        message = '%s: %d, %s' % (message, errno, os.strerror(errno))
        Exception.__init__(self, message)

class Lock(object):
    """advisory lock"""

    def __init__(self, filename):
        """lock using filename for synchronization"""
        self.filename = filename + '.lock'

        self.fd = None

        self.lock()

    def __del__(self):
        self.unlock()

    def lock(self):
        if self.fd:
            return

        self.fd = open(self.filename, 'w')
        fcntl.lockf(self.fd, fcntl.LOCK_EX)

    def unlock(self):
        if not self.fd:
            return

        fcntl.lockf(self.fd, fcntl.LOCK_UN)
        self.fd = None
        try:
            os.remove(self.filename)
        except OSError:
            # harmless race
            pass

def canonifymac(mac):
    return ':'.join(['%02x' % int(field, 16) for field in mac.split(':')])

def checkpid(pid):
    """return True if pid is live"""
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def runcmd(args, cwd=None):
    # TODO: stdin handling
    if type(args) == str:
        args = args.split(' ')
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True,
                                cwd=cwd)
        stdout = proc.stdout.read()
        stderr = proc.stderr.read()
        proc.wait()
        if proc.returncode:
            print ' '.join(args)
            print stderr.strip()
            raise PipeException('%s failed' % args[0], proc.returncode)
        return stdout
    except (OSError, IOError), inst:
        raise PipeException('could not run %s' % args[0], inst.errno)

def modprobe(modname):
    """attempt to load kernel module modname"""
    try:
        runcmd(['modprobe', '-q', modname])
        return True
    except PipeException:
        return False
