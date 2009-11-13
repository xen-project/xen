# utility functions

import os, subprocess

class PipeException(Exception):
    def __init__(self, message, errno):
        self.errno = errno
        message = '%s: %d, %s' % (message, errno, os.strerror(errno))
        Exception.__init__(self, message)

def canonifymac(mac):
    return ':'.join(['%02x' % int(field, 16) for field in mac.split(':')])

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
