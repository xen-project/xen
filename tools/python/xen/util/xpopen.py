#
# Copyright (c) 2001, 2002, 2003, 2004 Python Software Foundation; All Rights Reserved
#
# PSF LICENSE AGREEMENT FOR PYTHON 2.3
# ------------------------------------
# 
# 1. This LICENSE AGREEMENT is between the Python Software Foundation
# ("PSF"), and the Individual or Organization ("Licensee") accessing and
# otherwise using Python 2.3 software in source or binary form and its
# associated documentation.
# 
# 2. Subject to the terms and conditions of this License Agreement, PSF
# hereby grants Licensee a nonexclusive, royalty-free, world-wide
# license to reproduce, analyze, test, perform and/or display publicly,
# prepare derivative works, distribute, and otherwise use Python 2.3
# alone or in any derivative version, provided, however, that PSF's
# License Agreement and PSF's notice of copyright, i.e., "Copyright (c)
# 2001, 2002, 2003, 2004 Python Software Foundation; All Rights Reserved" are
# retained in Python 2.3 alone or in any derivative version prepared by
# Licensee.
# 
# 3. In the event Licensee prepares a derivative work that is based on
# or incorporates Python 2.3 or any part thereof, and wants to make
# the derivative work available to others as provided herein, then
# Licensee hereby agrees to include in any such work a brief summary of
# the changes made to Python 2.3.
# 
# 4. PSF is making Python 2.3 available to Licensee on an "AS IS"
# basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
# IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
# DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
# FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON 2.3 WILL NOT
# INFRINGE ANY THIRD PARTY RIGHTS.
# 
# 5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
# 2.3 FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
# A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON 2.3,
# OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
# 
# 6. This License Agreement will automatically terminate upon a material
# breach of its terms and conditions.
# 
# 7. Nothing in this License Agreement shall be deemed to create any
# relationship of agency, partnership, or joint venture between PSF and
# Licensee.  This License Agreement does not grant permission to use PSF
# trademarks or trade name in a trademark sense to endorse or promote
# products or services of Licensee, or any third party.
# 
# 8. By copying, installing or otherwise using Python 2.3, Licensee
# agrees to be bound by the terms and conditions of this License
# Agreement.
# 
# Modifications: Copyright (c) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# - add support for excluding a list of file descriptors from being
#   closed, allowing access to those file descriptors from the command.
#

"""Spawn a command with pipes to its stdin, stdout, and optionally stderr.

The normal os.popen(cmd, mode) call spawns a shell command and provides a
file interface to just the input or output of the process depending on
whether mode is 'r' or 'w'.  This module provides the functions xpopen2(cmd)
and xpopen3(cmd) which return two or three pipes to the spawned command.
Optionally exclude a list of file descriptors from being closed, allowing
access to those file descriptors from the command.
"""

import os
import sys

try:
    MAXFD = os.sysconf('SC_OPEN_MAX')
except (AttributeError, ValueError):
    MAXFD = 256

_active = []

def _cleanup():
    for inst in _active[:]:
        inst.poll()

class xPopen3:
    """Class representing a child process.  Normally instances are created
    by the factory functions popen2() and popen3()."""

    sts = -1                    # Child not completed yet

    def __init__(self, cmd, capturestderr=False, bufsize=-1, passfd=(), env=None):
        """The parameter 'cmd' is the shell command to execute in a
        sub-process.  The 'capturestderr' flag, if true, specifies that
        the object should capture standard error output of the child process.
        The default is false.  If the 'bufsize' parameter is specified, it
        specifies the size of the I/O buffers to/from the child process."""
        _cleanup()
        self.passfd = passfd
        p2cread, p2cwrite = os.pipe()
        c2pread, c2pwrite = os.pipe()
        if capturestderr:
            errout, errin = os.pipe()
        self.pid = os.fork()
        if self.pid == 0:
            # Child
            os.dup2(p2cread, 0)
            os.dup2(c2pwrite, 1)
            if capturestderr:
                os.dup2(errin, 2)
            self._run_child(cmd)
        os.close(p2cread)
        self.tochild = os.fdopen(p2cwrite, 'w', bufsize)
        os.close(c2pwrite)
        self.fromchild = os.fdopen(c2pread, 'r', bufsize)
        if capturestderr:
            os.close(errin)
            self.childerr = os.fdopen(errout, 'r', bufsize)
        else:
            self.childerr = None
        _active.append(self)

    def _run_child(self, cmd):
        if isinstance(cmd, basestring):
            cmd = ['/bin/sh', '-c', cmd]
        for i in range(3, MAXFD):
            if i in self.passfd:
                continue
            try:
                os.close(i)
            except OSError:
                pass
        try:
            os.execvp(cmd[0], cmd)
            if env is None:
                os.execvp(cmd[0], cmd)
            else:
                os.execvpe(cmd[0], cmd, env)
        finally:
            os._exit(127)

    def poll(self):
        """Return the exit status of the child process if it has finished,
        or -1 if it hasn't finished yet."""
        if self.sts < 0:
            try:
                pid, sts = os.waitpid(self.pid, os.WNOHANG)
                if pid == self.pid:
                    self.sts = sts
                    _active.remove(self)
            except os.error:
                pass
        return self.sts

    def wait(self):
        """Wait for and return the exit status of the child process."""
        if self.sts < 0:
            pid, sts = os.waitpid(self.pid, 0)
            if pid == self.pid:
                self.sts = sts
                _active.remove(self)
        return self.sts


def xpopen2(cmd, bufsize=-1, mode='t', passfd=[], env=None):
    """Execute the shell command 'cmd' in a sub-process.  If 'bufsize' is
    specified, it sets the buffer size for the I/O pipes.  The file objects
    (child_stdout, child_stdin) are returned."""
    inst = xPopen3(cmd, False, bufsize, passfd, env)
    return inst.fromchild, inst.tochild

def xpopen3(cmd, bufsize=-1, mode='t', passfd=[], env=None):
    """Execute the shell command 'cmd' in a sub-process.  If 'bufsize' is
    specified, it sets the buffer size for the I/O pipes.  The file objects
    (child_stdout, child_stdin, child_stderr) are returned."""
    inst = xPopen3(cmd, True, bufsize, passfd, env)
    return inst.fromchild, inst.tochild, inst.childerr

def call(*popenargs, **kwargs):
    """Run command with arguments.  Wait for command to complete, then
    return the status.

    The arguments are the same as for the xPopen3 constructor.  Example:

    status = call("ls -l")
    """
    return xPopen3(*popenargs, **kwargs).wait()
