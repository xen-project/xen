#!/usr/bin/python

"""
 Copyright (C) International Business Machines Corp., 2005
 Author: Dan Smith <danms@us.ibm.com>

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; under version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""

##
## These are utility functions for test cases
##

import sys
import commands
import os
import pwd
import time
import pty
import select
import signal
import re
import glob

TEST_PASS = 0
TEST_FAIL = 255
TEST_SKIP = 77

# We currently advise waiting this many seconds for the ramdisk to
# boot inside a domU
TEST_DOMU_BOOT_DELAY = 20

if os.environ.get("TEST_VERBOSE"):
    verbose = True
else:
    verbose = False

class TimeoutError(Exception):
    def __init__(self, msg, outputSoFar):
        self.msg = msg
        self.output = outputSoFar

    def __str__(self):
        return str(self.msg)

def runWithTimeout(cmd, timeout):
    args = cmd.split()

    pid, fd = pty.fork();

    startTime = time.time()

    if pid == 0:
        os.execvp(args[0], args)

    output = ""

    while time.time() - startTime < timeout:
        i, o, e = select.select([fd], [], [], timeout)

        if fd in i:
            try:
                str = os.read(fd, 1)
                output += str
            except OSError, e:
                exitPid, status = os.waitpid(pid, os.WNOHANG)

                if exitPid == pid:
                    if verbose:
                        print "Child exited with %i" % status
                    return status, output

    if verbose:
        print "Command timed out: killing pid %i" % pid
        
    os.kill(pid, signal.SIGINT)
    raise TimeoutError("Command execution time exceeded %i seconds" % timeout,
                       outputSoFar=output)

def traceCommand(command, timeout=None, logOutput=True):
    if verbose:
        print "[dom0] Running `%s'" % command

    if timeout:
        status, output = runWithTimeout(command, timeout)
    else:
        status, output = commands.getstatusoutput(command)

    if logOutput and verbose:
        print output

    return status, output

def getTestName():
    script = sys.argv[0]
    fname = os.path.basename(script)
    match = re.match("([^\.]+)\.[a-z]+", fname)
    if match:
        tname = match.group(1)
    else:
        tname = "UNKNOWN"

    return tname

def becomeNonRoot():
    """Become a non-root user, or FAIL if this is not possible.  This call
    succeeds if we are already running as a non-root user.
    """
    
    if os.geteuid() == 0:
        # Try and become "nobody".  This user is commonly in place, but this
        # could be extended to consider any number of users to be acceptable,
        # if there are systems where "nobody" is not present.
        allusers = pwd.getpwall()
        for u in allusers:
            if u[0] == "nobody":
                os.setreuid(u[2], u[2])
                break
        if os.geteuid() == 0:
            FAIL("Could not become a non-root user")

def FAIL(format, *args):
    print "\nREASON:", (format % args)
    sys.exit(TEST_FAIL)

def SKIP(format, *args):
    print "\nREASON:", (format % args)
    sys.exit(TEST_SKIP)

def saveLog(logText, filename=None):
    if not filename:
        filename = "log";
    logfile = open(filename, 'w');
    date = commands.getoutput("date");
    logfile.write("-- BEGIN XmTest Log @" + date + "\n");
    logfile.write(logText);
    logfile.write("\n-- END XmTest Log\n");
    logfile.close();

def waitForBoot():
    if verbose:
        print "[dom0] Waiting %i seconds for domU boot..." % TEST_DOMU_BOOT_DELAY
    time.sleep(TEST_DOMU_BOOT_DELAY)

def timeStamp():
    name = getTestName()

    t = time.asctime(time.localtime())

    print "*** Test %s started at %s %s" % (name, t,
                                            time.tzname[time.daylight])

#
# Try to start a domain and attach a console to it to see if
# the console system is working
#
def isConsoleDead():

    from XmTestLib import XmTestDomain, DomainError, XmConsole, ConsoleError

    domain = XmTestDomain()

    try:
        console = domain.start()
        console.runCmd("ls")
    except DomainError, e:
        return True
    except ConsoleError, e:
        domain.destroy()
        return True

    domain.destroy()

    return False

#
# We currently can only load as many concurrent HVM domains as loop 
# devices, need to find how many devices the system has.
def getMaxHVMDomains():
    nodes = glob.glob("/dev/loop*")
    maxd = len(nodes)

    return maxd


if __name__ == "__main__":

    timeStamp()

    FAIL("foo")

