# Misc utility functions for Xend
# (c) 2004 Mark A. Williamson <mark.williamson@cl.cam.ac.uk>

from twisted.internet import utils
from twisted.internet import reactor
from twisted.internet import protocol
from XendLogging import log
from StringIO import StringIO

import os

# This is rather distasteful.  Twisted doesn't play nicely with Python's
# standard os.popen, so here's an implementation of a synchronous popen that
# should work reliably. - MAW
def popen(cmd):
    global done_flag, result

    done_flag = False
    result = ''

    class PopenProtocol(protocol.ProcessProtocol):
        def connectionMade(self):
            self.transport.closeStdin() # we don't want stdin
        def outReceived(self, data):
            global result
            result = result + data
#        def errReceived(self, errdata):
#            log.debug("popen: %s" % errdata)
        def processEnded(self,status_obj):
            code = status_obj.value.exitCode
            if code:
                # todo: Should consider throwing an exception here.
                log.debug("popen: process exit with code %d" % code)
            global done_flag
            done_flag = True

    # using cmd.split is quick and dirty.  OK as long as people don't try anything
    # tricky with quotes, etc.
    args = cmd.split(' ')
    reactor.spawnProcess(PopenProtocol(), args[0], args, os.environ)

    # Ick!  Sit and ask the reactor to do IO, until the process finishes.
    # Can't just do "pass" here because then the reactor won't run at all :-(
    while not done_flag:
        reactor.iterate()

    return StringIO(result)
