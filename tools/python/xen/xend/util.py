# Misc utility functions for Xend
# (c) 2004 Mark A. Williamson <mark.williamson@cl.cam.ac.uk>

from twisted.internet import utils
from twisted.internet import reactor
from XendLogging import log
from StringIO import StringIO

# This is rather distasteful.  Twisted doesn't play nicely with Python's
# standard os.popen, so here's an implementation of a synchronous popen that
# should work reliably. - MAW
def popen(cmd):
    global done_flag, result

    done_flag = False
    result = ''
    
    def done(output):
        global done_flag, result
        done_flag = True
        result = output

    def err(output):
        global done_flag
# For normal use, suppress debug output here.  It grumbles about stderr if the
# program exits with $? != 0, even if stderr is redirected.  Grrr!
#        log.debug("util.popen(\'%s\'): %s" % (cmd, output))
        done_flag = True

    d = utils.getProcessOutput(cmd)
    d.addCallbacks(done, err)

    while not done_flag:
        reactor.iterate()

    return StringIO(result)
