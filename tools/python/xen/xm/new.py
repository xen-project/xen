#============================================================================
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
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2006 XenSource Ltd
#============================================================================

import os
import xmlrpclib

from xen.xend import PrettyPrint
from xen.xend import sxp
from xen.xend import XendClient
from xen.xend.XendClient import server

from xen.xm.opts import *
from xen.xm.create import *

def make_unstarted_domain(opts, config):
    """Create an unstarted domain.

    @param opts:   options
    @param config: configuration
    """
    try:
        server.xend.domain.new(config)
    except xmlrpclib.Fault, ex:
        import signal
        if vncpid:
            os.kill(vncpid, signal.SIGKILL)
        if ex.faultCode == XendClient.ERROR_INVALID_DOMAIN:
            err("the domain '%s' does not exist." % ex.faultString)
        else:
            err("%s" % ex.faultString)
    except Exception, ex:
        import signal
        if vncpid:
            os.kill(vncpid, signal.SIGKILL)
        err(str(ex))


def main(argv):
    try:
        (opts, config) = parseCommandLine(argv)
    except StandardError, ex:
        err(str(ex))

    if not opts:
        return

    if opts.vals.dryrun:
        PrettyPrint.prettyprint(config)
    else:
        make_unstarted_domain(opts, config)
        
if __name__ == '__main__':
    main(sys.argv)
        
