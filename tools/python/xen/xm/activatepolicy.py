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
# Copyright (C) 2007 International Business Machines Corp.
# Author: Stefan Berger <stefanb@us.ibm.com>
#============================================================================

"""Activate the managed policy of the system.
"""

import sys
from xen.util import xsconstants
from xml.dom import minidom
from xen.xm.opts import OptionError
from xen.xm import getpolicy
from xen.xm import main as xm_main
from xen.xm.main import server

def help():
    return """
    Usage: xm activatepolicy [options]

    Activate the xend-managed policy.

    The following options are defined:
      --load     Load the policy into the hypervisor.
      --boot     Have the system boot with the policy. Changes the default
                 title in grub.conf.
      --noboot   Remove the policy from the default entry in grub.conf.
    """

def activate_policy(flags):
    policystate = server.xenapi.XSPolicy.get_xspolicy()
    xs_ref = policystate['xs_ref']
    if int(policystate['type']) == 0 or xs_ref == "":
        print "No policy is installed."
        return
    rc = int(server.xenapi.XSPolicy.activate_xspolicy(xs_ref, flags))
    if rc == flags:
        print "Successfully activated the policy."
    else:
        print "An error occurred trying to activate the policy: %s" % \
              xsconstants.xserr2string(rc)

def remove_bootpolicy():
    server.xenapi.XSPolicy.rm_xsbootpolicy()

def main(argv):
    if xm_main.serverType != xm_main.SERVER_XEN_API:
        raise OptionError('xm needs to be configured to use the xen-api.')
    flags = 0
    c = 1

    while c < len(argv):
        if '--boot' == argv[c]:
            flags |= xsconstants.XS_INST_BOOT
        elif '--load' == argv[c]:
            flags |= xsconstants.XS_INST_LOAD
        elif '--noboot' == argv[c]:
            remove_bootpolicy()
        else:
            raise OptionError("Unknown command line option '%s'" % argv[c])
        c += 1

    if flags != 0:
        activate_policy(flags)

    getpolicy.getpolicy(False)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
