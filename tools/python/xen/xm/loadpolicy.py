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
# Copyright (C) 2006 International Business Machines Corp.
# Author: Reiner Sailer <sailer@us.ibm.com>
#============================================================================

"""Loading a compiled binary policy into the hypervisor.
"""
import sys
import traceback
from xen.util.xsm.xsm import XSMError, err, load_policy
from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.util import xsconstants
from xen.xm.activatepolicy import activate_policy
from xen.xm.main import server
from xen.util.acmpolicy import ACMPolicy

def help():
    return """Load the compiled binary (.bin) policy into the running
    hypervisor."""

def main(argv):
    if len(argv) != 2:
        raise OptionError('No policy defined')
    if xm_main.serverType == xm_main.SERVER_XEN_API:
        policy = argv[1]
        print "This command is deprecated for use with Xen-API " \
              "configuration. Consider using\n'xm activatepolicy'."
        policystate = server.xenapi.XSPolicy.get_xspolicy()
        if int(policystate['type']) == 0:
            print "No policy is installed."
            return

        if int(policystate['type']) != xsconstants.XS_POLICY_ACM:
            print "Unknown policy type '%s'." % policystate['type']
            return
        else:
            xml = policystate['repr']
            xs_ref = policystate['xs_ref']
            if not xml:
                OptionError("No policy installed on system?")
            acmpol = ACMPolicy(xml=xml)
            if acmpol.get_name() != policy:
                OptionError("Policy installed on system '%s' does not match"\
                            " the request policy '%s'" % \
                            (acmpol.get_name(), policy))
            activate_policy(xsconstants.XS_INST_LOAD)
    else:
        load_policy(argv[1])

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
        
