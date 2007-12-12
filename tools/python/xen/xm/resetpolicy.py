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
""" Reset the system's current policy to the default state.
"""
import sys
import xen.util.xsm.xsm as security
from xen.util.xsm.xsm import XSMError
from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.xm.main import server
from xen.util import xsconstants
from xen.util.acmpolicy import ACMPolicy


def help():
    return """
    Reset the system's policy to the default.

    When the system's policy is reset, all guest VMs should be halted,
    since otherwise this operation will fail.
    """


def resetpolicy():
    msg = None
    xs_type = xsconstants.XS_POLICY_ACM
    flags = xsconstants.XS_INST_LOAD

    if xm_main.serverType == xm_main.SERVER_XEN_API:
        if int(server.xenapi.XSPolicy.get_xstype()) & xs_type == 0:
            raise security.XSMError("ACM policy type not supported.")

        policystate = server.xenapi.XSPolicy.get_xspolicy()

        acmpol = ACMPolicy(xml=policystate['repr'])

        now_flags = int(policystate['flags'])

        if now_flags & xsconstants.XS_INST_BOOT == 0 and \
           not acmpol.is_default_policy():
            msg = "Old policy not found in bootloader file."

        try:
            policystate = server.xenapi.XSPolicy.reset_xspolicy(xs_type)
        except Exception, e:
            raise security.XSMError("An error occurred resetting the "
                                    "policy: %s" % str(e))

        xserr = int(policystate['xserr'])
        if xserr != xsconstants.XSERR_SUCCESS:
            raise security.XSMError("Could not reset the system's policy. "
                                    "Try to halt all guests.")
        else:
            print "Successfully reset the system's policy."
            if msg:
                print msg
    else:
        if server.xend.security.get_xstype() & xs_type == 0:
           raise security.XSMError("ACM policy type not supported.")

        xml, now_flags = server.xend.security.get_policy()

        acmpol = ACMPolicy(xml=xml)

        if int(now_flags) & xsconstants.XS_INST_BOOT == 0 and \
           not acmpol.is_default_policy():
            msg = "Old policy not found in bootloader file."

        rc, errors = server.xend.security.reset_policy()
        if rc != xsconstants.XSERR_SUCCESS:
            raise security.XSMError("Could not reset the system's policy. "
                                    "Try to halt all guests.")
        else:
            print "Successfully reset the system's policy."
            if msg:
                print msg


def main(argv):
    if len(argv) != 1:
        raise OptionError("No arguments expected.")

    resetpolicy()


if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
