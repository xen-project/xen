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

DOM0_UUID = "00000000-0000-0000-0000-000000000000"

DEFAULT_policy_template = \
"<?xml version=\"1.0\" ?>" +\
"<SecurityPolicyDefinition xmlns=\"http://www.ibm.com\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.ibm.com ../../security_policy.xsd\">" +\
"  <PolicyHeader>" +\
"    <PolicyName>DEFAULT</PolicyName>" +\
"    <Version>1.0</Version>" +\
"  </PolicyHeader>" +\
"  <SimpleTypeEnforcement>" +\
"    <SimpleTypeEnforcementTypes>" +\
"      <Type>SystemManagement</Type>" +\
"    </SimpleTypeEnforcementTypes>" +\
"  </SimpleTypeEnforcement>" +\
"  <ChineseWall>" +\
"    <ChineseWallTypes>" +\
"      <Type>SystemManagement</Type>" +\
"    </ChineseWallTypes>" +\
"  </ChineseWall>" +\
"  <SecurityLabelTemplate>" +\
"    <SubjectLabels bootstrap=\"SystemManagement\">" +\
"      <VirtualMachineLabel>" +\
"        <Name%s>SystemManagement</Name>" +\
"        <SimpleTypeEnforcementTypes>" +\
"          <Type>SystemManagement</Type>" +\
"        </SimpleTypeEnforcementTypes>" +\
"        <ChineseWallTypes>" +\
"          <Type/>" +\
"        </ChineseWallTypes>" +\
"      </VirtualMachineLabel>" +\
"    </SubjectLabels>" +\
"  </SecurityLabelTemplate>" +\
"</SecurityPolicyDefinition>"


def help():
    return """
    Reset the system's policy to the default.

    When the system's policy is reset, all guest VMs should be halted,
    since otherwise this operation will fail.
    """

def get_reset_policy_xml(dom0_seclab):
    if dom0_seclab == "":
        return DEFAULT_policy_template % ""
    else:
        poltyp, policy, label = dom0_seclab.split(":")
        if label != "SystemManagement":
            return DEFAULT_policy_template % \
                   (" from=\"%s\"" % label)
        else:
            return DEFAULT_policy_template % ""

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

        seclab = server.xenapi.VM.get_security_label(DOM0_UUID)
        xml = get_reset_policy_xml(seclab)
        try:
            policystate = server.xenapi.XSPolicy.set_xspolicy(xs_type,
                                                              xml,
                                                              flags,
                                                              True)
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

        seclab = server.xend.security.get_domain_label(0)
        if seclab[0] == '\'':
            seclab =  seclab[1:]
        xml = get_reset_policy_xml(seclab)
        rc, errors = server.xend.security.set_policy(xs_type,
                                                     xml,
                                                     flags,
                                                     True)
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
