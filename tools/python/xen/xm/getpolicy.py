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

"""Get the managed policy of the system.
"""

import sys
from xen.util import xsconstants
from xml.dom import minidom
from xen.xm.opts import OptionError
from xen.util.acmpolicy import ACMPolicy
from xen.xm import main as xm_main
from xen.xm.main import server

def help():
    return """
    Usage: xm getpolicy [options]

    The following options are defined
      --dumpxml     Display the XML of the policy

    Get the policy managed by xend."""


def display_policy_info(acmpol, policytype, uuid, version, flags,
                        dumpxml, xml):
    print "Policy name           : %s" % acmpol.get_name()
    print "Policy type           : %s" % policytype
    if uuid:
        print "Reference             : %s" % uuid
    print "Version of XML policy : %s" % version

    state = []
    if flags & xsconstants.XS_INST_LOAD:
        state.append("loaded")
    if flags & xsconstants.XS_INST_BOOT:
        state.append("activated for boot")
    print "Policy configuration  : %s" % ", ".join(state)
    if dumpxml:
        if xml:
            dom = minidom.parseString(xml.encode("utf-8"))
            print "%s" % dom.toprettyxml(indent="   ",newl="\n")


def display_security_subsystems(xstype):
    types = []
    if xstype & xsconstants.XS_POLICY_ACM:
        types.append("ACM")
        xstype ^= xsconstants.XS_POLICY_ACM
    if xstype != 0:
        types.append("unsupported (%08x)" % xstype)
    if len(types) == 0:
        types.append("None")
    print "Supported security subsystems   : %s \n" % ", ".join(types)


def getpolicy(dumpxml):
    if xm_main.serverType == xm_main.SERVER_XEN_API:
        xstype = int(server.xenapi.XSPolicy.get_xstype())
        display_security_subsystems(xstype)

        policystate = server.xenapi.XSPolicy.get_xspolicy()
        if int(policystate['type']) == 0:
            print "No policy is installed."
            return
        if int(policystate['type']) != xsconstants.XS_POLICY_ACM:
            print "Unknown policy type '%s'." % policystate['type']
        else:
            xml = policystate['repr']
            acmpol = None
            if xml:
                acmpol = ACMPolicy(xml=xml)

            display_policy_info(acmpol,
                                xsconstants.ACM_POLICY_ID,
                                policystate['xs_ref'],
                                policystate['version'],
                                int(policystate['flags']),
                                dumpxml,
                                xml)
    else:
        xstype = server.xend.security.get_xstype()
        display_security_subsystems(xstype)

        xml, flags = server.xend.security.get_policy()
        acmpol = None
        if xml != "":
            dom = None
            try:
                dom = minidom.parseString(xml)
                if dom:
                    acmpol = ACMPolicy(dom=dom)
            except Exception, e:
                print "Error parsing the library: " + str(e)

        if acmpol:
            display_policy_info(acmpol,
                                xsconstants.ACM_POLICY_ID,
                                None,
                                acmpol.get_version(),
                                flags,
                                dumpxml,
                                xml)
        else:
            print "No policy is installed."

def main(argv):
    dumpxml = False

    if '--dumpxml' in argv:
        dumpxml = True

    getpolicy(dumpxml)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
