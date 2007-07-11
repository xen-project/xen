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

def getpolicy(dumpxml):
    if xm_main.serverType != xm_main.SERVER_XEN_API:
        raise OptionError('xm needs to be configured to use the xen-api.')
    types = []
    xstype = int(server.xenapi.XSPolicy.get_xstype())
    if xstype & xsconstants.XS_POLICY_ACM:
        types.append("ACM")
        xstype ^= xsconstants.XS_POLICY_ACM
    if xstype != 0:
        types.append("unsupported (%08x)" % xstype)
    print "Supported security subsystems   : %s \n" % ", ".join(types)

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
        print "Policy installed on the system:"
        if acmpol:
            print "Policy name           : %s" % acmpol.get_name()
        print "Policy type           : %s" % xsconstants.ACM_POLICY_ID
        print "Reference             : %s" % policystate['xs_ref']
        print "Version of XML policy : %s" % policystate['version']
        state = []
        flags = int(policystate['flags'])
        if flags & xsconstants.XS_INST_LOAD:
            state.append("loaded")
        if flags & xsconstants.XS_INST_BOOT:
            state.append("system booted with")
        print "State of the policy   : %s" % ", ".join(state)
        if dumpxml:
            xml = policystate['repr']
            if xml:
                dom = minidom.parseString(xml.encode("utf-8"))
                print "%s" % dom.toprettyxml(indent="   ",newl="\n")

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
