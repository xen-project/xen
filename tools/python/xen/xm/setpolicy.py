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

import base64
import struct
import sys
import string
from xen.util import xsconstants
from xen.util.acmpolicy import ACMPolicy
from xen.xm.opts import OptionError
from xen.util.security import policy_dir_prefix
from xen.xm import main as xm_main
from xen.xm.main import server

def help():
    return """
    Usage: xm setpolicy <policytype> <policy> [options]

    Set the policy managed by xend.

    The only policytype that is currently supported is 'ACM'.

    The following options are defined
      --load     Load the policy immediately
      --boot     Have the system load the policy during boot
      --update   Automatically adapt the policy so that it will be
                 treated as an update to the current policy
    """

def create_update_xml(xml):
    """
        Adapt the new policy's xml header to be a simple type of an
        update to the currently enforce policy on the remote system.
        Increases the minor number by '1'.
    """
    policystate = server.xenapi.XSPolicy.get_xspolicy()
    if int(policystate['type']) == 0:
        return xml
    curpol = ACMPolicy(xml = policystate['repr'])
    curpol_version = curpol.get_version()
    tmp = curpol_version.split('.')
    if len(tmp) == 2:
        maj = int(tmp[0])
        min = int(tmp[1])
    else:
        maj = int(tmp)
        min = 0
    min += 1
    newpol_version = ""+str(maj)+"."+str(min)

    newpol = ACMPolicy(xml = xml)
    newpol.set_frompolicy_name(curpol.get_name())
    newpol.set_frompolicy_version(curpol.get_version())
    newpol.set_policy_version(newpol_version)
    return newpol.toxml()

def setpolicy(policytype, policy_name, flags, overwrite, is_update=False):
    if xm_main.serverType != xm_main.SERVER_XEN_API:
        raise OptionError('xm needs to be configured to use the xen-api.')
    if policytype != xsconstants.ACM_POLICY_ID:
        raise OptionError("Unsupported policytype '%s'." % policytype)
    else:
        xs_type = xsconstants.XS_POLICY_ACM

        policy_file = policy_dir_prefix + "/" + \
                      string.join(string.split(policy_name, "."), "/")
        policy_file += "-security_policy.xml"

        try:
            f = open(policy_file,"r")
            xml = f.read(-1)
            f.close()
        except:
            raise OptionError("Not a valid policy file")

        if is_update:
            xml = create_update_xml(xml)

        try:
            policystate = server.xenapi.XSPolicy.set_xspolicy(xs_type,
                                                              xml,
                                                              flags,
                                                              overwrite)
        except Exception, e:
            print "An error occurred setting the policy: %s" % str(e)
            return
        xserr = int(policystate['xserr'])
        if xserr != 0:
            print "An error occurred trying to set the policy: %s" % \
                  xsconstants.xserr2string(abs(xserr))
            errors = policystate['errors']
            if len(errors) > 0:
                print "Hypervisor reported errors:"
                err = base64.b64decode(errors)
                i = 0
                while i + 7 < len(err):
                    code, data = struct.unpack("!ii", errors[i:i+8])
                    print "(0x%08x, 0x%08x)" % (code, data)
                    i += 8
        else:
            print "Successfully set the new policy."


def main(argv):
    if len(argv) < 3:
       raise OptionError("Need at least 3 arguments.")

    if "-?" in argv:
        help()
        return

    policytype  = argv[1]
    policy_name = argv[2]
    is_update = False

    flags = 0
    if '--load' in argv:
        flags |= xsconstants.XS_INST_LOAD
    if '--boot' in argv:
        flags |= xsconstants.XS_INST_BOOT
    if '--update' in argv:
        is_update = True

    overwrite = True
    if '--nooverwrite' in argv:
        overwrite = False

    setpolicy(policytype, policy_name, flags, overwrite, is_update)

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))
        sys.exit(-1)
