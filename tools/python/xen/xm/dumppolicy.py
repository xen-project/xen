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
"""Display currently enforced policy (low-level hypervisor representation).
"""
import os
import sys
import base64
import tempfile
import commands
from xen.util.xsm.xsm import XSMError, err, dump_policy, dump_policy_file
from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.xm.main import server
from xen.util import xsconstants

DOM0_UUID = "00000000-0000-0000-0000-000000000000"

def help():
    return """
    Retrieve and print currently enforced hypervisor policy information
    (low-level)."""

def main(argv):
    if len(argv) != 1:
        raise OptionError("No arguments expected.")

    if xm_main.serverType == xm_main.SERVER_XEN_API:
        try:
            bin_pol = server.xenapi.ACMPolicy.get_enforced_binary()
            if bin_pol:
                dom0_ssid = server.xenapi.ACMPolicy.get_VM_ssidref(DOM0_UUID)
                bin = base64.b64decode(bin_pol)
                try:
                    fd, filename = tempfile.mkstemp(suffix=".bin")
                    os.write(fd, bin)
                    os.close(fd)
                    dump_policy_file(filename, dom0_ssid)
                finally:
                    os.unlink(filename)
            else:
                err("No policy is installed.")
        except Exception, e:
            err("An error occurred getting the running policy: %s" % str(e))
    else:
        dump_policy()

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))    
        sys.exit(-1)


