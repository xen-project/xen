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
# Author: Machon Gregory <mbgrego@tycho.ncsc.mil> 
#============================================================================

"""Get the current mode of the Flask XSM module.
"""

from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.xm.main import server
from xen.util import xsconstants

def help():
    return """
    Usage: xm getenforce

    Returns the current mode (Permissive, Enforcing) of the
    Flask XSM module."""

def getenforce():
    if xm_main.serverType == xm_main.SERVER_XEN_API:
        if xsconstants.XS_POLICY_FLASK != \
                int(server.xenapi.XSPolicy.get_xstype()):
            raise OptionError("Unsupported policy type")
        mode = int(server.xenapi.XSPolicy.getenforce())
    else:
        if server.xend.security.on() != xsconstants.XS_POLICY_FLASK:
            raise OptionError("Unsupported policy type")
        mode = server.xend.security.getenforce()
    
    if mode == 0:
        print "Permissive"
    elif mode == 1:
        print "Enforcing"

def main(argv): 
    if "-?" in argv:
        help()
        return

    if len(argv) != 1:
        raise OptionError("No arguments expected.")

    getenforce()

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: %s\n' % str(e))    
        sys.exit(-1)

    
