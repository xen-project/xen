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
# Copyright (C) 2009 Fujitsu Technology Solutions
#============================================================================

""" Create a new managed cpupool.
"""

import sys
from xen.xm.main import serverType, SERVER_XEN_API, server
from xen.xm.cpupool import parseCommandLine, err, help as help_options
from xen.util.sxputils import sxp2map


def help():
    return help_options()


def main(argv):
    try:
        (opts, config) = parseCommandLine(argv)
    except StandardError, ex:
        err(str(ex))

    if not opts:
        return

    if serverType == SERVER_XEN_API:
        record = sxp2map(config)
        if type(record.get('proposed_CPUs', [])) != list:
            record['proposed_CPUs'] = [record['proposed_CPUs']]
        server.xenapi.cpu_pool.create(record)
    else:
        server.xend.cpu_pool.new(config)

if __name__ == '__main__':
    main(sys.argv)

