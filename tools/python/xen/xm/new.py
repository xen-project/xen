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
# Copyright (C) 2006 XenSource Ltd
#============================================================================

import os
import xmlrpclib

from xen.xend import PrettyPrint
from xen.xend import sxp
from xen.xend import XendClient

from xen.xm.main import serverType, SERVER_XEN_API
from xen.xm.xenapi_create import *

from opts import *
from create import *

def make_unstarted_domain(opts, config):
    """Create an unstarted domain.

    @param opts:   options
    @param config: configuration
    """
    try:
        server.xend.domain.new(config)
    except xmlrpclib.Fault, ex:
        if ex.faultCode == XendClient.ERROR_INVALID_DOMAIN:
            err("the domain '%s' does not exist." % ex.faultString)
        else:
            err("%s" % ex.faultString)
    except Exception, ex:
        err(str(ex))


def main(argv):
    try:
        (opts, config) = parseCommandLine(argv)
    except StandardError, ex:
        err(str(ex))

    if not opts:
        return

    if type(config) == str:
        try:
            config = sxp.parse(file(config))[0]
        except IOError, exn:
            raise OptionError("Cannot read file %s: %s" % (config, exn[1]))

    if opts.vals.dryrun:
        PrettyPrint.prettyprint(config)
        return
    
    if serverType == SERVER_XEN_API:
        sxp2xml_inst = sxp2xml()
        doc = sxp2xml_inst.convert_sxp_to_xml(config) 
        
        xenapi_create_inst = xenapi_create()
        vm_refs = xenapi_create_inst.create(document = doc,
                                            skipdtd=opts.vals.skipdtd)
    else:       
        make_unstarted_domain(opts, config)
        
if __name__ == '__main__':
    main(sys.argv)
        
