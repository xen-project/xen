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
#
# Copyright (c) 2005 XenSource Ltd


import re
import sys

from xen.xend import sxp

from xen.xend.XendClient import server
from xen.xend.XendError import XendError
from xen.xend.xenstore.xstransact import xstransact

import xen.xend.XendProtocol


domain = None
domid = None
deviceClass = None
device = None
frontendPath = None
backendPath = None


def diagnose(dom):
    global domain
    global domid
    global dompath
    
    try:
        domain = server.xend_domain(dom)
        state = sxp.child_value(domain, 'state')
        domid = int(sxp.child_value(domain, 'domid'))
        name = sxp.child_value(domain, 'name')
        dompath = '/local/domain/%d' % domid

        print "Domain ID is %d." % domid
        print "Domain name is %s." % name

        if not state:
            raise XendError("Cannot find state")

        if state.find('c') != -1:
            print "Domain has crashed."

        diagnose_console()

        diagnose_devices()
    except xen.xend.XendProtocol.XendError, exn:
        print exn


def diagnose_console():
    port    = xstransact.Read(dompath + '/console/port')
    ringref = xstransact.Read(dompath + '/console/ring-ref')
    tty     = xstransact.Read(dompath + '/console/tty')

    if not port:
        print "Console port is missing; Xend has failed."
    if not ringref:
        print "Console ring-ref is missing; Xend has failed."
    if not tty:
        print "Console tty is missing; Xenconsoled has failed."


def diagnose_devices():
    global deviceClass
    global device
    global frontendPath
    global backendPath
    
    device_path = dompath + '/device'

    device_classes = xstransact.List(device_path)

    print "Found %d device classes in use." % len(device_classes)

    for dc in device_classes:
        deviceClass = dc
        device_class_path = device_path + '/' + deviceClass

        devices = xstransact.List(device_class_path)

        print "Found %d %s devices." % (len(devices), deviceClass)

        for d in devices:
            device = d
            
            print "Found device %s, %s." % (deviceClass, device)

            frontendPath = device_class_path + '/' + device
            backendPath = xstransact.Read(frontendPath, 'backend')

            if not backendPath:
                print ("Cannot find backend path for device %s, %s." %
                       (deviceClass, device))
            else:
                backend_error = xstransact.Read(backendPath, 'error')

                if backend_error:
                    diagnose_device_error(backend_error)


def diagnose_device_error(err):
    if re.search("2 reading .*/ring-ref and event-channel", err):
        print ("Backend is stuck waiting for frontend for device %s, %s." %
               (deviceClass, device))
        diagnose_stuck_frontend()
    else:
        print ("Device %s, %s shows error %s." %
               (deviceClass, device, err))


def diagnose_stuck_frontend():
    if deviceClass == "vbd":
        phy = xstransact.Read(backendPath, 'physical-device')

        if phy:
            print ("Device %s, %s hotplugging has completed successfully." %
                   (deviceClass, device))
        else:
            print ("Device %s, %s hotplugging failed." %
                   (deviceClass, device))


def main(argv = None):
    if argv is None:
        argv = sys.argv

    diagnose(argv[1])

    return 0


if __name__ == "__main__":
    sys.exit(main())
