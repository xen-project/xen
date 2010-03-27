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
# Copyright (c) 2005-2006 XenSource Inc


import re
import socket
import sys

from xen.xend import sxp

from xen.xend.XendClient import server
from xen.xend.XendError import XendError
from xen.xend.xenstore.xstransact import xstransact
from xen.xend.server import DevConstants

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
        domain = server.xend.domain(dom)
        state = sxp.child_value(domain, 'state')
        domid = int(sxp.child_value(domain, 'domid'))
        name = sxp.child_value(domain, 'name')

        print "Domain ID is %d." % domid
        print "Domain name is %s." % name

        if not state:
            raise XendError("Cannot find state")

        if state.find('c') != -1:
            print "Domain has crashed."
    except socket.error, exn:
        print "Cannot contact Xend."

        try:
            domid = int(dom)
            name = dom
        except ValueError:
            print \
"Without Xend, you will have to specify the domain ID, not the domain name."
            sys.exit(1)
    except xen.xend.XendProtocol.XendError, exn:
        print exn
        sys.exit(1)

    dompath = '/local/domain/%d' % domid
    diagnose_console()
    diagnose_devices()


def diagnose_console():
    port    = xstransact.Read(dompath + '/console/port')
    ringref = xstransact.Read(dompath + '/console/ring-ref')
    tty     = xstransact.Read(dompath + '/serial/0/tty')

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
                frontend_state = xstransact.Read(frontendPath, 'state')
                backend_state  = xstransact.Read(backendPath,  'state')

                print "Backend is in state %s." %  stateString(backend_state)
                print "Frontend is in state %s." % stateString(frontend_state)

                check_for_error(True)
                check_for_error(False)

                diagnose_hotplugging()


def check_for_error(backend):
    if backend:
        path = backendPath.replace('backend/', 'error/backend/')
    else:
        path = frontendPath.replace('device/', 'error/device/')

    err = xstransact.Read(path, 'error')

    if err:
        print ("%s for device %s, %s shows error %s." %
               (backend and 'Backend' or 'Frontend', deviceClass, device,
                err))


def diagnose_hotplugging():
    if deviceClass == 'vbd':
        phy = xstransact.Read(backendPath, 'physical-device')

        if phy:
            print ('Device %s, %s hotplugging has completed successfully, '
                   'and is connected to physical device %s.' %
                   (deviceClass, device, phy))
        else:
            print ('Device %s, %s hotplugging failed.' %
                   (deviceClass, device))
    elif deviceClass == 'vif':
        handle = xstransact.Read(backendPath, 'handle')

        if handle:
            print ('Device %s, %s hotplugging has completed successfully, '
                   'and is using handle %s.' %
                   (deviceClass, device, handle))
        else:
            print ('Device %s, %s hotplugging failed.' %
                   (deviceClass, device))


def stateString(state):
    return state and DevConstants.xenbusState[int(state)] or '<None>'


def main(argv = None):
    if argv is None:
        argv = sys.argv

    diagnose(argv[1])

    return 0


if __name__ == "__main__":
    sys.exit(main())
