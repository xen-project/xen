# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Support for virtual block devices.
"""

import os
import re
import string

from xen.xend.XendError import XendError, VmError
from xen.xend import XendRoot
from xen.xend.XendLogging import log
from xen.xend import sxp
from xen.xend import Blkctl

import channel
from controller import CtrlMsgRcvr, Dev, DevController
from messages import *

from xen.util.ip import _readline, _readlines

def expand_dev_name(name):
    if not name:
        return name
    if re.match( '^/dev/', name ):
        return name
    else:
        return '/dev/' + name

def blkdev_name_to_number(name):
    """Take the given textual block-device name (e.g., '/dev/sda1',
    'hda') and return the device number used by the OS. """

    n = expand_dev_name(name)

    try:
        return os.stat(n).st_rdev
    except Exception, ex:
        log.debug("exception looking up device number for %s: %s", name, ex)
        pass

    if re.match( '/dev/sd[a-p]([0-9]|1[0-5])', n):
        return 8 * 256 + 16 * (ord(n[7:8]) - ord('a')) + int(n[8:])

    if re.match( '/dev/hd[a-t]([1-9]|[1-5][0-9]|6[0-3])?', n):
        ide_majors = [ 3, 22, 33, 34, 56, 57, 88, 89, 90, 91 ]
        major = ide_majors[(ord(n[7:8]) - ord('a')) / 2]
        minor = ((ord(n[7:8]) - ord('a')) % 2) * 64 + int(n[8:] or 0)
        return major * 256 + minor

    # see if this is a hex device number
    if re.match( '^(0x)?[0-9a-fA-F]+$', name ):
        return string.atoi(name,16)
        
    return None

def blkdev_segment(name):
    """Take the given block-device name (e.g. '/dev/sda1', 'hda')
    and return a dictionary { device, start_sector,
    nr_sectors, type }
        device:       Device number of the given partition
        start_sector: Index of first sector of the partition
        nr_sectors:   Number of sectors comprising this partition
        type:         'Disk' or identifying name for partition type
    """
    val = None
    n = blkdev_name_to_number(name)
    if n:
        val = { 'device'       : n,
                'start_sector' : long(0),
                'nr_sectors'   : long(1L<<63),
                'type'         : 'Disk' }
    return val

def mount_mode(name):
    mode = None
    name = expand_dev_name(name)
    lines = _readlines(os.popen('mount 2>/dev/null'))
    exp = re.compile('^' + name + ' .*[\(,]r(?P<mode>[ow])[,\)]')
    for line in lines:
        pm = exp.match(line)
        if not pm: continue
        mode = pm.group('mode')
        break
    if mode == 'w':
        return mode
    if mode == 'o':
        mode = 'r'
    return mode
    
class BlkifBackend:
    """ Handler for the 'back-end' channel to a block device driver domain
    on behalf of a front-end domain.
    Must be connected using connect() before it can be used.
    """

    def __init__(self, controller, id, dom, recreate=False):
        self.controller = controller
        self.id = id
        self.frontendDomain = self.controller.getDomain()
        self.frontendChannel = None
        self.backendDomain = dom
        self.backendChannel = None
        self.destroyed = False
        self.connected = False
        self.evtchn = None
        self.status = None

    def init(self, recreate=False, reboot=False):
        self.destroyed = False
        self.status = BLKIF_INTERFACE_STATUS_DISCONNECTED
        self.frontendDomain = self.controller.getDomain()
        self.frontendChannel = self.controller.getChannel()
        cf = channel.channelFactory()
        self.backendChannel = cf.openChannel(self.backendDomain)

    def __str__(self):
        return ('<BlkifBackend frontend=%d backend=%d id=%d>'
                % (self.frontendDomain,
                   self.backendDomain,
                   self.id))

    def getId(self):
        return self.id

    def closeEvtchn(self):
        if self.evtchn:
            channel.eventChannelClose(self.evtchn)
            self.evtchn = None

    def openEvtchn(self):
        self.evtchn = channel.eventChannel(self.backendDomain, self.frontendDomain)
        
    def getEventChannelBackend(self):
        val = 0
        if self.evtchn:
            val = self.evtchn['port1']
        return val

    def getEventChannelFrontend(self):
        val = 0
        if self.evtchn:
            val = self.evtchn['port2']
        return val

    def connect(self, recreate=False):
        """Connect to the blkif control interface.

        @param recreate: true if after xend restart
        """
        log.debug("Connecting blkif %s", str(self))
        if recreate or self.connected:
            self.connected = True
            pass
        else:
            self.send_be_create()
        
    def send_be_create(self):
        log.debug("send_be_create %s", str(self))
        msg = packMsg('blkif_be_create_t',
                      { 'domid'        : self.frontendDomain,
                        'blkif_handle' : self.id })
        msg = self.backendChannel.requestResponse(msg)
        #todo: check return status
        self.connected = True

    def destroy(self, change=False, reboot=False):
        """Disconnect from the blkif control interface and destroy it.
        """
        self.send_be_disconnect()
        self.send_be_destroy()
        self.closeEvtchn()
        self.destroyed = True
        # For change true need to notify front-end, or back-end will do it?

    def send_be_disconnect(self):
        msg = packMsg('blkif_be_disconnect_t',
                      { 'domid'        : self.frontendDomain,
                        'blkif_handle' : self.id })
        self.backendChannel.writeRequest(msg)
        self.connected = False

    def send_be_destroy(self):
        msg = packMsg('blkif_be_destroy_t',
                      { 'domid'        : self.frontendDomain,
                        'blkif_handle' : self.id })
        self.backendChannel.writeRequest(msg)

    def connectInterface(self, val):
        self.openEvtchn()
        log.debug("Connecting blkif to event channel %s ports=%d:%d",
                  str(self), self.evtchn['port1'], self.evtchn['port2'])
        msg = packMsg('blkif_be_connect_t',
                      { 'domid'        : self.frontendDomain,
                        'blkif_handle' : self.id,
                        'evtchn'       : self.getEventChannelBackend(),
                        'shmem_frame'  : val['shmem_frame'] })
        msg = self.backendChannel.requestResponse(msg)
        #todo: check return status
        val = unpackMsg('blkif_be_connect_t', msg)
        self.status = BLKIF_INTERFACE_STATUS_CONNECTED
        self.send_fe_interface_status()
            
    def send_fe_interface_status(self):
        msg = packMsg('blkif_fe_interface_status_t',
                      { 'handle' : self.id,
                        'status' : self.status,
                        'domid'  : self.backendDomain,
                        'evtchn' : self.getEventChannelFrontend() })
        self.frontendChannel.writeRequest(msg)

    def interfaceDisconnected(self):
        self.status = BLKIF_INTERFACE_STATUS_DISCONNECTED
        #todo?: Close evtchn:
        #self.closeEvtchn()
        self.send_fe_interface_status()
        
    def interfaceChanged(self):
        """Notify the front-end that devices have been added or removed.
        The front-end should then probe for devices.
        """
        msg = packMsg('blkif_fe_interface_status_t',
                      { 'handle' : self.id,
                        'status' : BLKIF_INTERFACE_STATUS_CHANGED,
                        'domid'  : self.backendDomain,
                        'evtchn' : 0 })
        self.frontendChannel.writeRequest(msg)

class BlkDev(Dev):
    """Info record for a block device.
    """

    def __init__(self, controller, id, config, recreate=False):
        Dev.__init__(self, controller, id, config, recreate=recreate)
        self.dev = None
        self.uname = None
        self.vdev = None
        self.mode = None
        self.type = None
        self.params = None
        self.node = None
        self.device = None
        self.start_sector = None
        self.nr_sectors = None
        
        self.frontendDomain = self.getDomain()
        self.frontendChannel = None
        self.backendDomain = None
        self.backendChannel = None
        self.backendId = 0
        self.configure(self.config, recreate=recreate)

    def init(self, recreate=False, reboot=False):
        self.frontendDomain = self.getDomain()
        self.frontendChannel = self.getChannel()
        backend = self.getBackend()
        self.backendChannel = backend.backendChannel
        self.backendId = backend.id

    def configure(self, config, change=False, recreate=False):
        if change:
            raise XendError("cannot reconfigure vbd")
        self.config = config
        self.uname = sxp.child_value(config, 'uname')
        if not self.uname:
            raise VmError('vbd: Missing uname')
        # Split into type and type-specific params (which are passed to the
        # type-specific control script).
        (self.type, self.params) = string.split(self.uname, ':', 1)
        self.dev = sxp.child_value(config, 'dev')
        if not self.dev:
            raise VmError('vbd: Missing dev')
        self.mode = sxp.child_value(config, 'mode', 'r')
        
        self.vdev = blkdev_name_to_number(self.dev)
        if not self.vdev:
            raise VmError('vbd: Device not found: %s' % self.dev)
        
        try:
            self.backendDomain = int(sxp.child_value(config, 'backend', '0'))
        except:
            raise XendError('invalid backend domain')

        return self.config

    def attach(self, recreate=False, change=False):
        if recreate:
            node = sxp.child_value(recreate, 'node')
            print 'BlkDev>attach>', 'recreate=', recreate, 'node=', node
            self.setNode(node)
        else:
            node = Blkctl.block('bind', self.type, self.params)
            self.setNode(node)
            self.attachBackend()
        if change:
            self.interfaceChanged()

    def unbind(self):
        if self.node is None: return
        log.debug("Unbinding vbd (type %s) from %s"
                  % (self.type, self.node))
        Blkctl.block('unbind', self.type, self.node)

    def setNode(self, node):
    
        # NOTE: 
        # This clause is testing code for storage system experiments.
        # Add a new disk type that will just pass an opaque id in the
        # start_sector and use an experimental device type.
        # Please contact andrew.warfield@cl.cam.ac.uk with any concerns.
        if self.type == 'parallax':
            self.node   = node
            self.device =  61440 # (240,0)
            self.start_sector = long(self.params)
            self.nr_sectors = long(0)
            return
        # done.
            
        mounted_mode = self.check_mounted(node)
        if not '!' in self.mode and mounted_mode:
            if mounted_mode == "w":
                raise VmError("vbd: Segment %s is in writable use" %
                              self.uname)
            elif 'w' in self.mode:
                raise VmError("vbd: Segment %s is in read-only use" %
                              self.uname)
            
        segment = blkdev_segment(node)
        if not segment:
            raise VmError("vbd: Segment not found: uname=%s" % self.uname)
        self.node = node
        self.device = segment['device']
        self.start_sector = segment['start_sector']
        self.nr_sectors = segment['nr_sectors']

    def check_mounted(self, name):
        mode = mount_mode(name)
        xd = XendRoot.get_component('xen.xend.XendDomain')
        for vm in xd.domains():
            ctrl = vm.getDeviceController(self.getType(), error=False)
            if (not ctrl): continue
            for dev in ctrl.getDevices():
                if dev is self: continue
                if dev.type == 'phy' and name == expand_dev_name(dev.params):
                    mode = dev.mode
                    if 'w' in mode:
                        return 'w'
        if mode and 'r' in mode:
            return 'r'
        return None

    def readonly(self):
        return 'w' not in self.mode

    def sxpr(self):
        val = ['vbd',
               ['id', self.id],
               ['vdev', self.vdev],
               ['device', self.device],
               ['mode', self.mode]]
        if self.dev:
            val.append(['dev', self.dev])
        if self.uname:
            val.append(['uname', self.uname])
        if self.node:
            val.append(['node', self.node])
        val.append(['index', self.getIndex()])
        return val

    def getBackend(self):
        return self.controller.getBackend(self.backendDomain)

    def refresh(self):
        log.debug("Refreshing vbd domain=%d id=%s", self.frontendDomain, self.id)
        self.interfaceChanged()

    def destroy(self, change=False, reboot=False):
        """Destroy the device. If 'change' is true notify the front-end interface.

        @param change: change flag
        """
        self.destroyed = True
        log.debug("Destroying vbd domain=%d id=%s", self.frontendDomain, self.id)
        self.send_be_vbd_destroy()
        if change:
            self.interfaceChanged()
        self.unbind()

    def interfaceChanged(self):
        """Tell the back-end to notify the front-end that a device has been
        added or removed.
        """
        self.getBackend().interfaceChanged()

    def attachBackend(self):
        """Attach the device to its controller.

        """
        self.getBackend().connect()
        self.send_be_vbd_create()
        
    def send_be_vbd_create(self):
        msg = packMsg('blkif_be_vbd_create_t',
                      { 'domid'        : self.frontendDomain,
                        'blkif_handle' : self.backendId,
                        'pdevice'      : self.device,
                        'vdevice'      : self.vdev,
                        'readonly'     : self.readonly() })
        msg = self.backendChannel.requestResponse(msg)
        
        val = unpackMsg('blkif_be_vbd_create_t', msg)
        status = val['status']
        if status != BLKIF_BE_STATUS_OKAY:
            raise XendError("Creating vbd failed: device %s, error %d"
                            % (sxp.to_string(self.config), status))

    def send_be_vbd_destroy(self):
        msg = packMsg('blkif_be_vbd_destroy_t',
                      { 'domid'                : self.frontendDomain,
                        'blkif_handle'         : self.backendId,
                        'vdevice'              : self.vdev })
        return self.backendChannel.writeRequest(msg)
        
class BlkifController(DevController):
    """Block device interface controller. Handles all block devices
    for a domain.
    """
    
    def __init__(self, vm, recreate=False):
        """Create a block device controller.
        """
        DevController.__init__(self, vm, recreate=recreate)
        self.backends = {}
        self.backendId = 0
        self.rcvr = None

    def initController(self, recreate=False, reboot=False):
        self.destroyed = False
        # Add our handlers for incoming requests.
        self.rcvr = CtrlMsgRcvr(self.getChannel())
        self.rcvr.addHandler(CMSG_BLKIF_FE,
                             CMSG_BLKIF_FE_DRIVER_STATUS,
                             self.recv_fe_driver_status)
        self.rcvr.addHandler(CMSG_BLKIF_FE,
                             CMSG_BLKIF_FE_INTERFACE_CONNECT,
                             self.recv_fe_interface_connect)
        self.rcvr.registerChannel()
        if reboot:
            self.rebootBackends()
            self.rebootDevices()

    def sxpr(self):
        val = ['blkif', ['dom', self.getDomain()]]
        return val

    def rebootBackends(self):
        for backend in self.backends.values():
            backend.init(reboot=True)

    def getBackendById(self, id):
        return self.backends.get(id)

    def getBackendByDomain(self, dom):
        for backend in self.backends.values():
            if backend.backendDomain == dom:
                return backend
        return None

    def getBackend(self, dom):
        backend = self.getBackendByDomain(dom)
        if backend: return backend
        backend = BlkifBackend(self, self.backendId, dom)
        self.backendId += 1
        self.backends[backend.getId()] = backend
        backend.init()
        return backend

    def newDevice(self, id, config, recreate=False):
        """Create a device..

        @param id:      device id
        @param config:   device configuration
        @param recreate: if true it's being recreated (after xend restart)
        @type  recreate: bool
        @return: device
        @rtype:  BlkDev
        """
        return BlkDev(self, id, config, recreate=recreate)
        
    def destroyController(self, reboot=False):
        """Destroy the controller and all devices.
        """
        self.destroyed = True
        log.debug("Destroying blkif domain=%d", self.getDomain())
        self.destroyDevices(reboot=reboot)
        self.destroyBackends(reboot=reboot)
        self.rcvr.deregisterChannel()

    def destroyBackends(self, reboot=False):
        for backend in self.backends.values():
            backend.destroy(reboot=reboot)

    def recv_fe_driver_status(self, msg):
        val = unpackMsg('blkif_fe_driver_status_t', msg)
        for backend in self.backends.values():
            backend.interfaceDisconnected()

    def recv_fe_interface_connect(self, msg):
        val = unpackMsg('blkif_fe_interface_connect_t', msg)
        id = val['handle']
        backend = self.getBackendById(id)
        if backend:
            try:
                backend.connectInterface(val)
            except IOError, ex:
                log.error("Exception connecting backend: %s", ex)
        else:
            log.error('interface connect on unknown interface: id=%d', id)
    

