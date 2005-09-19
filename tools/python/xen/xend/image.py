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
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
#============================================================================

import os, string
import re

import xen.lowlevel.xc
from xen.xend import sxp
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log
from xen.xend.xenstore import DBVar
from xen.xend.xenstore.xstransact import xstransact

from xen.xend.server import channel


xc = xen.lowlevel.xc.new()


MAX_GUEST_CMDLINE = 1024

class ImageHandler:
    """Abstract base class for image handlers.

    initDomain() is called to initialise the domain memory and parse
    the configuration.
    
    createImage() is called to configure and build the domain from its
    kernel image and ramdisk etc.

    The method buildDomain() is used to build the domain, and must be
    defined in a subclass.  Usually this is the only method that needs
    defining in a subclass.

    The method createDeviceModel() is called to create the domain device
    model if it needs one.  The default is to do nothing.

    The method destroy() is called when the domain is destroyed.
    The default is to do nothing.
    
    """

    #======================================================================
    # Class vars and methods.

    """Table of image handler classes for virtual machine images.
    Indexed by image type.
    """
    imageHandlerClasses = {}

    def addImageHandlerClass(cls, h):
        """Add a handler class for an image type
        @param h:        handler: ImageHandler subclass
        """
        cls.imageHandlerClasses[h.ostype] = h

    addImageHandlerClass = classmethod(addImageHandlerClass)

    def findImageHandlerClass(cls, image):
        """Find the image handler class for an image config.

        @param image config
        @return ImageHandler subclass or None
        """
        ty = sxp.name(image)
        if ty is None:
            raise VmError('missing image type')
        imageClass = cls.imageHandlerClasses.get(ty)
        if imageClass is None:
            raise VmError('unknown image type: ' + ty)
        return imageClass

    findImageHandlerClass = classmethod(findImageHandlerClass)

    def create(cls, vm, image):
        """Create an image handler for a vm.

        @param vm vm
        @param image image config
        @return ImageHandler instance
        """
        imageClass = cls.findImageHandlerClass(image)
        return imageClass(vm, image)

    create = classmethod(create)

    #======================================================================
    # Instance vars and methods.

    ostype = None

    kernel = None
    ramdisk = None
    cmdline = None

    flags = 0

    def __init__(self, vm, config=None):
        self.vm = vm
        self.configure(config)

    def configure(self, config):
        """Config actions common to all unix-like domains."""
        if not config:
            self.kernel, self.cmdline, self.ramdisk = self.vm.gatherVm(
                ("image/kernel"), ("image/cmdline"), ("image/ramdisk"))
            return
        
        self.kernel = sxp.child_value(config, "kernel")
        self.cmdline = ""
        ip = sxp.child_value(config, "ip", None)
        if ip:
            self.cmdline += " ip=" + ip
        root = sxp.child_value(config, "root")
        if root:
            self.cmdline += " root=" + root
        args = sxp.child_value(config, "args")
        if args:
            self.cmdline += " " + args
        self.ramdisk = sxp.child_value(config, "ramdisk", '')
        
        self.vm.storeVm(("image/ostype", self.ostype),
                        ("image/kernel", self.kernel),
                        ("image/cmdline", self.cmdline),
                        ("image/ramdisk", self.ramdisk))

    def unlink(self, f):
        if not f: return
        try:
            os.unlink(f)
        except OSError, ex:
            log.warning("error removing bootloader file '%s': %s", f, ex)

    def initDomain(self, dom, memory, ssidref, cpu, cpu_weight, bootloading):
        """Initial domain create.

        @return domain id
        """

        mem_kb = self.getDomainMemory(memory)
        dom = xc.domain_create(dom = dom or 0, ssidref = ssidref)
        # if bootloader, unlink here. But should go after buildDomain() ?
        if bootloading:
            self.unlink(self.kernel)
            self.unlink(self.ramdisk)
        if dom <= 0:
            raise VmError('Creating domain failed: name=%s' %
                          self.vm.getName())
        log.debug("initDomain: cpu=%d mem_kb=%d ssidref=%d dom=%d", cpu, mem_kb, ssidref, dom)
        xc.domain_setcpuweight(dom, cpu_weight)
        xc.domain_setmaxmem(dom, mem_kb)

        try:
            xc.domain_memory_increase_reservation(dom, mem_kb, 0, 0)
        except:
            xc.domain_destroy(dom)
            raise

        if cpu != -1:
            xc.domain_pincpu(dom, 0, 1<<int(cpu))
        return dom

    def createImage(self):
        """Entry point to create domain memory image.
        Override in subclass  if needed.
        """
        self.createDomain()

    def createDomain(self):
        """Build the domain boot image.
        """
        # Set params and call buildDomain().
        self.flags = self.vm.getBackendFlags()

        if not os.path.isfile(self.kernel):
            raise VmError('Kernel image does not exist: %s' % self.kernel)
        if self.ramdisk and not os.path.isfile(self.ramdisk):
            raise VmError('Kernel ramdisk does not exist: %s' % self.ramdisk)
        if len(self.cmdline) >= MAX_GUEST_CMDLINE:
            log.warning('kernel cmdline too long, domain %d',
                        self.vm.getDomain())
        
        log.info("buildDomain os=%s dom=%d vcpus=%d", self.ostype,
                 self.vm.getDomain(), self.vm.getVCpuCount())
        err = self.buildDomain()
        if err != 0:
            raise VmError('Building domain failed: ostype=%s dom=%d err=%d'
                          % (self.ostype, self.vm.getDomain(), err))

    def getDomainMemory(self, mem_mb):
        """Memory (in KB) the domain will need for mem_mb (in MB)."""
        return mem_mb * 1024

    def buildDomain(self):
        """Build the domain. Define in subclass."""
        raise NotImplementedError()

    def createDeviceModel(self):
        """Create device model for the domain (define in subclass if needed)."""
        pass
    
    def destroy(self):
        """Extra cleanup on domain destroy (define in subclass if needed)."""
        pass

    def set_vminfo(self, d):
        if d.has_key('store_mfn'):
            self.vm.setStoreRef(d.get('store_mfn'))
        if d.has_key('console_mfn'):
            self.vm.setConsoleRef(d.get('console_mfn'))

addImageHandlerClass = ImageHandler.addImageHandlerClass

class LinuxImageHandler(ImageHandler):

    ostype = "linux"

    def buildDomain(self):
        if self.vm.store_channel:
            store_evtchn = self.vm.store_channel.port2
        else:
            store_evtchn = 0
        if self.vm.console_channel:
            console_evtchn = self.vm.console_channel.port2
        else:
            console_evtchn = 0

        log.debug("dom            = %d", self.vm.getDomain())
        log.debug("image          = %s", self.kernel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("console_evtchn = %d", console_evtchn)
        log.debug("cmdline        = %s", self.cmdline)
        log.debug("ramdisk        = %s", self.ramdisk)
        log.debug("flags          = %d", self.flags)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())

        ret = xc.linux_build(dom            = self.vm.getDomain(),
                             image          = self.kernel,
                             store_evtchn   = store_evtchn,
                             console_evtchn = console_evtchn,
                             cmdline        = self.cmdline,
                             ramdisk        = self.ramdisk,
                             flags          = self.flags,
                             vcpus          = self.vm.getVCpuCount())
        if isinstance(ret, dict):
            self.set_vminfo(ret)
            return 0
        return ret

class VmxImageHandler(ImageHandler):

    ostype = "vmx"

    memmap = None
    memmap_value = []
    device_channel = None
    pid = 0

    def configure(self, config):
        ImageHandler.configure(self, config)
        if not config:
            self.memmap, dmargs, self.device_model, self.display = self.vm.gatherVm(
                ("image/memmap"), ("image/dmargs"), ("image/device-model"),
                ("image/display"))
            self.dmargs = dmargs.split(' ')
            return
        
        self.memmap = sxp.child_value(config, 'memmap')
        self.dmargs = self.parseDeviceModelArgs(config)
        self.device_model = sxp.child_value(config, 'device_model')
        if not self.device_model:
            raise VmError("vmx: missing device model")
        self.display = sxp.child_value(config, 'display')

        self.vm.storeVm(("image/memmap", self.memmap),
                        ("image/dmargs", " ".join(self.dmargs)),
                        ("image/device-model", self.device_model),
                        ("image/display", self.display))

    def createImage(self):
        """Create a VM for the VMX environment.
        """
        self.parseMemmap()
        self.createDomain()

    def buildDomain(self):
        # Create an event channel
        self.device_channel = channel.eventChannel(0, self.vm.getDomain())
        log.info("VMX device model port: %d", self.device_channel.port2)
        if self.vm.store_channel:
            store_evtchn = self.vm.store_channel.port2
        else:
            store_evtchn = 0
        ret = xc.vmx_build(dom            = self.vm.getDomain(),
                           image          = self.kernel,
                           control_evtchn = self.device_channel.port2,
                           store_evtchn   = store_evtchn,
                           memsize        = self.vm.getMemoryTarget(),
                           memmap         = self.memmap_value,
                           cmdline        = self.cmdline,
                           ramdisk        = self.ramdisk,
                           flags          = self.flags,
                           vcpus          = self.vm.getVCpuCount())
        if isinstance(ret, dict):
            self.set_vminfo(ret)
            return 0
        return ret

    def parseMemmap(self):
        if self.memmap is None:
            return
        memmap = sxp.parse(open(self.memmap))[0]
        from xen.util.memmap import memmap_parse
        self.memmap_value = memmap_parse(memmap)
        
    # Return a list of cmd line args to the device models based on the
    # xm config file
    def parseDeviceModelArgs(self, config):
        dmargs = [ 'cdrom', 'boot', 'fda', 'fdb',
                   'localtime', 'serial', 'stdvga', 'isa' ] 
        ret = []
        for a in dmargs:
            v = sxp.child_value(config, a)

            # python doesn't allow '-' in variable names
            if a == 'stdvga': a = 'std-vga'

            # Handle booleans gracefully
            if a in ['localtime', 'std-vga', 'isa']:
                if v != None: v = int(v)

            log.debug("args: %s, val: %s" % (a,v))
            if v: 
                ret.append("-%s" % a)
                ret.append("%s" % v)

        # Handle disk/network related options
        devices = sxp.children(self.vm.config, 'device')
        for device in devices:
            name = sxp.name(sxp.child0(device))
            if name == 'vbd':
               vbdinfo = sxp.child(device, 'vbd')
               uname = sxp.child_value(vbdinfo, 'uname')
               typedev = sxp.child_value(vbdinfo, 'dev')
               (vbdtype, vbdparam) = string.split(uname, ':', 1)
               if re.match('^ioemu:', typedev):
                  (emtype, vbddev) = string.split(typedev, ':', 1)
               else:
                  emtype = 'vbd'
                  vbddev = typedev
               if emtype != 'ioemu':
                  continue;
               vbddev_list = ['hda', 'hdb', 'hdc', 'hdd']
               if vbddev not in vbddev_list:
                  raise VmError("vmx: for qemu vbd type=file&dev=hda~hdd")
               ret.append("-%s" % vbddev)
               ret.append("%s" % vbdparam)
            if name == 'vif':
               vifinfo = sxp.child(device, 'vif')
               mac = sxp.child_value(vifinfo, 'mac')
               ret.append("-macaddr")
               ret.append("%s" % mac)
            if name == 'vtpm':
               vtpminfo = sxp.child(device, 'vtpm')
               instance = sxp.child_value(vtpminfo, 'instance')
               ret.append("-instance")
               ret.append("%s" % instance)

        # Handle graphics library related options
        vnc = sxp.child_value(config, 'vnc')
        sdl = sxp.child_value(config, 'sdl')
        nographic = sxp.child_value(config, 'nographic')
        if nographic:
            ret.append('-nographic')
            return ret

        if vnc and sdl:
            ret = ret + ['-vnc-and-sdl', '-k', 'en-us']
        elif vnc:
            ret = ret + ['-vnc', '-k', 'en-us']
        if vnc:
            vncport = int(self.vm.getDomain()) + 5900
            ret = ret + ['-vncport', '%d' % vncport]
        return ret

    def createDeviceModel(self):
        if self.pid:
            return
        # Execute device model.
        #todo: Error handling
        # XXX RN: note that the order of args matter!
        args = [self.device_model]
        vnc = self.vncParams()
        if len(vnc):
            args = args + vnc
        args = args + ([ "-d",  "%d" % self.vm.getDomain(),
                  "-p", "%d" % self.device_channel.port1,
                  "-m", "%s" % self.vm.getMemoryTarget() ])
        args = args + self.dmargs
        env = dict(os.environ)
        env['DISPLAY'] = self.display
        log.info("spawning device models: %s %s", self.device_model, args)
        self.pid = os.spawnve(os.P_NOWAIT, self.device_model, args, env)
        log.info("device model pid: %d", self.pid)

    def vncParams(self):
        # see if a vncviewer was specified
        # XXX RN: bit of a hack. should unify this, maybe stick in config space
        vncconnect=[]
        args = self.cmdline
        if args:
            arg_list = string.split(args)
            for arg in arg_list:
                al = string.split(arg, '=')
                if al[0] == "VNC_VIEWER":
                    vncconnect=["-vncconnect", "%s" % al[1]]
                    break
        return vncconnect

    def destroy(self):
        channel.eventChannelClose(self.device_channel)
        import signal
        if not self.pid:
            return
        os.kill(self.pid, signal.SIGKILL)
        (pid, status) = os.waitpid(self.pid, 0)
        self.pid = 0

    def getDomainMemory(self, mem_mb):
        # for ioreq_t and xenstore
        static_pages = 2
        return (mem_mb * 1024) + self.getPageTableSize(mem_mb) + 4 * static_pages
            
    def getPageTableSize(self, mem_mb):
        """Return the size of memory needed for 1:1 page tables for physical
           mode.

        @param mem_mb: size in MB
        @return size in KB
        """
        # 1 page for the PGD + 1 pte page for 4MB of memory (rounded)
        if os.uname()[4] == 'x86_64':
            return (5 + ((mem_mb + 1) >> 1)) * 4
        elif os.uname()[4] == 'ia64':
            # XEN/IA64 has p2m table allocated on demand, so only return
            # guest firmware size here.
            return 16 * 1024
        else:
            return (1 + ((mem_mb + 3) >> 2)) * 4
