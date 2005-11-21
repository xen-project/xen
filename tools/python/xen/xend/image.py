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
# Copyright (C) 2005 XenSource Ltd
#============================================================================


import os, string
import re

import xen.lowlevel.xc
from xen.xend import sxp
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log
from xen.xend.server.netif import randomMAC


xc = xen.lowlevel.xc.xc()


MAX_GUEST_CMDLINE = 1024


def create(vm, imageConfig, deviceConfig):
    """Create an image handler for a vm.

    @return ImageHandler instance
    """
    return findImageHandlerClass(imageConfig)(vm, imageConfig, deviceConfig)


class ImageHandler:
    """Abstract base class for image handlers.

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

    ostype = None


    def __init__(self, vm, imageConfig, deviceConfig):
        self.vm = vm

        self.kernel = None
        self.ramdisk = None
        self.cmdline = None

        self.configure(imageConfig, deviceConfig)

    def configure(self, imageConfig, _):
        """Config actions common to all unix-like domains."""

        def get_cfg(name, default = None):
            return sxp.child_value(imageConfig, name, default)

        self.kernel = get_cfg("kernel")
        self.cmdline = ""
        ip = get_cfg("ip")
        if ip:
            self.cmdline += " ip=" + ip
        root = get_cfg("root")
        if root:
            self.cmdline += " root=" + root
        args = get_cfg("args")
        if args:
            self.cmdline += " " + args
        self.ramdisk = get_cfg("ramdisk", '')
        
        self.vm.storeVm(("image/ostype", self.ostype),
                        ("image/kernel", self.kernel),
                        ("image/cmdline", self.cmdline),
                        ("image/ramdisk", self.ramdisk))


    def cleanupBootloading(self):
        self.unlink(self.kernel)
        self.unlink(self.ramdisk)


    def unlink(self, f):
        if not f: return
        try:
            os.unlink(f)
        except OSError, ex:
            log.warning("error removing bootloader file '%s': %s", f, ex)


    def createImage(self):
        """Entry point to create domain memory image.
        Override in subclass  if needed.
        """
        return self.createDomain()


    def createDomain(self):
        """Build the domain boot image.
        """
        # Set params and call buildDomain().

        if not os.path.isfile(self.kernel):
            raise VmError('Kernel image does not exist: %s' % self.kernel)
        if self.ramdisk and not os.path.isfile(self.ramdisk):
            raise VmError('Kernel ramdisk does not exist: %s' % self.ramdisk)
        if len(self.cmdline) >= MAX_GUEST_CMDLINE:
            log.warning('kernel cmdline too long, domain %d',
                        self.vm.getDomid())
        
        log.info("buildDomain os=%s dom=%d vcpus=%d", self.ostype,
                 self.vm.getDomid(), self.vm.getVCpuCount())

        result = self.buildDomain()

        if isinstance(result, dict):
            return result
        else:
            raise VmError('Building domain failed: ostype=%s dom=%d err=%s'
                          % (self.ostype, self.vm.getDomid(), str(result)))


    def getDomainMemory(self, mem):
        """@return The memory required, in KiB, by the domain to store the
        given amount, also in KiB.  This is normally just mem, but VMX domains
        have overheads to account for."""
        return mem

    def buildDomain(self):
        """Build the domain. Define in subclass."""
        raise NotImplementedError()

    def createDeviceModel(self):
        """Create device model for the domain (define in subclass if needed)."""
        pass
    
    def destroy(self):
        """Extra cleanup on domain destroy (define in subclass if needed)."""
        pass


class LinuxImageHandler(ImageHandler):

    ostype = "linux"

    def buildDomain(self):
        store_evtchn = self.vm.getStorePort()
        console_evtchn = self.vm.getConsolePort()

        log.debug("dom            = %d", self.vm.getDomid())
        log.debug("image          = %s", self.kernel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("console_evtchn = %d", console_evtchn)
        log.debug("cmdline        = %s", self.cmdline)
        log.debug("ramdisk        = %s", self.ramdisk)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())

        return xc.linux_build(dom            = self.vm.getDomid(),
                              image          = self.kernel,
                              store_evtchn   = store_evtchn,
                              console_evtchn = console_evtchn,
                              cmdline        = self.cmdline,
                              ramdisk        = self.ramdisk)

class VmxImageHandler(ImageHandler):

    ostype = "vmx"

    def configure(self, imageConfig, deviceConfig):
        ImageHandler.configure(self, imageConfig, deviceConfig)

        self.dmargs = self.parseDeviceModelArgs(imageConfig, deviceConfig)
        self.device_model = sxp.child_value(imageConfig, 'device_model')
        if not self.device_model:
            raise VmError("vmx: missing device model")
        self.display = sxp.child_value(imageConfig, 'display')

        self.vm.storeVm(("image/dmargs", " ".join(self.dmargs)),
                        ("image/device-model", self.device_model),
                        ("image/display", self.display))

        self.device_channel = None
        self.pid = 0

        self.dmargs += self.configVNC(imageConfig)

        self.lapic = 0
        lapic = sxp.child_value(imageConfig, 'lapic')
        if not lapic is None:
            self.lapic = int(lapic)

    def buildDomain(self):
        # Create an event channel
        self.device_channel = xc.evtchn_alloc_unbound(dom=self.vm.getDomid(),
                                                      remote_dom=0)
        log.info("VMX device model port: %d", self.device_channel)

        store_evtchn = self.vm.getStorePort()

        log.debug("dom            = %d", self.vm.getDomid())
        log.debug("image          = %s", self.kernel)
        log.debug("control_evtchn = %d", self.device_channel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("memsize        = %d", self.vm.getMemoryTarget() / 1024)
        log.debug("lapic          = %d", self.lapic)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())

        return xc.vmx_build(dom            = self.vm.getDomid(),
                            image          = self.kernel,
                            control_evtchn = self.device_channel,
                            store_evtchn   = store_evtchn,
                            memsize        = self.vm.getMemoryTarget() / 1024,
                            lapic          = self.lapic,
                            vcpus          = self.vm.getVCpuCount())


    # Return a list of cmd line args to the device models based on the
    # xm config file
    def parseDeviceModelArgs(self, imageConfig, deviceConfig):
        dmargs = [ 'cdrom', 'boot', 'fda', 'fdb', 'ne2000', 
                   'localtime', 'serial', 'stdvga', 'isa', 'vcpus' ]
        ret = []
        for a in dmargs:
            v = sxp.child_value(imageConfig, a)

            # python doesn't allow '-' in variable names
            if a == 'stdvga': a = 'std-vga'
            if a == 'ne2000': a = 'nic-ne2000'

            # Handle booleans gracefully
            if a in ['localtime', 'std-vga', 'isa', 'nic-ne2000']:
                if v != None: v = int(v)
                if v: ret.append("-%s" % a)
            else:
                if v:
                    ret.append("-%s" % a)
                    ret.append("%s" % v)
            log.debug("args: %s, val: %s" % (a,v))

        # Handle disk/network related options
        mac = None
        for (name, info) in deviceConfig:
            if name == 'vbd':
               uname = sxp.child_value(info, 'uname')
               typedev = sxp.child_value(info, 'dev')
               (_, vbdparam) = string.split(uname, ':', 1)
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
               type = sxp.child_value(info, 'type')
               if type != 'ioemu':
                   continue
               if mac != None:
                   continue
               mac = sxp.child_value(info, 'mac')
               bridge = sxp.child_value(info, 'bridge')
               if mac == None:
                   mac = randomMAC()
               if bridge == None:
                   bridge = 'xenbr0'
               ret.append("-macaddr")
               ret.append("%s" % mac)
               ret.append("-bridge")
               ret.append("%s" % bridge)
            if name == 'vtpm':
               instance = sxp.child_value(info, 'instance')
               ret.append("-instance")
               ret.append("%s" % instance)
        return ret

    def configVNC(self, config):
        # Handle graphics library related options
        vnc = sxp.child_value(config, 'vnc')
        sdl = sxp.child_value(config, 'sdl')
        ret = []
        nographic = sxp.child_value(config, 'nographic')
        if nographic:
            ret.append('-nographic')
            return ret

        if vnc and sdl:
            ret = ret + ['-vnc-and-sdl', '-k', 'en-us']
        elif vnc:
            ret = ret + ['-vnc', '-k', 'en-us']
        if vnc:
            vncport = int(self.vm.getDomid()) + 5900
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
        args = args + ([ "-d",  "%d" % self.vm.getDomid(),
                  "-p", "%d" % self.device_channel,
                  "-m", "%s" % (self.vm.getMemoryTarget() / 1024)])
        args = args + self.dmargs
        env = dict(os.environ)
        if self.display:
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
        import signal
        if not self.pid:
            return
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        self.pid = 0

    def getDomainMemory(self, mem):
        """@see ImageHandler.getDomainMemory"""
	page_kb = 4
	if os.uname()[4] == 'ia64':
	    page_kb = 16
        # for ioreq_t and xenstore
        static_pages = 2
        return mem + (self.getPageTableSize(mem / 1024) + static_pages) * page_kb
            
    def getPageTableSize(self, mem_mb):
        """Return the pages of memory needed for 1:1 page tables for physical
           mode.

        @param mem_mb: size in MB
        @return size in KB
        """
        # 1 page for the PGD + 1 pte page for 4MB of memory (rounded)
        if os.uname()[4] == 'x86_64':
            return 5 + ((mem_mb + 1) >> 1)
        elif os.uname()[4] == 'ia64':
            # 1:1 pgtable is allocated on demand ia64, so just return rom size
	    # for guest firmware
            return 1024
        else:
            return 1 + ((mem_mb + 3) >> 2)


"""Table of image handler classes for virtual machine images.  Indexed by
image type.
"""
imageHandlerClasses = {}


for h in LinuxImageHandler, VmxImageHandler:
    imageHandlerClasses[h.ostype] = h


def findImageHandlerClass(image):
    """Find the image handler class for an image config.

    @param image config
    @return ImageHandler subclass or None
    """
    ty = sxp.name(image)
    if ty is None:
        raise VmError('missing image type')
    imageClass = imageHandlerClasses.get(ty)
    if imageClass is None:
        raise VmError('unknown image type: ' + ty)
    return imageClass
