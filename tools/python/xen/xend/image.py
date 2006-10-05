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
import math

import xen.lowlevel.xc
from xen.xend import sxp
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log
from xen.xend.server.netif import randomMAC
from xen.xend.xenstore.xswatch import xswatch
from xen.xend import arch
from xen.xend import FlatDeviceTree


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

    def getRequiredAvailableMemory(self, mem_kb):
        """@param mem_kb The configured maxmem or memory, in KiB.
        @return The corresponding required amount of memory for the domain,
        also in KiB.  This is normally the given mem_kb, but architecture- or
        image-specific code may override this to add headroom where
        necessary."""
        return mem_kb

    def getRequiredInitialReservation(self, mem_kb):
        """@param mem_kb The configured memory, in KiB.
        @return The corresponding required amount of memory to be free, also
        in KiB. This is normally the same as getRequiredAvailableMemory, but
        architecture- or image-specific code may override this to
        add headroom where necessary."""
        return self.getRequiredAvailableMemory(mem_kb)

    def getRequiredShadowMemory(self, shadow_mem_kb, maxmem_kb):
        """@param shadow_mem_kb The configured shadow memory, in KiB.
        @param maxmem_kb The configured maxmem, in KiB.
        @return The corresponding required amount of shadow memory, also in
        KiB."""
        # PV domains don't need any shadow memory
        return 0

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

        log.debug("domid          = %d", self.vm.getDomid())
        log.debug("image          = %s", self.kernel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("console_evtchn = %d", console_evtchn)
        log.debug("cmdline        = %s", self.cmdline)
        log.debug("ramdisk        = %s", self.ramdisk)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())
        log.debug("features       = %s", self.vm.getFeatures())

        return xc.linux_build(domid          = self.vm.getDomid(),
                              image          = self.kernel,
                              store_evtchn   = store_evtchn,
                              console_evtchn = console_evtchn,
                              cmdline        = self.cmdline,
                              ramdisk        = self.ramdisk,
                              features       = self.vm.getFeatures())

class PPC_LinuxImageHandler(LinuxImageHandler):

    ostype = "linux"

    def configure(self, imageConfig, deviceConfig):
        LinuxImageHandler.configure(self, imageConfig, deviceConfig)
        self.imageConfig = imageConfig

    def buildDomain(self):
        store_evtchn = self.vm.getStorePort()
        console_evtchn = self.vm.getConsolePort()

        log.debug("domid          = %d", self.vm.getDomid())
        log.debug("image          = %s", self.kernel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("console_evtchn = %d", console_evtchn)
        log.debug("cmdline        = %s", self.cmdline)
        log.debug("ramdisk        = %s", self.ramdisk)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())
        log.debug("features       = %s", self.vm.getFeatures())

        devtree = FlatDeviceTree.build(self)

        return xc.linux_build(domid          = self.vm.getDomid(),
                              image          = self.kernel,
                              store_evtchn   = store_evtchn,
                              console_evtchn = console_evtchn,
                              cmdline        = self.cmdline,
                              ramdisk        = self.ramdisk,
                              features       = self.vm.getFeatures(),
                              arch_args      = devtree.to_bin())

class HVMImageHandler(ImageHandler):

    def configure(self, imageConfig, deviceConfig):
        ImageHandler.configure(self, imageConfig, deviceConfig)

        info = xc.xeninfo()
        if not 'hvm' in info['xen_caps']:
            raise VmError("HVM guest support is unavailable: is VT/AMD-V "
                          "supported by your CPU and enabled in your BIOS?")

        self.dmargs = self.parseDeviceModelArgs(imageConfig, deviceConfig)
        self.device_model = sxp.child_value(imageConfig, 'device_model')
        if not self.device_model:
            raise VmError("hvm: missing device model")
        self.display = sxp.child_value(imageConfig, 'display')
        self.xauthority = sxp.child_value(imageConfig, 'xauthority')
        self.vncconsole = sxp.child_value(imageConfig, 'vncconsole')

        self.vm.storeVm(("image/dmargs", " ".join(self.dmargs)),
                        ("image/device-model", self.device_model),
                        ("image/display", self.display))

        self.pid = 0

        self.dmargs += self.configVNC(imageConfig)

        self.pae  = int(sxp.child_value(imageConfig, 'pae', 0))

        self.acpi = int(sxp.child_value(imageConfig, 'acpi', 0))
        self.apic = int(sxp.child_value(imageConfig, 'apic', 0))

    def buildDomain(self):
        store_evtchn = self.vm.getStorePort()

        log.debug("domid          = %d", self.vm.getDomid())
        log.debug("image          = %s", self.kernel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("memsize        = %d", self.vm.getMemoryTarget() / 1024)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())
        log.debug("pae            = %d", self.pae)
        log.debug("acpi           = %d", self.acpi)
        log.debug("apic           = %d", self.apic)

        self.register_shutdown_watch()

        return xc.hvm_build(domid          = self.vm.getDomid(),
                            image          = self.kernel,
                            store_evtchn   = store_evtchn,
                            memsize        = self.vm.getMemoryTarget() / 1024,
                            vcpus          = self.vm.getVCpuCount(),
                            pae            = self.pae,
                            acpi           = self.acpi,
                            apic           = self.apic)

    # Return a list of cmd line args to the device models based on the
    # xm config file
    def parseDeviceModelArgs(self, imageConfig, deviceConfig):
        dmargs = [ 'boot', 'fda', 'fdb', 'soundhw',
                   'localtime', 'serial', 'stdvga', 'isa', 'vcpus',
                   'acpi', 'usb', 'usbdevice']
        ret = []
        for a in dmargs:
            v = sxp.child_value(imageConfig, a)

            # python doesn't allow '-' in variable names
            if a == 'stdvga': a = 'std-vga'

            # Handle booleans gracefully
            if a in ['localtime', 'std-vga', 'isa', 'usb', 'acpi']:
                if v != None: v = int(v)
                if v: ret.append("-%s" % a)
            else:
                if v:
                    ret.append("-%s" % a)
                    ret.append("%s" % v)

            if a in ['fda', 'fdb' ]:
                if v:
                    if not os.path.isfile(v):
                        raise VmError("Floppy file %s does not exist." % v)
            log.debug("args: %s, val: %s" % (a,v))

        # Handle disk/network related options
        mac = None
        ret = ret + ["-domain-name", "%s" % self.vm.info['name']]
        nics = 0
        for (name, info) in deviceConfig:
            if name == 'vbd':
                uname = sxp.child_value(info, 'uname')
                if uname is not None and 'file:' in uname:
                    (_, vbdparam) = string.split(uname, ':', 1)
                    if not os.path.isfile(vbdparam):
                        raise VmError('Disk image does not exist: %s' %
                                      vbdparam)
            if name == 'vif':
                type = sxp.child_value(info, 'type')
                if type != 'ioemu':
                    continue
                nics += 1
                mac = sxp.child_value(info, 'mac')
                if mac == None:
                    mac = randomMAC()
                bridge = sxp.child_value(info, 'bridge', 'xenbr0')
                model = sxp.child_value(info, 'model', 'rtl8139')
                ret.append("-net")
                ret.append("nic,vlan=%d,macaddr=%s,model=%s" %
                           (nics, mac, model))
                ret.append("-net")
                ret.append("tap,vlan=%d,bridge=%s" % (nics, bridge))
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
        if vnc:
            vncdisplay = sxp.child_value(config, 'vncdisplay',
                                         int(self.vm.getDomid()))
            vncunused = sxp.child_value(config, 'vncunused')
            if vncunused:
                ret += ['-vncunused']
            else:
                ret += ['-vnc', '%d' % vncdisplay]
            ret += ['-k', 'en-us']
            vnclisten = sxp.child_value(config, 'vnclisten')
            if not(vnclisten):
                vnclisten = xen.xend.XendRoot.instance().get_vnclisten_address()
            if vnclisten:
                ret += ['-vnclisten', vnclisten]
        return ret

    def createDeviceModel(self):
        if self.pid:
            return
        # Execute device model.
        #todo: Error handling
        args = [self.device_model]
        args = args + ([ "-d",  "%d" % self.vm.getDomid(),
                  "-m", "%s" % (self.vm.getMemoryTarget() / 1024)])
        args = args + self.dmargs
        env = dict(os.environ)
        if self.display:
            env['DISPLAY'] = self.display
        if self.xauthority:
            env['XAUTHORITY'] = self.xauthority
        if self.vncconsole:
            args = args + ([ "-vncviewer" ])
        log.info("spawning device models: %s %s", self.device_model, args)
        self.pid = os.spawnve(os.P_NOWAIT, self.device_model, args, env)
        log.info("device model pid: %d", self.pid)

    def destroy(self):
        self.unregister_shutdown_watch();
        import signal
        if not self.pid:
            return
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        self.pid = 0

    def register_shutdown_watch(self):
        """ add xen store watch on control/shutdown """
        self.shutdownWatch = xswatch(self.vm.dompath + "/control/shutdown", \
                                    self.hvm_shutdown)
        log.debug("hvm shutdown watch registered")

    def unregister_shutdown_watch(self):
        """Remove the watch on the control/shutdown, if any. Nothrow
        guarantee."""

        try:
            if self.shutdownWatch:
                self.shutdownWatch.unwatch()
        except:
            log.exception("Unwatching hvm shutdown watch failed.")
        self.shutdownWatch = None
        log.debug("hvm shutdown watch unregistered")

    def hvm_shutdown(self, _):
        """ watch call back on node control/shutdown,
            if node changed, this function will be called
        """
        from xen.xend.XendConstants import DOMAIN_SHUTDOWN_REASONS
        xd = xen.xend.XendDomain.instance()
        vm = xd.domain_lookup( self.vm.getDomid() )

        reason = vm.readDom('control/shutdown')
        log.debug("hvm_shutdown fired, shutdown reason=%s", reason)
        for x in shutdown_reasons.keys():
            if shutdown_reasons[x] == reason:
                vm.info['shutdown'] = 1
                vm.info['shutdown_reason'] = x
                vm.refreshShutdown(vm.info)

        return 1 # Keep watching

class IA64_HVM_ImageHandler(HVMImageHandler):

    ostype = "hvm"

    def getRequiredAvailableMemory(self, mem_kb):
        page_kb = 16
        # ROM size for guest firmware, ioreq page and xenstore page
        extra_pages = 1024 + 2
        return mem_kb + extra_pages * page_kb

    def getRequiredShadowMemory(self, shadow_mem_kb, maxmem_kb):
        # Explicit shadow memory is not a concept 
        return 0

class X86_HVM_ImageHandler(HVMImageHandler):

    ostype = "hvm"

    def getRequiredAvailableMemory(self, mem_kb):
        # Add 8 MiB overhead for QEMU's video RAM.
        return self.getRequiredInitialReservation(mem_kb) + 8192

    def getRequiredInitialReservation(self, mem_kb):
        page_kb = 4
        # This was derived emperically:
        #   2.4 MB overhead per 1024 MB RAM
        #   + 4 to avoid low-memory condition
        extra_mb = (2.4/1024) * (mem_kb/1024.0) + 4;
        extra_pages = int( math.ceil( extra_mb*1024 / page_kb ))
        return mem_kb + extra_pages * page_kb

    def getRequiredShadowMemory(self, shadow_mem_kb, maxmem_kb):
        # The given value is the configured value -- we need to include the
        # overhead due to getRequiredInitialReservation.
        maxmem_kb = self.getRequiredInitialReservation(maxmem_kb)

        # 1MB per vcpu plus 4Kib/Mib of RAM.  This is higher than 
        # the minimum that Xen would allocate if no value were given.
        return max(1024 * self.vm.getVCpuCount() + maxmem_kb / 256,
                   shadow_mem_kb)


_handlers = {
    "powerpc": {
        "linux": PPC_LinuxImageHandler,
    },
    "ia64": {
        "linux": LinuxImageHandler,
        "hvm": IA64_HVM_ImageHandler,
    },
    "x86": {
        "linux": LinuxImageHandler,
        "hvm": X86_HVM_ImageHandler,
    },
}

def findImageHandlerClass(image):
    """Find the image handler class for an image config.

    @param image config
    @return ImageHandler subclass or None
    """
    type = sxp.name(image)
    if type is None:
        raise VmError('missing image type')
    try:
        return _handlers[arch.type][type]
    except KeyError:
        raise VmError('unknown image type: ' + type)
