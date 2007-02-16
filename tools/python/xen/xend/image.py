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
import signal

import xen.lowlevel.xc
from xen.xend.XendConstants import REVERSE_DOMAIN_SHUTDOWN_REASONS
from xen.xend.XendError import VmError, XendError
from xen.xend.XendLogging import log
from xen.xend.XendOptions import instance as xenopts
from xen.xend.server.netif import randomMAC
from xen.xend.xenstore.xswatch import xswatch
from xen.xend import arch

xc = xen.lowlevel.xc.xc()

MAX_GUEST_CMDLINE = 1024


def create(vm, vmConfig, imageConfig, deviceConfig):
    """Create an image handler for a vm.

    @return ImageHandler instance
    """
    return findImageHandlerClass(imageConfig)(vm, vmConfig, imageConfig,
                                              deviceConfig)


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


    def __init__(self, vm, vmConfig, imageConfig, deviceConfig):
        self.vm = vm

        self.bootloader = False
        self.kernel = None
        self.ramdisk = None
        self.cmdline = None

        self.configure(vmConfig, imageConfig, deviceConfig)

    def configure(self, vmConfig, imageConfig, _):
        """Config actions common to all unix-like domains."""
        if '_temp_using_bootloader' in vmConfig:
            self.bootloader = True
            self.kernel = vmConfig['_temp_kernel']
            self.cmdline = vmConfig['_temp_args']
            self.ramdisk = vmConfig['_temp_ramdisk']
        else:
            self.kernel = vmConfig['PV_kernel']
            self.cmdline = vmConfig['PV_args']
            self.ramdisk = vmConfig['PV_ramdisk']
        self.vm.storeVm(("image/ostype", self.ostype),
                        ("image/kernel", self.kernel),
                        ("image/cmdline", self.cmdline),
                        ("image/ramdisk", self.ramdisk))


    def cleanupBootloading(self):
        if self.bootloader:
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

    def getRequiredInitialReservation(self):
        """@param mem_kb The configured memory, in KiB.
        @return The corresponding required amount of memory to be free, also
        in KiB. This is normally the same as getRequiredAvailableMemory, but
        architecture- or image-specific code may override this to
        add headroom where necessary."""
        return self.getRequiredAvailableMemory(self.vm.getMemoryTarget())

    def getRequiredMaximumReservation(self):
        """@param mem_kb The maximum possible memory, in KiB.
        @return The corresponding required amount of memory to be free, also
        in KiB. This is normally the same as getRequiredAvailableMemory, but
        architecture- or image-specific code may override this to
        add headroom where necessary."""
        return self.getRequiredAvailableMemory(self.vm.getMemoryMaximum())

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

    def createDeviceModel(self, restore = False):
        """Create device model for the domain (define in subclass if needed)."""
        pass
    
    def destroy(self):
        """Extra cleanup on domain destroy (define in subclass if needed)."""
        pass


    def recreate(self):
        pass


class LinuxImageHandler(ImageHandler):

    ostype = "linux"

    def buildDomain(self):
        store_evtchn = self.vm.getStorePort()
        console_evtchn = self.vm.getConsolePort()

        mem_mb = self.getRequiredInitialReservation() / 1024

        log.debug("domid          = %d", self.vm.getDomid())
        log.debug("memsize        = %d", mem_mb)
        log.debug("image          = %s", self.kernel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("console_evtchn = %d", console_evtchn)
        log.debug("cmdline        = %s", self.cmdline)
        log.debug("ramdisk        = %s", self.ramdisk)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())
        log.debug("features       = %s", self.vm.getFeatures())

        return xc.linux_build(domid          = self.vm.getDomid(),
                              memsize        = mem_mb,
                              image          = self.kernel,
                              store_evtchn   = store_evtchn,
                              console_evtchn = console_evtchn,
                              cmdline        = self.cmdline,
                              ramdisk        = self.ramdisk,
                              features       = self.vm.getFeatures())

class PPC_LinuxImageHandler(LinuxImageHandler):

    ostype = "linux"
    
    def getRequiredShadowMemory(self, shadow_mem_kb, maxmem_kb):
        """@param shadow_mem_kb The configured shadow memory, in KiB.
        @param maxmem_kb The configured maxmem, in KiB.
        @return The corresponding required amount of shadow memory, also in
        KiB.
        PowerPC currently uses "shadow memory" to refer to the hash table."""
        return max(maxmem_kb / 64, shadow_mem_kb)



class PPC_ProseImageHandler(PPC_LinuxImageHandler):

    ostype = "prose"

    def buildDomain(self):
        store_evtchn = self.vm.getStorePort()
        console_evtchn = self.vm.getConsolePort()

        mem_mb = self.getRequiredInitialReservation() / 1024

        log.debug("dom            = %d", self.vm.getDomid())
        log.debug("memsize        = %d", mem_mb)
        log.debug("image          = %s", self.kernel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("console_evtchn = %d", console_evtchn)
        log.debug("cmdline        = %s", self.cmdline)
        log.debug("ramdisk        = %s", self.ramdisk)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())
        log.debug("features       = %s", self.vm.getFeatures())

        return xc.arch_prose_build(dom            = self.vm.getDomid(),
                                   memsize        = mem_mb,
                                   image          = self.kernel,
                                   store_evtchn   = store_evtchn,
                                   console_evtchn = console_evtchn,
                                   cmdline        = self.cmdline,
                                   ramdisk        = self.ramdisk,
                                   features       = self.vm.getFeatures())

class HVMImageHandler(ImageHandler):

    ostype = "hvm"

    def __init__(self, vm, vmConfig, imageConfig, deviceConfig):
        ImageHandler.__init__(self, vm, vmConfig, imageConfig, deviceConfig)
        self.shutdownWatch = None
        self.rebootFeatureWatch = None

    def configure(self, vmConfig, imageConfig, deviceConfig):
        ImageHandler.configure(self, vmConfig, imageConfig, deviceConfig)

        if not self.kernel:
            self.kernel = '/usr/lib/xen/boot/hvmloader'

        info = xc.xeninfo()
        if 'hvm' not in info['xen_caps']:
            raise VmError("HVM guest support is unavailable: is VT/AMD-V "
                          "supported by your CPU and enabled in your BIOS?")

        self.dmargs = self.parseDeviceModelArgs(vmConfig)
        self.device_model = imageConfig['hvm'].get('device_model')
        if not self.device_model:
            raise VmError("hvm: missing device model")
        
        self.display = imageConfig['hvm'].get('display')
        self.xauthority = imageConfig['hvm'].get('xauthority')
        self.vncconsole = imageConfig['hvm'].get('vncconsole')

        self.vm.storeVm(("image/dmargs", " ".join(self.dmargs)),
                        ("image/device-model", self.device_model),
                        ("image/display", self.display))

        self.pid = None

        self.pae  = imageConfig['hvm'].get('pae', 0)
        self.apic  = imageConfig['hvm'].get('apic', 0)
        self.acpi  = imageConfig['hvm']['devices'].get('acpi', 0)
        

    def buildDomain(self):
        store_evtchn = self.vm.getStorePort()

        mem_mb = self.getRequiredInitialReservation() / 1024

        log.debug("domid          = %d", self.vm.getDomid())
        log.debug("image          = %s", self.kernel)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("memsize        = %d", mem_mb)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())
        log.debug("pae            = %d", self.pae)
        log.debug("acpi           = %d", self.acpi)
        log.debug("apic           = %d", self.apic)

        self.register_shutdown_watch()
        self.register_reboot_feature_watch()

        return xc.hvm_build(domid          = self.vm.getDomid(),
                            image          = self.kernel,
                            store_evtchn   = store_evtchn,
                            memsize        = mem_mb,
                            vcpus          = self.vm.getVCpuCount(),
                            pae            = self.pae,
                            acpi           = self.acpi,
                            apic           = self.apic)

    # Return a list of cmd line args to the device models based on the
    # xm config file
    def parseDeviceModelArgs(self, vmConfig):
        dmargs = [ 'boot', 'fda', 'fdb', 'soundhw',
                   'localtime', 'serial', 'stdvga', 'isa',
                   'acpi', 'usb', 'usbdevice', 'keymap' ]
        
        hvmDeviceConfig = vmConfig['image']['hvm']['devices']
        ret = ['-vcpus', str(self.vm.getVCpuCount())]

        for a in dmargs:
            v = hvmDeviceConfig.get(a)

            # python doesn't allow '-' in variable names
            if a == 'stdvga': a = 'std-vga'
            if a == 'keymap': a = 'k'

            # Handle booleans gracefully
            if a in ['localtime', 'std-vga', 'isa', 'usb', 'acpi']:
                try:
                    if v != None: v = int(v)
                    if v: ret.append("-%s" % a)
                except (ValueError, TypeError):
                    pass # if we can't convert it to a sane type, ignore it
            else:
                if v:
                    ret.append("-%s" % a)
                    ret.append("%s" % v)

            if a in ['fda', 'fdb']:
                if v:
                    if not os.path.isabs(v):
                        raise VmError("Floppy file %s does not exist." % v)
            log.debug("args: %s, val: %s" % (a,v))

        # Handle disk/network related options
        mac = None
        ret = ret + ["-domain-name", str(self.vm.info['name_label'])]
        nics = 0
        
        for devuuid in vmConfig['vbd_refs']:
            devinfo = vmConfig['devices'][devuuid][1]
            uname = devinfo.get('uname')
            if uname is not None and 'file:' in uname:
                (_, vbdparam) = string.split(uname, ':', 1)
                if not os.path.isfile(vbdparam):
                    raise VmError('Disk image does not exist: %s' %
                                  vbdparam)

        for devuuid in vmConfig['vif_refs']:
            devinfo = vmConfig['devices'][devuuid][1]
            dtype = devinfo.get('type', 'ioemu')
            if dtype != 'ioemu':
                continue
            nics += 1
            mac = devinfo.get('mac')
            if mac is None:
                mac = randomMAC()
            bridge = devinfo.get('bridge', 'xenbr0')
            model = devinfo.get('model', 'rtl8139')
            ret.append("-net")
            ret.append("nic,vlan=%d,macaddr=%s,model=%s" %
                       (nics, mac, model))
            ret.append("-net")
            ret.append("tap,vlan=%d,bridge=%s" % (nics, bridge))


        #
        # Find RFB console device, and if it exists, make QEMU enable
        # the VNC console.
        #
        if vmConfig['image'].get('nographic'):
            # skip vnc init if nographic is set
            ret.append('-nographic')
            return ret

        vnc_config = {}
        has_vnc = int(vmConfig['image'].get('vnc', 0)) != 0
        has_sdl = int(vmConfig['image'].get('sdl', 0)) != 0
        for dev_uuid in vmConfig['console_refs']:
            dev_type, dev_info = vmConfig['devices'][dev_uuid]
            if dev_type == 'vfb':
                vnc_config = dev_info.get('other_config', {})
                has_vnc = True
                break

        if has_vnc:
            if not vnc_config:
                for key in ('vncunused', 'vnclisten', 'vncdisplay',
                            'vncpasswd'):
                    if key in vmConfig['image']:
                        vnc_config[key] = vmConfig['image'][key]

            if not vnc_config.get('vncunused', 0) and \
                   vnc_config.get('vncdisplay', 0):
                vncdisplay = vnc_config.get('vncdisplay')
                ret.append('-vnc')
                ret.append(str(vncdisplay))
            else:
                ret.append('-vncunused')

            vnclisten = vnc_config.get('vnclisten',
                                       xenopts().get_vnclisten_address())
            ret.append('-vnclisten')
            ret.append(str(vnclisten))

            # Store vncpassword in xenstore
            vncpasswd = vnc_config.get('vncpasswd')
            if not vncpasswd:
                vncpasswd = xenopts().get_vncpasswd_default()

            if vncpasswd is None:
                raise VmError('vncpasswd is not setup in vmconfig or '
                              'xend-config.sxp')

            if vncpasswd != '':
                self.vm.storeVm('vncpasswd', vncpasswd)
        elif has_sdl:
            # SDL is default in QEMU.
            pass
        else:
            ret.append('-nographic')

        return ret

    def createDeviceModel(self, restore = False):
        if self.pid:
            return
        # Execute device model.
        #todo: Error handling
        args = [self.device_model]
        args = args + ([ "-d",  "%d" % self.vm.getDomid(),
                  "-m", "%s" % (self.getRequiredInitialReservation() / 1024)])
        args = args + self.dmargs
        if restore:
            args = args + ([ "-loadvm", "/tmp/xen.qemu-dm.%d" % self.vm.getDomid() ])
        env = dict(os.environ)
        if self.display:
            env['DISPLAY'] = self.display
        if self.xauthority:
            env['XAUTHORITY'] = self.xauthority
        if self.vncconsole:
            args = args + ([ "-vncviewer" ])
        log.info("spawning device models: %s %s", self.device_model, args)
        # keep track of pid and spawned options to kill it later
        self.pid = os.spawnve(os.P_NOWAIT, self.device_model, args, env)
        self.vm.storeDom("image/device-model-pid", self.pid)
        log.info("device model pid: %d", self.pid)

    def recreate(self):
        self.register_shutdown_watch()
        self.register_reboot_feature_watch()
        self.pid = self.vm.gatherDom(('image/device-model-pid', int))

    def destroy(self, suspend = False):
        self.unregister_shutdown_watch()
        self.unregister_reboot_feature_watch();
        if self.pid:
            try:
                sig = signal.SIGKILL
                if suspend:
                    log.info("use sigusr1 to signal qemu %d", self.pid)
                    sig = signal.SIGUSR1
                os.kill(self.pid, sig)
            except OSError, exn:
                log.exception(exn)
            try:
                os.waitpid(self.pid, 0)
            except OSError, exn:
                # This is expected if Xend has been restarted within the
                # life of this domain.  In this case, we can kill the process,
                # but we can't wait for it because it's not our child.
                pass
            self.pid = None

    def register_shutdown_watch(self):
        """ add xen store watch on control/shutdown """
        self.shutdownWatch = xswatch(self.vm.dompath + "/control/shutdown",
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
        xd = xen.xend.XendDomain.instance()
        try:
            vm = xd.domain_lookup( self.vm.getDomid() )
        except XendError:
            # domain isn't registered, no need to clean it up.
            return False

        reason = vm.getShutdownReason()
        log.debug("hvm_shutdown fired, shutdown reason=%s", reason)
        if reason in REVERSE_DOMAIN_SHUTDOWN_REASONS:
            vm.info['shutdown'] = 1
            vm.info['shutdown_reason'] = \
                REVERSE_DOMAIN_SHUTDOWN_REASONS[reason]
            vm.refreshShutdown(vm.info)

        return True # Keep watching

    def register_reboot_feature_watch(self):
        """ add xen store watch on control/feature-reboot """
        self.rebootFeatureWatch = xswatch(self.vm.dompath + "/control/feature-reboot", \
                                         self.hvm_reboot_feature)
        log.debug("hvm reboot feature watch registered")

    def unregister_reboot_feature_watch(self):
        """Remove the watch on the control/feature-reboot, if any. Nothrow
        guarantee."""

        try:
            if self.rebootFeatureWatch:
                self.rebootFeatureWatch.unwatch()
        except:
            log.exception("Unwatching hvm reboot feature watch failed.")
        self.rebootFeatureWatch = None
        log.debug("hvm reboot feature watch unregistered")

    def hvm_reboot_feature(self, _):
        """ watch call back on node control/feature-reboot,
            if node changed, this function will be called
        """
        status = self.vm.readDom('control/feature-reboot')
        log.debug("hvm_reboot_feature fired, module status=%s", status)
        if status == '1':
            self.unregister_shutdown_watch()

        return True # Keep watching


class IA64_HVM_ImageHandler(HVMImageHandler):

    def getRequiredAvailableMemory(self, mem_kb):
        page_kb = 16
        # ROM size for guest firmware, ioreq page and xenstore page
        extra_pages = 1024 + 3
        return mem_kb + extra_pages * page_kb

    def getRequiredInitialReservation(self):
        return self.vm.getMemoryTarget()

    def getRequiredShadowMemory(self, shadow_mem_kb, maxmem_kb):
        # Explicit shadow memory is not a concept 
        return 0

class X86_HVM_ImageHandler(HVMImageHandler):

    def getRequiredAvailableMemory(self, mem_kb):
        # Add 8 MiB overhead for QEMU's video RAM.
        return mem_kb + 8192

    def getRequiredInitialReservation(self):
        return self.vm.getMemoryTarget()

    def getRequiredMaximumReservation(self):
        return self.vm.getMemoryMaximum()

    def getRequiredShadowMemory(self, shadow_mem_kb, maxmem_kb):
        # 256 pages (1MB) per vcpu,
        # plus 1 page per MiB of RAM for the P2M map,
        # plus 1 page per MiB of RAM to shadow the resident processes.  
        # This is higher than the minimum that Xen would allocate if no value 
        # were given (but the Xen minimum is for safety, not performance).
        return max(4 * (256 * self.vm.getVCpuCount() + 2 * (maxmem_kb / 1024)),
                   shadow_mem_kb)

class X86_Linux_ImageHandler(LinuxImageHandler):

    def buildDomain(self):
        # set physical mapping limit
        # add an 8MB slack to balance backend allocations.
        mem_kb = self.getRequiredMaximumReservation() + (8 * 1024)
        xc.domain_set_memmap_limit(self.vm.getDomid(), mem_kb)
        return LinuxImageHandler.buildDomain(self)

_handlers = {
    "powerpc": {
        "linux": PPC_LinuxImageHandler,
        "prose": PPC_ProseImageHandler,
    },
    "ia64": {
        "linux": LinuxImageHandler,
        "hvm": IA64_HVM_ImageHandler,
    },
    "x86": {
        "linux": X86_Linux_ImageHandler,
        "hvm": X86_HVM_ImageHandler,
    },
}

def findImageHandlerClass(image):
    """Find the image handler class for an image config.

    @param image config
    @return ImageHandler subclass or None
    """
    image_type = image['type']
    if image_type is None:
        raise VmError('missing image type')
    try:
        return _handlers[arch.type][image_type]
    except KeyError:
        raise VmError('unknown image type: ' + image_type)
