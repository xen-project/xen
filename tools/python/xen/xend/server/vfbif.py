from xen.xend.server.DevController import DevController
from xen.xend.XendLogging import log

from xen.xend.XendError import VmError
import xen.xend
import os

def spawn_detached(path, args, env):
    p = os.fork()
    if p == 0:
        os.spawnve(os.P_NOWAIT, path, args, env)
        os._exit(0)
    else:
        os.waitpid(p, 0)
        
CONFIG_ENTRIES = ['type', 'vncdisplay', 'vnclisten', 'vncpasswd', 'vncunused',
                  'display', 'xauthority', 'keymap',
                  'uuid', 'location', 'protocol']

class VfbifController(DevController):
    """Virtual frame buffer controller. Handles all vfb devices for a domain.
    Note that we only support a single vfb per domain at the moment.
    """

    def __init__(self, vm):
        DevController.__init__(self, vm)
        
    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""

        back = dict([(k, str(config[k])) for k in CONFIG_ENTRIES
                     if config.has_key(k)])

        devid = 0
        return (devid, back, {})


    def getDeviceConfiguration(self, devid):
        result = DevController.getDeviceConfiguration(self, devid)

        devinfo = self.readBackend(devid, *CONFIG_ENTRIES)
        return dict([(CONFIG_ENTRIES[i], devinfo[i])
                     for i in range(len(CONFIG_ENTRIES))
                     if devinfo[i] is not None])


    def createDevice(self, config):
        DevController.createDevice(self, config)
        if self.vm.info.is_hvm():
            # is HVM, so qemu-dm will handle the vfb.
            return
        
        std_args = [ "--domid", "%d" % self.vm.getDomid(),
                     "--title", self.vm.getName() ]
        t = config.get("type", None)
        if t == "vnc":
            passwd = None
            if config.has_key("vncpasswd"):
                passwd = config["vncpasswd"]
            else:
                passwd = xen.xend.XendOptions.instance().get_vncpasswd_default()
            if passwd:
                self.vm.storeVm("vncpasswd", passwd)
                log.debug("Stored a VNC password for vfb access")
            else:
                log.debug("No VNC passwd configured for vfb access")

            # Try to start the vnc backend
            args = [xen.util.auxbin.pathTo("xen-vncfb")]
            if config.has_key("vncunused"):
                args += ["--unused"]
            elif config.has_key("vncdisplay"):
                args += ["--vncport", "%d" % (5900 + int(config["vncdisplay"]))]
            vnclisten = config.get("vnclisten",
                                   xen.xend.XendOptions.instance().get_vnclisten_address())
            args += [ "--listen", vnclisten ]
            if config.has_key("keymap"):
                args += ["-k", "%s" % config["keymap"]]
            spawn_detached(args[0], args + std_args, os.environ)
        elif t == "sdl":
            args = [xen.util.auxbin.pathTo("xen-sdlfb")]
            env = dict(os.environ)
            if config.has_key("display"):
                env['DISPLAY'] = config["display"]
            if config.has_key("xauthority"):
                env['XAUTHORITY'] = config["xauthority"]
            spawn_detached(args[0], args + std_args, env)
        else:
            raise VmError('Unknown vfb type %s (%s)' % (t, repr(config)))


    def waitForDevice(self, devid):
        if self.vm.info.get('HVM_boot_policy'):
            log.debug('skip waiting for HVM vfb')
            # is a qemu-dm managed device, don't wait for hotplug for these.
            return

        DevController.waitForDevice(self, devid)


    def reconfigureDevice(self, _, config):
        """ Only allow appending location information of vnc port into
        xenstore."""

        if 'location' in config:
            (devid, back, front) = self.getDeviceDetails(config)
            self.writeBackend(devid, 'location', config['location'])
            return back.get('uuid')

        raise VmError('Refusing to reconfigure device vfb:%d' % devid)

    def destroyDevice(self, devid, force):
        if self.vm.info.get('HVM_boot_policy'):
            # remove the backend xenstore entries for HVM guests no matter
            # what
            DevController.destroyDevice(self, devid, True)
        else:
            DevController.destroyDevice(self, devid, force)


    def migrate(self, deviceConfig, network, dst, step, domName):
        if self.vm.info.get('HVM_boot_policy'):        
            return 0
        return DevController.migrate(self, deviceConfig, network, dst, step,
                                     domName)
    
class VkbdifController(DevController):
    """Virtual keyboard controller. Handles all vkbd devices for a domain.
    """

    def getDeviceDetails(self, config):
        """@see DevController.getDeviceDetails"""
        devid = 0
        back = {}
        front = {}
        return (devid, back, front)

    def waitForDevice(self, config):
        if self.vm.info.get('HVM_boot_policy'):
            # is a qemu-dm managed device, don't wait for hotplug for these.
            return

        DevController.waitForDevice(self, config)

    def destroyDevice(self, devid, force):
        if self.vm.info.get('HVM_boot_policy'):
            # remove the backend xenstore entries for HVM guests no matter
            # what
            DevController.destroyDevice(self, devid, True)
        else:
            DevController.destroyDevice(self, devid, force)

    def migrate(self, deviceConfig, network, dst, step, domName):
        if self.vm.info.get('HVM_boot_policy'):        
            return 0
        return DevController.migrate(self, deviceConfig, network, dst, step,
                                     domName)        
