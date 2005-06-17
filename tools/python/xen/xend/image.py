import os, string

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()
from xen.xend import sxp
from xen.xend.XendError import VmError
from xen.xend.XendLogging import log
from xen.xend.xenstore import DBVar

from xen.xend.server import channel

class ImageHandler:
    """Abstract base class for image handlers.

    initDomain() is called to initialise the domain memory.
    
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

    db = None
    ostype = None

    config = None
    kernel = None
    ramdisk = None
    cmdline = None
    flags = 0

    __exports__ = [
        DBVar('ostype',  ty='str'),
        DBVar('config',  ty='sxpr'),
        DBVar('kernel',  ty='str'),
        DBVar('ramdisk', ty='str'),
        DBVar('cmdline', ty='str'),
        DBVar('flags',   ty='int'),
        ]

    def __init__(self, vm, config):
        self.vm = vm
        self.db = vm.db.addChild('/image')
        self.config = config

    def exportToDB(self, save=False, sync=False):
        self.db.exportToDB(self, fields=self.__exports__, save=save, sync=sync)

    def importFromDB(self):
        self.db.importFromDB(self, fields=self.__exports__)

    def unlink(self, f):
        if not f: return
        try:
            os.unlink(f)
        except OSError, ex:
            log.warning("error removing bootloader file '%s': %s", f, ex)

    def initDomain(self, dom, memory, cpu, cpu_weight):
        """Initial domain create.

        @return domain id
        """

        mem_kb = self.getDomainMemory(memory)
        if not self.vm.restore:
            dom = xc.domain_create(dom = dom or 0)
            # if bootloader, unlink here. But should go after buildDomain() ?
            if self.vm.bootloader:
                self.unlink(self.kernel)
                self.unlink(self.ramdisk)
            if dom <= 0:
                raise VmError('Creating domain failed: name=%s' % self.vm.name)
        log.debug("initDomain: cpu=%d mem_kb=%d dom=%d", cpu, mem_kb, dom)
        # xc.domain_setuuid(dom, uuid)
        xc.domain_setcpuweight(dom, cpu_weight)
        xc.domain_setmaxmem(dom, mem_kb)
        xc.domain_memory_increase_reservation(dom, mem_kb)
        if cpu != -1:
            xc.domain_pincpu(dom, 0, 1<<int(cpu))
        return dom

    def createImage(self):
        """Entry point to create domain memory image.
        Override in subclass  if needed.
        """
        self.configure()
        self.createDomain()

    def configure(self):
        """Config actions common to all unix-like domains."""
        self.kernel = sxp.child_value(self.config, "kernel")
        self.cmdline = ""
        ip = sxp.child_value(self.config, "ip", None)
        if ip:
            self.cmdline += " ip=" + ip
        root = sxp.child_value(self.config, "root")
        if root:
            self.cmdline += " root=" + root
        args = sxp.child_value(self.config, "args")
        if args:
            self.cmdline += " " + args
        self.ramdisk = sxp.child_value(self.config, "ramdisk", '')
        
    def createDomain(self):
        """Build the domain boot image.
        """
        # Set params and call buildDomain().
        self.flags = 0
        if self.vm.netif_backend: self.flags |= SIF_NET_BE_DOMAIN
        if self.vm.blkif_backend: self.flags |= SIF_BLK_BE_DOMAIN

        if self.vm.recreate or self.vm.restore:
            return
        if not os.path.isfile(self.kernel):
            raise VmError('Kernel image does not exist: %s' % self.kernel)
        if self.ramdisk and not os.path.isfile(self.ramdisk):
            raise VmError('Kernel ramdisk does not exist: %s' % self.ramdisk)
        if len(self.cmdline) >= 256:
            log.warning('kernel cmdline too long, domain %d', self.vm.getDomain())
        
        log.info("buildDomain os=%s dom=%d vcpus=%d", self.ostype,
                 self.vm.getDomain(), self.vm.vcpus)
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

addImageHandlerClass = ImageHandler.addImageHandlerClass

class LinuxImageHandler(ImageHandler):

    ostype = "linux"

    def buildDomain(self):
        if self.vm.store_channel:
            store_evtchn = self.vm.store_channel.port2
        else:
            store_evtchn = 0
        ret = xc.linux_build(dom            = self.vm.getDomain(),
                             image          = self.kernel,
                             control_evtchn = self.vm.channel.getRemotePort(),
                             store_evtchn   = store_evtchn,
                             cmdline        = self.cmdline,
                             ramdisk        = self.ramdisk,
                             flags          = self.flags,
                             vcpus          = self.vm.vcpus)
        if isinstance(ret, dict):
            self.vm.store_mfn = ret.get('store_mfn')
            return 0
        return ret

class Plan9ImageHandler(ImageHandler):

    ostype = "plan9"

    def buildDomain(self):
        return xc.plan9_build(dom            = self.vm.getDomain(),
                              image          = self.kernel,
                              control_evtchn = self.vm.channel.getRemotePort(),
                              cmdline        = self.cmdline,
                              ramdisk        = self.ramdisk,
                              flags          = self.flags,
                              vcpus          = self.vm.vcpus)

class VmxImageHandler(ImageHandler):

    __exports__ = ImageHandler.__exports__ + [
        DBVar('memmap',        ty='str'),
        DBVar('memmap_value',  ty='sxpr'),
        # device channel?
        ]
    
    ostype = "vmx"
    memmap = None
    memmap_value = None
    device_channel = None

    def createImage(self):
        """Create a VM for the VMX environment.
        """
        self.configure()
        self.parseMemmap()
        self.createDomain()

    def buildDomain(self):
        return xc.vmx_build(dom            = self.vm.getDomain(),
                            image          = self.kernel,
                            control_evtchn = 0,
                            memsize        = self.vm.memory,
                            memmap         = self.memmap_value,
                            cmdline        = self.cmdline,
                            ramdisk        = self.ramdisk,
                            flags          = self.flags)

    def parseMemmap(self):
        self.memmap = sxp.child_value(self.vm.config, "memmap")
        if self.memmap is None:
            raise VmError("missing memmap")
        memmap = sxp.parse(open(self.memmap))[0]
        from xen.util.memmap import memmap_parse
        self.memmap_value = memmap_parse(memmap)
        
    def createDeviceModel_old(self):
        device_model = sxp.child_value(self.vm.config, 'device_model')
        if not device_model:
            raise VmError("vmx: missing device model")
        device_config = sxp.child_value(self.vm.config, 'device_config')
        if not device_config:
            raise VmError("vmx: missing device config")
        # Create an event channel.
        self.device_channel = channel.eventChannel(0, self.vm.getDomain())
        # Execute device model.
        #todo: Error handling
        os.system(device_model
                  + " -f %s" % device_config
                  + " -d %d" % self.vm.getDomain()
                  + " -p %d" % self.device_channel['port1']
                  + " -m %s" % self.vm.memory)

    def createDeviceModel(self):
        device_model = sxp.child_value(self.vm.config, 'device_model')
        if not device_model:
            raise VmError("vmx: missing device model")
        device_config = sxp.child_value(self.vm.config, 'device_config')
        if not device_config:
            raise VmError("vmx: missing device config")
        # Create an event channel
        self.device_channel = channel.eventChannel(0, self.vm.getDomain())
        # Execute device model.
        #todo: Error handling
        # XXX RN: note that the order of args matter!
        os.system(device_model
                  + " -f %s" % device_config
                  + self.vncParams()
                  + " -d %d" % self.vm.getDomain()
                  + " -p %d" % (int(self.device_channel.port1)-1)
                  + " -m %s" % self.vm.memory)

    def vncParams(self):
        # see if a vncviewer was specified
        # XXX RN: bit of a hack. should unify this, maybe stick in config space
        vncconnect=""
        image = self.config
        args = sxp.child_value(image, "args")
        if args:
            arg_list = string.split(args)
            for arg in arg_list:
                al = string.split(arg, '=')
                if al[0] == "VNC_VIEWER":
                    vncconnect=" -v %s" % al[1]
                    break
        return vncconnect

    def destroy(self):
        channel.eventChannelClose(self.device_channel)

    def getDomainMemory(self, mem_mb):
        return (mem_mb * 1024) + self.getPageTableSize(mem_mb)
            
    def getPageTableSize(self, mem_mb):
        """Return the size of memory needed for 1:1 page tables for physical
           mode.

        @param mem_mb: size in MB
        @return size in KB
        """
        # Logic x86-32 specific. 
        # 1 page for the PGD + 1 pte page for 4MB of memory (rounded)
        return (1 + ((mem_mb + 3) >> 2)) * 4
