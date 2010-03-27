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
# Copyright (C) 2005-2007 XenSource Ltd
#============================================================================


import os, os.path, string
import re
import math
import time
import signal
import thread
import fcntl
import sys
import errno
import glob
import traceback
import platform

import xen.lowlevel.xc
from xen.xend.XendConstants import *
from xen.xend.XendError import VmError, XendError, HVMRequired
from xen.xend.XendLogging import log
from xen.xend.XendOptions import instance as xenopts
from xen.xend.xenstore.xstransact import xstransact
from xen.xend.xenstore.xswatch import xswatch
from xen.xend import arch
from xen.xend import XendOptions
from xen.util import oshelp
from xen.util import utils
from xen.xend import osdep

xc = xen.lowlevel.xc.xc()

MAX_GUEST_CMDLINE = 1024

sentinel_path_prefix = '/var/run/xend/dm-'
sentinel_fifos_inuse = { }

def cleanup_stale_sentinel_fifos():
    for path in glob.glob(sentinel_path_prefix + '*.fifo'):
        if path in sentinel_fifos_inuse: continue
        try: os.unlink(path)
        except OSError, e:
            log.warning('could not delete stale fifo %s: %s',
                path, utils.exception_string(e))

def create(vm, vmConfig):
    """Create an image handler for a vm.

    @return ImageHandler instance
    """
    return findImageHandlerClass(vmConfig)(vm, vmConfig)


class ImageHandler:
    """Abstract base class for image handlers.

    createImage() is called to configure and build the domain from its
    kernel image and ramdisk etc.

    The method buildDomain() is used to build the domain, and must be
    defined in a subclass.  Usually this is the only method that needs
    defining in a subclass.

    The method createDeviceModel() is called to create the domain device
    model.

    The method destroyDeviceModel() is called to reap the device model
    """

    ostype = None
    superpages = 0
    memory_sharing = 0

    def __init__(self, vm, vmConfig):
        self.vm = vm

        self.bootloader = False
        self.use_tmp_kernel = False
        self.use_tmp_ramdisk = False
        self.kernel = None
        self.ramdisk = None
        self.cmdline = None

        self.configure(vmConfig)

    def configure(self, vmConfig):
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
        # There a code-paths where use_tmp_xxx is not set at all; but if
        # this is set, the variable itself is a boolean.
        if 'use_tmp_kernel' in vmConfig and vmConfig['use_tmp_kernel']:
            self.use_tmp_kernel = True
        if 'use_tmp_ramdisk' in vmConfig and vmConfig['use_tmp_ramdisk']:
            self.use_tmp_ramdisk = True
        self.vm.storeVm(("image/ostype", self.ostype),
                        ("image/kernel", self.kernel),
                        ("image/cmdline", self.cmdline),
                        ("image/ramdisk", self.ramdisk))
        self.vm.permissionsVm("image/cmdline", { 'dom': self.vm.getDomid(), 'read': True } )

        self.device_model = vmConfig['platform'].get('device_model')

        self.display = vmConfig['platform'].get('display')
        self.xauthority = vmConfig['platform'].get('xauthority')
        self.vncconsole = int(vmConfig['platform'].get('vncconsole', 0))
        self.dmargs = self.parseDeviceModelArgs(vmConfig)
        self.pid = None
        rtc_timeoffset = int(vmConfig['platform'].get('rtc_timeoffset', 0))
        if vmConfig['platform'].get('localtime', 0):
            if time.localtime(time.time())[8]:
                rtc_timeoffset -= time.altzone
            else:
                rtc_timeoffset -= time.timezone
        if rtc_timeoffset != 0:
            xc.domain_set_time_offset(self.vm.getDomid(), rtc_timeoffset)

        self.cpuid = None
        self.cpuid_check = None
        if 'cpuid' in vmConfig:
            self.cpuid = vmConfig['cpuid'];
        if 'cpuid_check' in vmConfig:
            self.cpuid_check = vmConfig['cpuid_check']

    def cleanupTmpImages(self):
        if self.use_tmp_kernel:
            self.unlink(self.kernel)
        if self.use_tmp_ramdisk:
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

        if self.kernel and not os.path.isfile(self.kernel):
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

    def prepareEnvironment(self):
        """Prepare the environment for the execution of the domain. This
        method is called before any devices are set up."""
        
        domid = self.vm.getDomid()
        
        # Delete left-over pipes
        try:
            os.unlink('/var/run/tap/qemu-read-%d' % domid)
            os.unlink('/var/run/tap/qemu-write-%d' % domid)
        except:
            pass

        # No device model, don't create pipes
        if self.device_model is None:
            return

        if platform.system() != 'SunOS':
            # If we use a device model, the pipes for communication between
            # blktapctrl and ioemu must be present before the devices are 
            # created (blktapctrl must access them for new block devices)

            try:
                os.makedirs('/var/run/tap', 0755)
            except:
                pass

            try:
                os.mkfifo('/var/run/tap/qemu-read-%d' % domid, 0600)
                os.mkfifo('/var/run/tap/qemu-write-%d' % domid, 0600)
            except OSError, e:
                log.warn('Could not create blktap pipes for domain %d' % domid)
                log.exception(e)
                pass


    # Return a list of cmd line args to the device models based on the
    # xm config file
    def parseDeviceModelArgs(self, vmConfig):
        ret = ["-domain-name", str(self.vm.info['name_label'])]

        xen_extended_power_mgmt = int(vmConfig['platform'].get(
            'xen_extended_power_mgmt', 0))
        if xen_extended_power_mgmt != 0:
             xstransact.Store("/local/domain/0/device-model/%i"
                              % self.vm.getDomid(),
                              ('xen_extended_power_mgmt',
                               xen_extended_power_mgmt))

        # Find RFB console device, and if it exists, make QEMU enable
        # the VNC console.
        if int(vmConfig['platform'].get('nographic', 0)) != 0:
            # skip vnc init if nographic is set
            ret.append('-nographic')
            return ret

        vram = str(vmConfig['platform'].get('videoram',4))
        ret.append('-videoram')
        ret.append(vram)

        vnc_config = {}
        has_vnc = int(vmConfig['platform'].get('vnc', 0)) != 0
        has_sdl = int(vmConfig['platform'].get('sdl', 0)) != 0
        opengl = 1
        keymap = vmConfig['platform'].get("keymap")
        for dev_uuid in vmConfig['console_refs']:
            dev_type, dev_info = vmConfig['devices'][dev_uuid]
            if dev_type == 'vfb':
                if 'keymap' in dev_info:
                    keymap = dev_info.get('keymap',{})
                if 'monitor' in dev_info:
                    ret.append("-serial")
                    ret.append(dev_info.get('monitor',{}))
                    ret.append("-monitor")
                    ret.append("null")
                if 'serial' in dev_info:
                    ret.append("-serial")
                    ret.append(dev_info.get('serial',{}))
                if int(dev_info.get('vnc', 0)) != 0 :
                    has_vnc = True
                if int(dev_info.get('sdl', 0)) != 0 :
                    has_sdl = True
                if has_sdl:
                    self.display = dev_info.get('display', self.display)
                    self.xauthority = dev_info.get('xauthority', self.xauthority)
                    opengl = int(dev_info.get('opengl', opengl))
                if has_vnc:
                    vnc_config = dev_info.get('other_config', {})
                break

        if keymap:
            ret.append("-k")
            ret.append(keymap)

        if has_vnc:
            if not vnc_config:
                for key in ('vncunused', 'vnclisten', 'vncdisplay',
                            'vncpasswd'):
                    if key in vmConfig['platform']:
                        vnc_config[key] = vmConfig['platform'][key]
            if vnc_config.has_key("vncpasswd"):
                passwd = vnc_config["vncpasswd"]
            else:
                passwd = XendOptions.instance().get_vncpasswd_default()
            vncopts = ""
            if passwd:
                self.vm.storeVm("vncpasswd", passwd)
                self.vm.permissionsVm("vncpasswd", { 'dom': self.vm.getDomid(), 'read': True } )
                vncopts = vncopts + ",password"
                log.debug("Stored a VNC password for vfb access")
            else:
                log.debug("No VNC passwd configured for vfb access")

            if XendOptions.instance().get_vnc_tls():
                vncx509certdir = XendOptions.instance().get_vnc_x509_cert_dir()
                vncx509verify = XendOptions.instance().get_vnc_x509_verify()

                if not os.path.exists(vncx509certdir):
                    raise VmError("VNC x509 certificate dir %s does not exist" % vncx509certdir)

                if vncx509verify:
                    vncopts = vncopts + ",tls,x509verify=%s" % vncx509certdir
                else:
                    vncopts = vncopts + ",tls,x509=%s" % vncx509certdir


            vnclisten = vnc_config.get('vnclisten',
                                       XendOptions.instance().get_vnclisten_address())
            vncdisplay = int(vnc_config.get('vncdisplay', 0))
            ret.append('-vnc')
            ret.append("%s:%s%s" % (vnclisten, vncdisplay, vncopts))

            if int(vnc_config.get('vncunused', 1)) != 0:
                ret.append('-vncunused')

        if has_sdl:
            ret.append('-sdl')
            if int(vmConfig['platform'].get('opengl', opengl)) != 1 :
                ret.append('-disable-opengl')

        if not has_sdl and not has_vnc :
            ret.append('-nographic')

        if vmConfig['platform'].get('parallel'):
            ret = ret + ["-parallel", vmConfig['platform'].get('parallel')]

        if int(vmConfig['platform'].get('monitor', 0)) != 0:
            if vmConfig['platform'].get('monitor_path'):
                ret = ret + ['-monitor', vmConfig['platform'].get('monitor_path')]
            else:
                ret = ret + ['-monitor', 'vc']

        return ret

    def getDeviceModelArgs(self, restore = False):
        args = [self.device_model]
        args = args + ([ "-d",  "%d" % self.vm.getDomid() ])
        args = args + self.dmargs
        return args

    def _openSentinel(self, sentinel_path_fifo):
        self.sentinel_fifo = file(sentinel_path_fifo, 'r')
        self.sentinel_lock = thread.allocate_lock()
        oshelp.fcntl_setfd_cloexec(self.sentinel_fifo, True)
        sentinel_fifos_inuse[sentinel_path_fifo] = 1
        self.sentinel_path_fifo = sentinel_path_fifo

    def createDeviceModel(self, restore = False):
        if self.device_model is None:
            return
        if self.pid:
            return
        # Execute device model.
        #todo: Error handling
        args = self.getDeviceModelArgs(restore)
        env = dict(os.environ)
        if self.display:
            env['DISPLAY'] = self.display
        if self.xauthority:
            env['XAUTHORITY'] = self.xauthority
        unique_id = "%i-%i" % (self.vm.getDomid(), time.time())
        sentinel_path = sentinel_path_prefix + unique_id
        sentinel_path_fifo = sentinel_path + '.fifo'
        os.mkfifo(sentinel_path_fifo, 0600)
        sentinel_write = file(sentinel_path_fifo, 'r+')
        self._openSentinel(sentinel_path_fifo)
        self.vm.storeDom("image/device-model-fifo", sentinel_path_fifo)
        xstransact.Mkdir("/local/domain/0/device-model/%i" % self.vm.getDomid())
        xstransact.SetPermissions("/local/domain/0/device-model/%i" % self.vm.getDomid(),
                        { 'dom': self.vm.getDomid(), 'read': True, 'write': True })
        log.info("spawning device models: %s %s", self.device_model, args)
        # keep track of pid and spawned options to kill it later

        self.logfile = "/var/log/xen/qemu-dm-%s.log" %  str(self.vm.info['name_label'])

        # rotate log
        logfile_mode = os.O_WRONLY|os.O_CREAT|os.O_APPEND
        logrotate_count = XendOptions.instance().get_qemu_dm_logrotate_count()
        if logrotate_count > 0:
            logfile_mode |= os.O_TRUNC
            if os.path.exists("%s.%d" % (self.logfile, logrotate_count)):
                os.unlink("%s.%d" % (self.logfile, logrotate_count))
            for n in range(logrotate_count - 1, 0, -1):
                if os.path.exists("%s.%d" % (self.logfile, n)):
                    os.rename("%s.%d" % (self.logfile, n),
                              "%s.%d" % (self.logfile, (n + 1)))
            if os.path.exists(self.logfile):
                os.rename(self.logfile, self.logfile + ".1")

        null = os.open("/dev/null", os.O_RDONLY)
        logfd = os.open(self.logfile, logfile_mode, 0666)
        
        sys.stderr.flush()
        contract = osdep.prefork("%s:%d" %
                                 (self.vm.getName(), self.vm.getDomid()))
        pid = os.fork()
        if pid == 0: #child
            try:
                osdep.postfork(contract)
                os.dup2(null, 0)
                os.dup2(logfd, 1)
                os.dup2(logfd, 2)
                oshelp.close_fds((sentinel_write.fileno(),))
                try:
                    os.execve(self.device_model, args, env)
                except Exception, e:
                    print >>sys.stderr, (
                        'failed to set up fds or execute dm %s: %s' %
                        (self.device_model, utils.exception_string(e)))
                    os._exit(126)
            except:
                os._exit(127)
        else:
            osdep.postfork(contract, abandon=True)
            self.pid = pid
            os.close(null)
            os.close(logfd)
        sentinel_write.close()
        self.vm.storeDom("image/device-model-pid", self.pid)
        log.info("device model pid: %d", self.pid)
        # we would very much prefer not to have a thread here and instead
        #  have a callback but sadly we don't have Twisted in xend
        self.sentinel_thread = thread.start_new_thread(self._sentinel_watch,())
        if self.device_model.find('stubdom-dm') > -1 :
            from xen.xend import XendDomain
            domains = XendDomain.instance()
            domains.domains_lock.release()

            count = 0
            while True:
                orig_state = xstransact.Read("/local/domain/0/device-model/%i/state"
                                    % self.vm.getDomid())
                # This can occur right after start-up
                if orig_state != None:
                    break

                log.debug('createDeviceModel %i: orig_state is None, retrying' % self.vm.getDomid())

                time.sleep(0.1)
                count += 1
                if count > 100:
                    break

            domains.domains_lock.acquire()

    def signalDeviceModel(self, cmd, ret, par = None):
        if self.device_model is None:
            return
        # Signal the device model to for action
        if cmd is '' or ret is '':
            raise VmError('need valid command and result when signal device model')

        count = 0
        while True:
            orig_state = xstransact.Read("/local/domain/0/device-model/%i/state"
                                % self.vm.getDomid())
            # This can occur right after start-up
            if orig_state != None:
                break

            log.debug('signalDeviceModel: orig_state is None, retrying')

            time.sleep(0.1)
            count += 1
            if count < 100:
                continue

            raise VmError('Device model isn\'t ready for commands')

        if par is not None:
            xstransact.Store("/local/domain/0/device-model/%i"
                             % self.vm.getDomid(), ('parameter', par))

        xstransact.Store("/local/domain/0/device-model/%i"
                         % self.vm.getDomid(), ('command', cmd))
        # Wait for confirmation.  Could do this with a watch but we'd
        # still end up spinning here waiting for the watch to fire. 
        state = ''
        count = 0
        while state != ret:
            state = xstransact.Read("/local/domain/0/device-model/%i/state"
                                    % self.vm.getDomid())
            time.sleep(0.1)
            count += 1
            if count > 100:
                raise VmError('Timed out waiting for device model action')

        #resotre orig state
        xstransact.Store("/local/domain/0/device-model/%i"
                         % self.vm.getDomid(), ('state', orig_state))
        log.info("signalDeviceModel:restore dm state to %s", orig_state)

    def saveDeviceModel(self):
        # Signal the device model to pause itself and save its state
        self.signalDeviceModel('save', 'paused')

    def resumeDeviceModel(self):
        if self.device_model is None:
            return
        # Signal the device model to resume activity after pausing to save.
        xstransact.Store("/local/domain/0/device-model/%i"
                         % self.vm.getDomid(), ('command', 'continue'))

    def _dmfailed(self, message):
        log.warning("domain %s: %s", self.vm.getName(), message)
        try:
            xc.domain_shutdown(self.vm.getDomid(), DOMAIN_CRASH)
        except:
            pass

    def recreate(self):
        if self.device_model is None:
            return
        name = self.vm.getName()
        sentinel_path_fifo = self.vm.readDom('image/device-model-fifo')
        fifo_fd = -1
        log.debug("rediscovering %s", sentinel_path_fifo)
        if sentinel_path_fifo is None:
            log.debug("%s device model no sentinel, cannot rediscover", name)
        else:
            try:
                # We open it O_WRONLY because that fails ENXIO if no-one
                # has it open for reading (see SuSv3).  The dm process got
                # a read/write descriptor from our earlier invocation.
                fifo_fd = os.open(sentinel_path_fifo, os.O_WRONLY|os.O_NONBLOCK)
            except OSError, e:
                if e.errno == errno.ENXIO:
                    self._dmfailed("%s device model no longer running"%name)
                elif e.errno == errno.ENOENT:
                    log.debug("%s device model sentinel %s absent!",
                            name, sentinel_path_fifo)
                else:
                    raise
        if fifo_fd >= 0:
            self._openSentinel(sentinel_path_fifo)
            os.close(fifo_fd)
            self.pid = self.vm.gatherDom(('image/device-model-pid', int))
            log.debug("%s device model rediscovered, pid %s sentinel fifo %s",
                    name, self.pid, sentinel_path_fifo)
            self.sentinel_thread = thread.start_new_thread(self._sentinel_watch,())

    def _sentinel_watch(self):
        log.info("waiting for sentinel_fifo")
        try: self.sentinel_fifo.read(1)
        except OSError, e: pass
        self.sentinel_lock.acquire()
        if self.pid:
            try:
                (p,st) = os.waitpid(self.pid, os.WNOHANG)
                if p == self.pid:
                    message = oshelp.waitstatus_description(st)
                else:
                    # obviously it is malfunctioning, kill it now
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                        message = "malfunctioning (closed sentinel), killed"
                    except:
                        message = "malfunctioning or died ?"
                message = "pid %d: %s" % (self.pid, message)
            except Exception, e:
                message = "waitpid failed: %s" % utils.exception_string(e)
            message = "device model failure: %s" % message
            try: message += "; see %s " % self.logfile
            except: pass
            self._dmfailed(message)
            self.pid = None
        else:
            log.info("%s device model terminated", self.vm.getName())
        self.sentinel_lock.release()

    def destroyDeviceModel(self):
        if self.device_model is None:
            return
        self.sentinel_lock.acquire()
        try:
            stubdomid = self.vm.getStubdomDomid()
            if stubdomid is not None :
                from xen.xend import XendDomain
                XendDomain.instance().domain_destroy(stubdomid)
            elif self.pid:
                try:
                    os.kill(self.pid, signal.SIGHUP)
                except OSError, exn:
                    log.exception(exn)
                # Try to reap the child every 100ms for 10s. Then SIGKILL it.
                for i in xrange(100):
                    try:
                        (p, rv) = os.waitpid(self.pid, os.WNOHANG)
                        if p == self.pid:
                            break
                    except OSError:
                        # This is expected if Xend has been restarted within
                        # the life of this domain.  In this case, we can kill
                        # the process, but we can't wait for it because it's
                        # not our child. We continue this loop, and after it is
                        # terminated make really sure the process is going away
                        # (SIGKILL).
                        pass
                    time.sleep(0.1)
                else:
                    log.warning("DeviceModel %d took more than 10s "
                                "to terminate: sending SIGKILL" % self.pid)
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                        os.waitpid(self.pid, 0)
                    except OSError:
                        # This happens if the process doesn't exist.
                        pass
        finally:
            self.pid = None
            self.sentinel_lock.release()
            
        state = xstransact.Remove("/local/domain/0/device-model/%i"
                                  % self.vm.getDomid())
        try:
            os.unlink('/var/run/tap/qemu-read-%d' % self.vm.getDomid())
            os.unlink('/var/run/tap/qemu-write-%d' % self.vm.getDomid())
        except:
            pass
        try:
            del sentinel_fifos_inuse[self.sentinel_path_fifo]
            os.unlink(self.sentinel_path_fifo)
        except:
            pass

    def setCpuid(self):
        xc.domain_set_policy_cpuid(self.vm.getDomid())

        if self.cpuid is not None:
            cpuid = self.cpuid
            transformed = {}
            for sinput, regs in cpuid.iteritems():
                inputs = sinput.split(',')
                input = long(inputs[0])
                sub_input = None
                if len(inputs) == 2:
                    sub_input = long(inputs[1])
                t = xc.domain_set_cpuid(self.vm.getDomid(),
                                        input, sub_input, regs)
                transformed[sinput] = t
            self.cpuid = transformed

        if self.cpuid_check is not None:
            cpuid_check = self.cpuid_check
            transformed = {}
            for sinput, regs_check in cpuid_check.iteritems():
                inputs = sinput.split(',')
                input = long(inputs[0])
                sub_input = None
                if len(inputs) == 2:
                    sub_input = long(inputs[1])
                t = xc.domain_check_cpuid(input, sub_input, regs_check)
                transformed[sinput] = t
            self.cpuid_check = transformed

class LinuxImageHandler(ImageHandler):

    ostype = "linux"
    flags = 0
    vhpt = 0

    def configure(self, vmConfig):
        ImageHandler.configure(self, vmConfig)
        self.vramsize = int(vmConfig['platform'].get('videoram',4)) * 1024
        self.is_stubdom = (self.kernel.find('stubdom') >= 0)
        self.superpages = int(vmConfig['superpages'])

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
        log.debug("flags          = %d", self.flags)
        log.debug("superpages     = %d", self.superpages)
        if arch.type == "ia64":
            log.debug("vhpt          = %d", self.vhpt)

        return xc.linux_build(domid          = self.vm.getDomid(),
                              memsize        = mem_mb,
                              image          = self.kernel,
                              store_evtchn   = store_evtchn,
                              console_evtchn = console_evtchn,
                              cmdline        = self.cmdline,
                              ramdisk        = self.ramdisk,
                              features       = self.vm.getFeatures(),
                              flags          = self.flags,
                              vhpt           = self.vhpt,
                              superpages     = self.superpages)

    def getBitSize(self):
        return xc.getBitSize(image    = self.kernel,
                                 cmdline  = self.cmdline,
                                 features = self.vm.getFeatures()
                                 ).get('type') 

    def getRequiredAvailableMemory(self, mem_kb):
        if self.is_stubdom :
            mem_kb += self.vramsize
        return mem_kb

    def getRequiredInitialReservation(self):
        return self.vm.getMemoryTarget()

    def getRequiredMaximumReservation(self):
        return self.vm.getMemoryMaximum()

    def parseDeviceModelArgs(self, vmConfig):
        ret = ImageHandler.parseDeviceModelArgs(self, vmConfig)
        if vmConfig['platform'].get('serial'):
            ret = ["-serial", vmConfig['platform'].get('serial')] + ret
        else:
            ret = ["-serial", "pty"] + ret
        return ret

    def getDeviceModelArgs(self, restore = False):
        args = ImageHandler.getDeviceModelArgs(self, restore)
        args = args + ([ "-M", "xenpv"])
        return args


class HVMImageHandler(ImageHandler):

    ostype = "hvm"

    def __init__(self, vm, vmConfig):
        ImageHandler.__init__(self, vm, vmConfig)
        self.shutdownWatch = None
        self.rebootFeatureWatch = None
    
    def getBitSize(self):
        return None

    def configure(self, vmConfig):
        ImageHandler.configure(self, vmConfig)

        self.loader = vmConfig['platform'].get('loader')

        info = xc.xeninfo()
        if 'hvm' not in info['xen_caps']:
            raise HVMRequired()

        xen_platform_pci = int(vmConfig['platform'].get('xen_platform_pci',1))
        rtc_timeoffset = vmConfig['platform'].get('rtc_timeoffset')

        if not self.display :
            self.display = ''

        store_dmargs = [ x for x in self.dmargs
                         if x not in ['-sdl', '-disable-opengl'] ]
        try :
            midx = store_dmargs.index('-monitor')
            store_dmargs[midx + 1] = 'pty'
        except ValueError :
            pass
        self.vm.storeVm(("image/dmargs", " ".join(store_dmargs)),
                        ("image/device-model", self.device_model),
                        ("image/display", self.display))
        self.vm.permissionsVm("image/dmargs", { 'dom': self.vm.getDomid(), 'read': True } )

        if xen_platform_pci == 0:
            disable_pf = 1
            log.info("No need to create platform device.[domid:%d]", self.vm.getDomid())
        else:
            disable_pf = 0
            log.info("Need to create platform device.[domid:%d]", self.vm.getDomid())

        xstransact.Store("/local/domain/0/device-model/%i"%self.vm.getDomid(),
                                      ('disable_pf', disable_pf))
        self.vm.storeVm(("rtc/timeoffset", rtc_timeoffset))
        self.vm.permissionsVm("rtc/timeoffset", { 'dom': self.vm.getDomid(), 'read': True } )

        self.apic = int(vmConfig['platform'].get('apic', 0))
        self.acpi = int(vmConfig['platform'].get('acpi', 0))
        self.guest_os_type = vmConfig['platform'].get('guest_os_type')
        self.memory_sharing = int(vmConfig['memory_sharing'])
        xc.dom_set_memshr(self.vm.getDomid(), self.memory_sharing)


    # Return a list of cmd line args to the device models based on the
    # xm config file
    def parseDeviceModelArgs(self, vmConfig):
        ret = ImageHandler.parseDeviceModelArgs(self, vmConfig)
        ret = ret + ['-vcpus', str(self.vm.getVCpuCount())]
        ret = ret + ['-vcpu_avail', hex(self.vm.getVCpuAvail())]

        if self.kernel:
            log.debug("kernel         = %s", self.kernel)
            ret = ret + ['-kernel', self.kernel]
        if self.ramdisk:
            log.debug("ramdisk        = %s", self.ramdisk)
            ret = ret + ['-initrd', self.ramdisk]
        if self.cmdline:
            log.debug("cmdline        = %s", self.cmdline)
            ret = ret + ['-append', self.cmdline]


        dmargs = [ 'boot', 'fda', 'fdb', 'soundhw',
                   'localtime', 'serial', 'stdvga', 'isa',
                   'acpi', 'usb', 'usbdevice', 'gfx_passthru' ]

        for a in dmargs:
            v = vmConfig['platform'].get(a)

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
            elif a == 'serial':
                if v:
                    if type(v) == str:
                        v = [v]
                    for s in v:
                        if s:
                            ret.append("-serial")
                            ret.append("%s" % s)
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
                raise VmError("MAC address not specified or generated.")
            bridge = devinfo.get('bridge', 'xenbr0')
            model = devinfo.get('model', 'rtl8139')
            ret.append("-net")
            ret.append("nic,vlan=%d,macaddr=%s,model=%s" %
                       (nics, mac, model))
            vifname = devinfo.get('vifname')
            if vifname:
                vifname = "tap-" + vifname
            else:
                vifname = "tap%d.%d" % (self.vm.getDomid(), nics-1)
            ret.append("-net")
            ret.append("tap,vlan=%d,ifname=%s,bridge=%s" %
                       (nics, vifname, bridge))

        if nics == 0:
            ret.append("-net")
            ret.append("none")

        return ret

    def getDeviceModelArgs(self, restore = False):
        args = ImageHandler.getDeviceModelArgs(self, restore)
        args = args + ([ "-M", "xenfv"])
        if restore:
            args = args + ([ "-loadvm", "/var/lib/xen/qemu-save.%d" %
                             self.vm.getDomid() ])
        return args

    def buildDomain(self):
        store_evtchn = self.vm.getStorePort()

        memmax_mb = self.getRequiredMaximumReservation() / 1024
        mem_mb = self.getRequiredInitialReservation() / 1024

        log.debug("domid          = %d", self.vm.getDomid())
        log.debug("image          = %s", self.loader)
        log.debug("store_evtchn   = %d", store_evtchn)
        log.debug("memsize        = %d", memmax_mb)
        log.debug("target         = %d", mem_mb)
        log.debug("vcpus          = %d", self.vm.getVCpuCount())
        log.debug("vcpu_avail     = %li", self.vm.getVCpuAvail())
        log.debug("acpi           = %d", self.acpi)
        log.debug("apic           = %d", self.apic)

        rc = xc.hvm_build(domid          = self.vm.getDomid(),
                          image          = self.loader,
                          memsize        = memmax_mb,
                          target         = mem_mb,
                          vcpus          = self.vm.getVCpuCount(),
                          vcpu_avail     = self.vm.getVCpuAvail(),
                          acpi           = self.acpi,
                          apic           = self.apic)
        rc['notes'] = { 'SUSPEND_CANCEL': 1 }

        rc['store_mfn'] = xc.hvm_get_param(self.vm.getDomid(),
                                           HVM_PARAM_STORE_PFN)
        xc.hvm_set_param(self.vm.getDomid(), HVM_PARAM_STORE_EVTCHN,
                         store_evtchn)

        return rc


class IA64_HVM_ImageHandler(HVMImageHandler):

    def configure(self, vmConfig):
        HVMImageHandler.configure(self, vmConfig)
        self.vhpt = int(vmConfig['platform'].get('vhpt',  0))
        self.vramsize = int(vmConfig['platform'].get('videoram',4)) * 1024

    def buildDomain(self):
        xc.nvram_init(self.vm.getName(), self.vm.getDomid())
        xc.hvm_set_param(self.vm.getDomid(), HVM_PARAM_VHPT_SIZE, self.vhpt)
        if self.guest_os_type is not None:
            xc.set_os_type(self.guest_os_type.lower(), self.vm.getDomid())
        return HVMImageHandler.buildDomain(self)

    def getRequiredAvailableMemory(self, mem_kb):
        page_kb = 16
        # ROM size for guest firmware, io page, xenstore page
        # buffer io page, buffer pio page and memmap info page
        extra_pages = 1024 + 5
        mem_kb += extra_pages * page_kb
        mem_kb += self.vramsize
        return mem_kb

    def getRequiredInitialReservation(self):
        return self.vm.getMemoryTarget()

    def getRequiredShadowMemory(self, shadow_mem_kb, maxmem_kb):
        # Explicit shadow memory is not a concept 
        return 0

    def getDeviceModelArgs(self, restore = False):
        args = HVMImageHandler.getDeviceModelArgs(self, restore)
        args = args + ([ "-m", "%s" %
                         (self.getRequiredInitialReservation() / 1024) ])
        return args

    def setCpuid(self):
        # Guest CPUID configuration is not implemented yet.
        return

class IA64_Linux_ImageHandler(LinuxImageHandler):

    def configure(self, vmConfig):
        LinuxImageHandler.configure(self, vmConfig)
        self.vhpt = int(vmConfig['platform'].get('vhpt',  0))

    def setCpuid(self):
        # Guest CPUID configuration is not implemented yet.
        return

class X86_HVM_ImageHandler(HVMImageHandler):

    def configure(self, vmConfig):
        HVMImageHandler.configure(self, vmConfig)
        self.pae = int(vmConfig['platform'].get('pae',  0))
        self.vramsize = int(vmConfig['platform'].get('videoram',4)) * 1024

    def buildDomain(self):
        xc.hvm_set_param(self.vm.getDomid(), HVM_PARAM_PAE_ENABLED, self.pae)
        rc = HVMImageHandler.buildDomain(self)
        self.setCpuid()
        return rc
    
    def getBitSize(self):
        return None

    def getRequiredAvailableMemory(self, mem_kb):
        return mem_kb + self.vramsize

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
        rc = LinuxImageHandler.buildDomain(self)
        self.setCpuid()
        return rc

_handlers = {
    "ia64": {
        "linux": IA64_Linux_ImageHandler,
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
    image_type = image.image_type()
    try:
        return _handlers[arch.type][image_type]
    except KeyError:
        raise VmError('unknown image type: ' + image_type)

