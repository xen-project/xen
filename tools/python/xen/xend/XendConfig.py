#===========================================================================
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
# Copyright (C) 2006 XenSource Ltd
#============================================================================

import re
import time

from xen.xend import sxp
from xen.xend import uuid
from xen.xend.XendError import VmError
from xen.xend.XendDevices import XendDevices
from xen.xend.XendLogging import log
from xen.xend.PrettyPrint import prettyprintstring

"""
XendConfig API

  XendConfig will try to mirror as closely the Xen API VM Struct
  providing a backwards compatibility mode for SXP dumping, loading.

XendConfig is a subclass of the python dict in order to emulate the
previous behaviour of the XendDomainInfo.info dictionary. However,
the new dictionary also exposes a set of attributes that implement
the Xen API VM configuration interface.

Example:

>>> cfg = XendConfig(cfg = dict_from_xc_domain_getinfo)
>>> cfg.name_label
Domain-0
>>> cfg['name']
Domain-0
>>> cfg.kernel_kernel
/boot/vmlinuz-xen
>>> cfg.kernel_initrd
/root/initrd
>>> cfg.kernel_args
root=/dev/sda1 ro
>>> cfg['image']
(linux
  (kernel /boot/vmlinuz-xen)
  (ramdisk /root/initrd)
  (root '/dev/sda1 ro'))
>>>  

Internally, XendConfig will make sure changes via the old 'dict'
interface get reflected, if possible, to the attribute store.

It does this by overriding __setitem__, __getitem__, __hasitem__,
__getattr__, __setattr__, __hasattr__.

What this means is that as code is moved from the SXP interface to
the Xen API interface, we can spot unported code by tracing calls
to  __getitem__ and __setitem__.

"""


LEGACY_CFG_TO_XENAPI_CFG = {
    'uuid': 'uuid',
    'vcpus': 'vcpus_number',
    'maxmem': 'memory_static_max',
    'memory': 'memory_static_min',
    'name': 'name_label',
    'on_poweroff': 'actions_after_shutdown',            
    'on_reboot': 'actions_after_reboot',
    'on_crash': 'actions_after_crash',
    'bootloader': 'boot_method',
    'kernel_kernel': 'kernel_kernel',
    'kernel_initrd': 'kernel_initrd',
    'kernel_args': 'kernel_args',
    }

XENAPI_CFG_CUSTOM_TRANSLATE = [
    'vifs',
    'vbds',
    ]

XENAPI_HVM_CFG = {
    'platform_std_vga': 'std-vga',
    'platform_serial' : 'serial',
    'platform_localtime': 'localtime',
    'platform_enable_audio': 'soundhw',
}    

XENAPI_UNSUPPORTED_IN_LEGACY_CFG = [
    'name_description',
    'user_version',
    'is_a_template',
    'memory_dynamic_min',
    'memory_dynamic_max',
    'memory_actual',
    'vcpus_policy',
    'vcpus_params',
    'vcpus_features_required',
    'vcpus_features_can_use',
    'vcpus_features_force_on',
    'vcpus_features_force_off',
    'actions_after_suspend',
    'tpm_instance',
    'tpm_backends',
    'bios_boot',
    'platform_std_vga',
    'platform_serial',
    'platform_localtime',
    'platform_clock_offset',
    'platform_enable_audio',
    'builder',
    'grub_cmdline',
    'pci_bus',
    'otherconfig'
    ]


# configuration params that need to be converted to ints
# since the XMLRPC transport for Xen API does not use
# 32 bit ints but string representation of 64 bit ints.
XENAPI_INT_CFG = [
    'user_version',
    'vcpus_number',
    'memory_static_min',
    'memory_static_max',
    'memory_dynamic_min',
    'memory_dynamic_max',
    'tpm_instance',
    'tpm_backend',
]    

##
## Xend Configuration Parameters
##


# All parameters of VMs that may be configured on-the-fly, or at start-up.
VM_CONFIG_ENTRIES = [
    ('name',        str),
    ('on_crash',    str),
    ('on_poweroff', str),
    ('on_reboot',   str),
    ('on_xend_start', str),
    ('on_xend_stop', str),        
]

# All entries written to the store.  This is VM_CONFIG_ENTRIES, plus those
# entries written to the store that cannot be reconfigured on-the-fly.
VM_STORE_ENTRIES = [
    ('uuid',       str),
    ('vcpus',      int),
    ('vcpu_avail', int),
    ('memory',     int),
    ('maxmem',     int),
    ('start_time', float),
]

VM_STORED_ENTRIES = VM_CONFIG_ENTRIES + VM_STORE_ENTRIES

# Configuration entries that we expect to round-trip -- be read from the
# config file or xc, written to save-files (i.e. through sxpr), and reused as
# config on restart or restore, all without munging.  Some configuration
# entries are munged for backwards compatibility reasons, or because they
# don't come out of xc in the same form as they are specified in the config
# file, so those are handled separately.

ROUNDTRIPPING_CONFIG_ENTRIES = [
    ('uuid',       str),
    ('vcpus',      int),
    ('vcpu_avail', int),
    ('cpu_weight', float),
    ('memory',     int),
    ('shadow_memory', int),
    ('maxmem',     int),
    ('bootloader', str),
    ('bootloader_args', str),
    ('features', str),
    ('localtime', int),
]
ROUNDTRIPPING_CONFIG_ENTRIES += VM_CONFIG_ENTRIES

## Static Configuration

STATIC_CONFIG_ENTRIES = [
    ('cpu',      int),
    ('cpus',     str),
    ('image',    list),
    ('security', list), # TODO: what if null?
]

DEPRECATED_ENTRIES = [
    ('restart', str),
]

##
## Config Choices
##

CONFIG_RESTART_MODES = ('restart', 'destroy', 'preserve', 'rename-restart')
CONFIG_OLD_DOM_STATES = ('running', 'blocked', 'paused', 'shutdown',
                         'crashed', 'dying')

##
## Defaults
##

def DEFAULT_VCPUS(info):
    if 'max_vcpu_id' in info: return int(info['max_vcpu_id']) + 1
    else: return 1

DEFAULT_CONFIGURATION = (
    ('uuid',         lambda info: uuid.createString()),
    ('name',         lambda info: 'Domain-' + info['uuid']),

    ('on_poweroff',  lambda info: 'destroy'),
    ('on_reboot',    lambda info: 'restart'),
    ('on_crash',     lambda info: 'restart'),
    ('features',     lambda info: ''),

    
    ('memory',       lambda info: 0),
    ('shadow_memory',lambda info: 0),
    ('maxmem',       lambda info: 0),
    ('bootloader',   lambda info: None),
    ('bootloader_args', lambda info: None),            
    ('backend',      lambda info: []),
    ('device',       lambda info: {}),
    ('image',        lambda info: None),
    ('security',     lambda info: []),
    ('on_xend_start', lambda info: 'ignore'),    
    ('on_xend_stop', lambda info: 'ignore'),

    ('cpus',         lambda info: []),
    ('cpu_weight',   lambda info: 1.0),
    ('vcpus',        lambda info: DEFAULT_VCPUS(info)),
    ('online_vcpus', lambda info: info['vcpus']),
    ('max_vcpu_id',  lambda info: info['vcpus']-1),
    ('vcpu_avail',   lambda info: (1<<info['vcpus'])-1),

    # New for Xen API
    ('kernel_kernel', lambda info: ''),
    ('kernel_initrd', lambda info: ''),
    ('kernel_args',   lambda info: ''),
    
)
    
class XendConfigError(VmError):
    def __str__(self):
        return 'Invalid Configuration: %s' % str(self.value)

##
## XendConfig SXP Config Compat
##

class XendSXPConfig:
    def get_domid(self):
        pass
    def get_handle(self):
        return self['uuid']
        

##
## XendConfig Class (an extended dictionary)
##

class XendConfig(dict):
    """ Generic Configuration Parser accepting SXP, Python or XML.
    This is a dictionary-like object that is populated.

    @ivar legacy: dictionary holding legacy xen domain info
    @ivar xenapi: dictionary holding xen api config info
    """

    def __init__(self, filename = None, fd = None,
                 sxp = None, xml = None, pycfg = None, xenapi_vm = None,
                 cfg = {}):
        """Constructor. Provide either the filename, fd or sxp.

        @keyword filename: filename of an SXP file
        @keyword fd: file descriptor of an SXP file
        @keyword sxp: a list of list of a parsed SXP
        @keyword xml: an XML tree object
        @keyword xenapi_vm: a struct passed from an XMLRPC call (Xen API)
        @keyword cfg: a dictionary of configuration (eg. from xc)
        """
        format = 'unknown'

        self.xenapi = {}

        if filename and not fd:
            fd = open(filename, 'r')

        if fd:
            format = self._detect_format(fd)
        
        if fd:
            if format == 'sxp':
                sxp = self._read_sxp(fd)
            elif format == 'python' and filename != None:
                pycfg = self._read_python(filename)
            elif format == 'python' and filename == None:
                raise XendConfigError("Python files must be passed as a "
                                      "filename rather than file descriptor.")
            elif format == 'xml':
                xml = self._read_xml(fd)
            else:
                raise XendConfigError("Unable to determine format of file")
                
        if sxp:
            cfg = self._populate_from_sxp(sxp)
        if xml:
            cfg = self._populate_from_xml(xml)
        if pycfg:
            cfg = self._populate_from_python_config(pycfg)
        if xenapi_vm:
            cfg = self._populate_from_xenapi_vm(xenapi_vm)
            
        if cfg:
            self.update(cfg)
            
        if xenapi_vm:
            self.xenapi.update(xenapi_vm)

        log.debug('XendConfig: %s' % str(self))
        self.validate()

    #
    # Xen API Attribute Access
    #

    def __getattr__(self, name):
        try:
            return dict.__getattr__(self, name)
        except AttributeError:
            try:
                return  self.__dict__['xenapi'][name]
            except KeyError:
                raise AttributeError("XendConfig Xen API has no attribute "
                                     "'%s'" % name)
            

    def __setattr__(self, name, value):
        try:
            return dict.__setattr__(self, name, value)
        except AttributeError:
            self.xenapi[name] = value
            #self.set_legacy_api_with_xen_api_value(name, value)

    def __delattr__(self, name):
        try:
            dict.__delattr__(self, name)
        except AttributeError:
            del self.xenapi[name]
        #self.del_legacy_api_with_xen_api_key(name)


    """
    #
    # Legacy API Attribute Access
    #

    def __getitem__(self, key):
        try:
            return self.legacy[key]
        except KeyError:
            raise AttributeError, "XendConfig Legacy has no attribute '%s'"\
                  % key

    def __setitem__(self, key, value):
        self.legacy[key] = value
        self.set_xen_api_with_legacy_api_value(key, value)

    def __delitem__(self, key):
        del self.legacy[key]
        self.del_xen_api_with_legacy_api_key(key)
    """
    

    def _detect_format(self, fd):
        """Detect the format of the configuration passed.

        @param fd: file descriptor of contents to detect
        @rtype: string, 'sxp', 'xml', 'python' or 'unknown'
        """
        format = 'unknown'
        
        fd.seek(0)
        for line in fd:
            stripped = line.strip()
            if stripped:
                if re.search(r'^\(', stripped): 
                    format = 'sxp'
                elif re.search(r'^\<?xml', stripped):
                    format = 'xml'
                else:
                    format = 'python'
                break

        fd.seek(0)
        return format

    def _read_sxp(self, fd):
        """ Read and parse SXP (from SXP to list of lists)

        @rtype: list of lists.
        """
        try:
            parsed = sxp.parse(fd)[0]
            return parsed
        except:
            raise
            return None

    def _read_xml(self, fd):
        """TODO: Read and parse XML (from XML to dict)

        @rtype: dict
        """
        raise NotImplementedError

    def _read_python(self, filename):
        """Read and parse python module that represents the config.

        @rtype: dict
        """
        cfg_globals = {}
        execfile(filename, cfg_globals, {})
        return cfg_globals

    def _populate_from_sxp(self, parsed):
        """ Populate this XendConfig using the parsed SXP.

        @rtype: dictionary
        """
        cfg = {}

        # First step is to convert deprecated options to
        # current equivalents.
        
        restart = sxp.child_value(parsed, 'restart')
        if restart:
            if restart == 'onreboot':
                cfg['on_poweroff'] = 'destroy'
                cfg['on_reboot'] = 'restart'
                cfg['on_crash'] = 'destroy'
            elif restart == 'always':
                for opt in ('on_poweroff', 'on_reboot', 'on_crash'):
                    cfg[opt] = 'restart'
            elif restart == 'never':
                for opt in ('on_poweroff', 'on_reboot', 'on_crash'):
                    cfg[opt] = 'never'                
            else:
                log.warn('Ignoring unrecognised value for deprecated option:'
                         'restart = \'%s\'', restart)

        # Only extract options we know about.
        all_params = VM_CONFIG_ENTRIES + ROUNDTRIPPING_CONFIG_ENTRIES + \
                     STATIC_CONFIG_ENTRIES
                     
        for key, typeconv in all_params:
            val = sxp.child_value(parsed, key)
            if val:
                try:
                    cfg[key] = typeconv(val)
                except ValueError:
                    pass

        # Manually extract other complex configuration
        # options.

        cfg['backend'] = []
        for c in sxp.children(parsed, 'backend'):
            cfg['backend'].append(sxp.name(sxp.child0(c)))

        cfg['device'] = {}
        for dev in sxp.children(parsed, 'device'):
            config = sxp.child0(dev)
            dev_type = sxp.name(config)
            dev_info = {}
            for opt, val in config[1:]:
                dev_info[opt] = val
            log.debug("XendConfig: reading device: %s" % dev_info)
            # create uuid if it doesn't
            dev_uuid = dev_info.get('uuid', uuid.createString())
            dev_info['uuid'] = dev_uuid
            cfg['device'][dev_uuid] = (dev_type, dev_info)
            
            #cfg['device'].append((sxp.name(config), config))


        # Extract missing data from configuration entries
        if 'image' in cfg:
            image_vcpus = sxp.child_value(cfg['image'], 'vcpus')
            if image_vcpus is not None:
                try:
                    if 'vcpus' not in cfg:
                        cfg['vcpus'] = int(image_vcpus)
                    elif cfg['vcpus'] != int(image_vcpus):
                        cfg['vcpus'] = int(image_vcpus)
                        log.warn('Overriding vcpus from %d to %d using image'
                                 'vcpus value.', cfg['vcpus'])
                except ValueError, e:
                    raise XendConfigError('integer expeceted: %s: %s' %
                                        str(cfg['image']), e)

        # Deprecated cpu configuration
        if 'cpu' in cfg:
            if 'cpus' in cfg:
                cfg['cpus'] = "%s,%s" % (str(cfg['cpu']), cfg['cpus'])
            else:
                cfg['cpus'] = str(cfg['cpu'])

        # convert 'cpus' string to list of ints
        # 'cpus' supports a list of ranges (0-3), seperated by
        # commas, and negation, (^1).  
        # Precedence is settled by  order of the string:
        #     "0-3,^1"   -> [0,2,3]
        #     "0-3,^1,1" -> [0,1,2,3]
        try:
            if 'cpus' in cfg:
                cpus = []
                for c in cfg['cpus'].split(','):
                    if c.find('-') != -1:             
                        (x, y) = c.split('-')
                        for i in range(int(x), int(y)+1):
                            cpus.append(int(i))
                    else:
                        # remove this element from the list 
                        if c[0] == '^':
                            cpus = [x for x in cpus if x != int(c[1:])]
                        else:
                            cpus.append(int(c))

                cfg['cpus'] = cpus
        except ValueError, e:
            raise XendConfigError('cpus = %s: %s' % (cfg['cpus'], e))

        # Parse image SXP outside of image.py
        # - used to be only done in image.py
        if 'image' in cfg:
            cfg['kernel_kernel'] = sxp.child_value(cfg['image'], 'kernel','')
            cfg['kernel_initrd'] = sxp.child_value(cfg['image'], 'ramdisk','')
            kernel_args = sxp.child_value(cfg['image'], 'args', '')

            # attempt to extract extra arguments from SXP config
            arg_ip = sxp.child_value(cfg['image'], 'ip')
            if arg_ip: kernel_args += ' ip=%s' % arg_ip
            arg_root = sxp.child_value(cfg['image'], 'root')
            if arg_root: kernel_args += ' root=%s' % arg_root
            
            cfg['kernel_args'] = kernel_args

        # TODO: get states
        old_state = sxp.child_value(parsed, 'state')
        if old_state:
            for i in range(len(CONFIG_OLD_DOM_STATES)):
                cfg[CONFIG_OLD_DOM_STATES[i]] = (old_state[i] != '-')

        # Xen API extra cfgs
        # ------------------
        cfg['vif_refs'] = []
        cfg['vbd_refs'] = []
        for dev_uuid, (dev_type, dev_info) in cfg['device'].items():
            if dev_type == 'vif':
                cfg['vif_refs'].append(dev_uuid)
            elif dev_type in ('vbd','tap'):
                cfg['vbd_refs'].append(dev_uuid)
                
        return cfg


    def _populate_from_xenapi_vm(self, xenapi_vm):
        cfg = {}

        for cfgkey, apikey in LEGACY_CFG_TO_XENAPI_CFG.items():
            try:
                if apikey in XENAPI_INT_CFG:
                    cfg[cfgkey] = int(xenapi_vm[apikey])
                else:
                    cfg[cfgkey] = xenapi_vm[apikey]                    
            except KeyError:
                pass

        # Reconstruct image SXP 
        # TODO: get rid of SXP altogether from here
        sxp_image = ['linux']
        if xenapi_vm['kernel_kernel']:
            sxp_image.append(['kernel', xenapi_vm['kernel_kernel']])
        if xenapi_vm['kernel_initrd']:
            sxp_image.append(['ramdisk', xenapi_vm['kernel_initrd']])
        if xenapi_vm['kernel_args']:
            sxp_image.append(['args', xenapi_vm['kernel_args']])

        cfg['image'] = prettyprintstring(sxp_image)

        # make sure device structures are there.
        if 'device' not in cfg:
            cfg['device'] = {}
        if 'vif_refs' not in cfg:
            cfg['vif_refs'] = []
        if 'vbd_refs' not in cfg:
            cfg['vbd_refs'] = []

        return cfg


    def _sync_xen_api_from_legacy_api(self):
        """ Sync all the attributes that is supported by the Xen API
        from the legacy API configuration.
        """
        for cfgkey, apikey in LEGACY_CFG_TO_XENAPI_CFG.items():        
            if cfgkey in self:
                self.xenapi[apikey] = self[cfgkey]

    def _sync_legacy_api_from_xen_api(self):
        for cfgkey, apikey in LEGACY_CFG_TO_XENAPI_CFG.items():
            if apikey in self.xenapi:
                self[cfgkey] = self.xenapi[apikey]


    def _populate_from_xml(self, parsed_xml):
        raise NotImplementedError

    def _populate_from_python_config(self, parsed_py):
        raise NotImplementedError
        

    def get_sxp(self, domain = None, ignore_devices = False, ignore = []):
        """ Get SXP representation of this config object.

        Incompat: removed store_mfn, console_mfn

        @keyword domain: (optional) XendDomainInfo to get extra information
                         from such as domid and running devices.
        @type    domain: XendDomainInfo
        @keyword ignore: (optional) list of 'keys' that we do not want
                         to export.
        @type    ignore: list of strings
        @rtype: list of list (SXP representation)
        """
        sxpr = ['domain']

        # TODO: domid/dom is the same thing but called differently
        #       depending if it is from xenstore or sxpr.

        if domain.getDomid() != None:
            sxpr.append(['domid', domain.getDomid()])

        for cfg, typefunc in ROUNDTRIPPING_CONFIG_ENTRIES:
            if cfg in self:
                if self[cfg] != None:
                    sxpr.append([cfg, self[cfg]])

        if 'image' in self:
            sxpr.append(['image', self['image']])
        if 'security' in self:
            sxpr.append(['security', self['security']])
        if 'shutdown_reason' in self:
            sxpr.append(['shutdown_reason', self['shutdown_reason']])
        if 'cpu_time' in self:
            sxpr.append(['cpu_time', self['cpu_time']/1e9])

        sxpr.append(['online_vcpus', self['online_vcpus']])

        if 'start_time' in self:
            uptime = time.time() - self['start_time']
            sxpr.append(['up_time', str(uptime)])
            sxpr.append(['start_time', str(self['start_time'])])

        sxpr.append(['on_xend_start', self.get('on_xend_start', 'ignore')])
        sxpr.append(['on_xend_stop', self.get('on_xend_stop', 'ignore')])

        sxpr.append(['status', domain.state])

        # Marshall devices (running or from configuration)
        if not ignore_devices:
            for cls in XendDevices.valid_devices():
                found = False
                
                # figure if there is a device that is running
                if domain:
                    try:
                        controller = domain.getDeviceController(cls)
                        configs = controller.configurations()
                        for config in configs:
                            sxpr.append(['device', config])
                            found = True
                    except:
                        log.exception("dumping sxp from device controllers")
                        pass
                        
                # if we didn't find that device, check the existing config
                # for a device in the same class
                if not found:
                    for dev_type, dev_info in self.all_devices_sxpr():
                        if dev_type == cls:
                            sxpr.append(['device', dev_info])

        return sxpr

    def validate(self):
        """ Validate the configuration and fill in missing configuration
        with defaults.
        """

        # Fill in default values
        for key, default_func in DEFAULT_CONFIGURATION:
            if key not in self:
                self[key] = default_func(self)

        # Basic sanity checks
        if 'image' in self and isinstance(self['image'], str):
            self['image'] = sxp.from_string(self['image'])
        if 'security' in self and isinstance(self['security'], str):
            self['security'] = sxp.from_string(self['security'])
        if self['memory'] == 0 and 'mem_kb' in self:
            self['memory'] = (self['mem_kb'] + 1023)/1024
        if self['memory'] <= 0:
            raise XendConfigError('Invalid memory size: %s' %
                                  str(self['memory']))

        self['maxmem'] = max(self['memory'], self['maxmem'])

        # Verify devices
        for d_uuid, (d_type, d_info) in self['device'].items():
            if d_type not in XendDevices.valid_devices():
                raise XendConfigError('Invalid device (%s)' % d_type)

        # Verify restart modes
        for event in ('on_poweroff', 'on_reboot', 'on_crash'):
            if self[event] not in CONFIG_RESTART_MODES:
                raise XendConfigError('Invalid restart event: %s = %s' % \
                                      (event, str(self[event])))

        # Verify that {vif,vbd}_refs are here too
        if 'vif_refs' not in self:
            self['vif_refs'] = []
        if 'vbd_refs' not in self:
            self['vbd_refs'] = []

    def device_add(self, dev_type, cfg_sxp = None, cfg_xenapi = None):
        if dev_type not in XendDevices.valid_devices():
            raise XendConfigError("XendConfig: %s not a valid device type" %
                            dev_type)

        if cfg_sxp == None and cfg_xenapi == None:
            raise XendConfigError("XendConfig: device_add requires some "
                                  "config.")

        if cfg_sxp:
            log.debug("XendConfig.device_add: %s" % str(cfg_sxp))
        if cfg_xenapi:
            log.debug("XendConfig.device_add: %s" % str(cfg_xenapi))

        if cfg_sxp:
            config = sxp.child0(cfg_sxp)
            dev_type = sxp.name(config)
            dev_info = {}

            try:
                for opt, val in config[1:]:
                    dev_info[opt] = val
            except ValueError:
                pass # SXP has no options for this device

            # create uuid if it doesn't exist
            dev_uuid = dev_info.get('uuid', uuid.createString())
            dev_info['uuid'] = dev_uuid
            self['device'][dev_uuid] = (dev_type, dev_info)
            if dev_type in ('vif', 'vbd'):
                self['%s_refs' % dev_type].append(dev_uuid)
            elif dev_type in ('tap',):
                self['vbd_refs'].append(dev_uuid)
            return dev_uuid

        if cfg_xenapi:
            dev_info = {}            
            if dev_type == 'vif':
                if cfg_xenapi.get('MAC'): # don't add if blank
                    dev_info['mac'] = cfg_xenapi.get('MAC')
                # vifname is the name on the guest, not dom0
                # TODO: we don't have the ability to find that out or
                #       change it from dom0
                #if cfg_xenapi.get('device'):  # don't add if blank
                #    dev_info['vifname'] = cfg_xenapi.get('device')
                if cfg_xenapi.get('type'):
                    dev_info['type'] = cfg_xenapi.get('type')
                
                dev_uuid = cfg_xenapi.get('uuid', uuid.createString())
                dev_info['uuid'] = dev_uuid
                self['device'][dev_uuid] = (dev_type, dev_info)
                self['vif_refs'].append(dev_uuid)
                return dev_uuid
            
            elif dev_type == 'vbd':
                dev_info['uname'] = cfg_xenapi.get('image', None)
                dev_info['dev'] = '%s:disk' % cfg_xenapi.get('device')
                if cfg_xenapi.get('mode') == 'RW':
                    dev_info['mode'] = 'w'
                else:
                    dev_info['mode'] = 'r'

                dev_uuid = cfg_xenapi.get('uuid', uuid.createString())
                dev_info['uuid'] = dev_uuid
                self['device'][dev_uuid] = (dev_type, dev_info)
                self['vbd_refs'].append(dev_uuid)                
                return dev_uuid
            
            elif dev_type == 'tap':
                dev_info['uname'] = 'tap:qcow:%s' % cfg_xenapi.get('image')
                dev_info['dev'] = '%s:disk' % cfg_xenapi.get('device')
                
                if cfg_xenapi.get('mode') == 'RW':
                    dev_info['mode'] = 'w'
                else:
                    dev_info['mode'] = 'r'

                dev_uuid = cfg_xenapi.get('uuid', uuid.createString())
                dev_info['uuid'] = dev_uuid
                self['device'][dev_uuid] = (dev_type, dev_info)
                self['vbd_refs'].append(dev_uuid)                
                return dev_uuid                
                
        return ''

    def device_sxpr(self, dev_uuid = None, dev_type = None, dev_info = None):
        """Get Device SXPR by either giving the device UUID or (type, config).

        @rtype: list of lists
        @return: device config sxpr
        """
        sxpr = []
        if dev_uuid != None and dev_uuid in self['device']:
            dev_type, dev_info = self['device']

        if dev_type == None or dev_info == None:
            raise XendConfigError("Required either UUID or device type and "
                                  "configuration dictionary.")
            
        sxpr.append(dev_type)
        config = [(opt, val) for opt, val in dev_info.items() \
                  if opt != 'type']
        sxpr += config

        return sxpr

    def all_devices_sxpr(self):
        sxprs = []
        for dev_type, dev_info in self['device'].values():
            sxpr =  self.device_sxpr(dev_type = dev_type, dev_info = dev_info)
            sxprs.append((dev_type, sxpr))
        return sxprs

                     
#
# debugging 
#

if __name__ == "__main__":
    pass
    
