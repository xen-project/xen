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
# Copyright (C) 2006-2007 XenSource Ltd
#============================================================================

import logging
import re
import time
import types

from xen.xend import sxp
from xen.xend import uuid
from xen.xend.XendError import VmError
from xen.xend.XendDevices import XendDevices
from xen.xend.PrettyPrint import prettyprintstring
from xen.xend.XendConstants import DOM_STATE_HALTED

log = logging.getLogger("xend.XendConfig")
log.setLevel(logging.DEBUG)


"""
XendConfig API

  XendConfig will try to mirror as closely the Xen API VM Struct
  with extra parameters for those options that are not supported.

"""

def reverse_dict(adict):
    """Return the reverse mapping of a dictionary."""
    return dict([(v, k) for k, v in adict.items()])

def bool0(v):
    return v != '0' and bool(v)

# Recursively copy a data struct, scrubbing out VNC passwords.
# Will scrub any dict entry with a key of 'vncpasswd' or any
# 2-element list whose first member is 'vncpasswd'. It will
# also scrub a string matching '(vncpasswd XYZ)'. Everything
# else is no-op passthrough
def scrub_password(data):
    if type(data) == dict or type(data) == XendConfig:
        scrubbed = {}
        for key in data.keys():
            if key == "vncpasswd":
                scrubbed[key] = "XXXXXXXX"
            else:
                scrubbed[key] = scrub_password(data[key])
        return scrubbed
    elif type(data) == list:
        if len(data) == 2 and type(data[0]) == str and data[0] == 'vncpasswd':
            return ['vncpasswd', 'XXXXXXXX']
        else:
            scrubbed = []
            for entry in data:
                scrubbed.append(scrub_password(entry))
            return scrubbed
    elif type(data) == tuple:
        scrubbed = []
        for entry in data:
            scrubbed.append(scrub_password(entry))
        return tuple(scrubbed)
    elif type(data) == str:
        return re.sub(r'\(vncpasswd\s+[^\)]+\)','(vncpasswd XXXXXX)', data)
    else:
        return data

#
# CPU fields:
#
# vcpus_number -- the maximum number of vcpus that this domain may ever have.
#                 aka XendDomainInfo.getVCpuCount().
# vcpus        -- the legacy configuration name for above.
# max_vcpu_id  -- vcpus_number - 1.  This is given to us by Xen.
#
# cpus         -- the list of pCPUs available to each vCPU.
#
#   vcpu_avail:  a bitmap telling the guest domain whether it may use each of
#                its VCPUs.  This is translated to
#                <dompath>/cpu/<id>/availability = {online,offline} for use
#                by the guest domain.
# online_vpcus -- the number of VCPUs currently up, as reported by Xen.  This
#                 is changed by changing vcpu_avail, and waiting for the
#                 domain to respond.
#


# Mapping from XendConfig configuration keys to the old
# legacy configuration keys that map directly.

XENAPI_CFG_TO_LEGACY_CFG = {
    'uuid': 'uuid',
    'vcpus_number': 'vcpus',
    'cpus': 'cpus',
    'memory_static_min': 'memory',
    'memory_static_max': 'maxmem',
    'name_label': 'name',
    'actions_after_shutdown': 'on_poweroff',
    'actions_after_reboot': 'on_reboot',
    'actions_after_crash': 'on_crash', 
    'PV_bootloader': 'bootloader',
    'PV_bootloader_args': 'bootloader_args',
}

LEGACY_CFG_TO_XENAPI_CFG = reverse_dict(XENAPI_CFG_TO_LEGACY_CFG)

# Platform configuration keys.
XENAPI_PLATFORM_CFG = [ 'acpi', 'apic', 'device_model', 'display', 'fda',
                        'fdb', 'keymap', 'isa', 'localtime', 'nographic',
                        'pae', 'serial', 'sdl', 'soundhw','stdvga', 'usb',
                        'usbdevice', 'vnc', 'vncconsole', 'vncdisplay',
                        'vnclisten', 'vncpasswd', 'vncunused', 'xauthority']

# List of XendConfig configuration keys that have no direct equivalent
# in the old world.

XENAPI_CFG_TYPES = {
    'uuid': str,
    'power_state': str,
    'name_label': str,
    'name_description': str,
    'user_version': str,
    'is_a_template': bool0,
    'resident_on': str,
    'memory_static_min': int,
    'memory_static_max': int,
    'memory_dynamic_min': int,
    'memory_dynamic_max': int,
    'memory_actual': int,
    'cpus': list,
    'vcpus_policy': str,
    'vcpus_params': dict,
    'vcpus_number': int,
    'actions_after_shutdown': str,
    'actions_after_reboot': str,
    'actions_after_crash': str,
    'PV_bootloader': str,
    'PV_kernel': str,
    'PV_ramdisk': str,
    'PV_args': str,
    'PV_bootloader_args': str,
    'HVM_boot_policy': str,
    'HVM_boot_params': dict,
    'PCI_bus': str,
    'platform': dict,
    'tools_version': dict,
    'other_config': dict,
}

# List of legacy configuration keys that have no equivalent in the
# Xen API, but are still stored in XendConfig.

LEGACY_UNSUPPORTED_BY_XENAPI_CFG = [
    # roundtripped (dynamic, unmodified)
    'shadow_memory',
    'security',
    'vcpu_avail',
    'cpu_weight',
    'cpu_cap',
    'features',
    # read/write
    'on_xend_start',
    'on_xend_stop',
    # read-only
    'domid',
    'start_time',
    'cpu_time',
    'online_vcpus',
    # write-once
    'cpu',
    'cpus',
]

LEGACY_CFG_TYPES = {
    'uuid':          str,
    'name':          str,
    'vcpus':         int,
    'vcpu_avail':    long,
    'memory':        int,
    'shadow_memory': int,
    'maxmem':        int,
    'start_time':    float,
    'cpu_cap':       int,
    'cpu_weight':    int,
    'cpu_time':      float,
    'features':      str,
    'localtime':     int,
    'name':          str,
    'on_poweroff':   str,
    'on_reboot':     str,
    'on_crash':      str,
    'on_xend_stop':  str,
    'on_xend_start': str,
    'online_vcpus':  int,
}

# Values that should be stored in xenstore's /vm/<uuid> that is used
# by Xend. Used in XendDomainInfo to restore running VM state from
# xenstore.
LEGACY_XENSTORE_VM_PARAMS = [
    'uuid',
    'name',
    'vcpus',
    'vcpu_avail',
    'memory',
    'shadow_memory',
    'maxmem',
    'start_time',
    'name',
    'on_poweroff',
    'on_crash',
    'on_reboot',
    'on_xend_start',
    'on_xend_stop',
]

DEFAULT_DM = '/usr/lib/xen/bin/qemu-dm'

##
## Config Choices
##

CONFIG_RESTART_MODES = ('restart', 'destroy', 'preserve', 'rename-restart')
CONFIG_OLD_DOM_STATES = ('running', 'blocked', 'paused', 'shutdown',
                         'crashed', 'dying')

class XendConfigError(VmError):
    def __str__(self):
        return 'Invalid Configuration: %s' % str(self.value)

##
## XendConfig Class (an extended dictionary)
##

class XendConfig(dict):
    """ The new Xend VM Configuration.

    Stores the configuration in xenapi compatible format but retains
    import and export functions for SXP.
    """
    def __init__(self, filename = None, sxp_obj = None,
                 xapi = None, dominfo = None):
        
        dict.__init__(self)
        self.update(self._defaults())

        if filename:
            try:
                sxp_obj = sxp.parse(open(filename,'r'))
                sxp_obj = sxp_obj[0]
            except IOError, e:
                raise XendConfigError("Unable to read file: %s" % filename)
        
        if sxp_obj:
            self._sxp_to_xapi(sxp_obj)
            self._sxp_to_xapi_unsupported(sxp_obj)
        elif xapi:
            self.update_with_xenapi_config(xapi)
        elif dominfo:
            # output from xc.domain_getinfo
            self._dominfo_to_xapi(dominfo)

        log.debug('XendConfig.init: %s' % scrub_password(self))

        # validators go here
        self.validate()

    """ In time, we should enable this type checking addition. It is great
        also for tracking bugs and unintended writes to XendDomainInfo.info
    def __setitem__(self, key, value):
        type_conv = XENAPI_CFG_TYPES.get(key)
        if callable(type_conv):
            try:
                dict.__setitem__(self, key, type_conv(value))
            except (ValueError, TypeError):
                raise XendConfigError("Wrong type for configuration value " +
                                      "%s. Expected %s" %
                                      (key, type_conv.__name__))
        else:
            dict.__setitem__(self, key, value)
    """

    def _defaults(self):
        defaults = {
            'name_label': 'Domain-Unnamed',
            'actions_after_shutdown': 'destroy',
            'actions_after_reboot': 'restart',
            'actions_after_crash': 'restart',
            'actions_after_suspend': '',
            'features': '',
            'PV_bootloader': '',
            'PV_kernel': '',
            'PV_ramdisk': '',
            'PV_args': '',
            'PV_bootloader_args': '',
            'HVM_boot_policy': '',
            'HVM_boot_params': {},
            'memory_static_min': 0,
            'memory_dynamic_min': 0,
            'shadow_memory': 0,
            'memory_static_max': 0,
            'memory_dynamic_max': 0,
            'memory_actual': 0,
            'devices': {},
            'security': None,
            'on_xend_start': 'ignore',
            'on_xend_stop': 'ignore',
            'cpus': [],
            'cpu_weight': 256,
            'cpu_cap': 0,
            'vcpus_number': 1,
            'vcpus_params': {},
            'console_refs': [],
            'vif_refs': [],
            'vbd_refs': [],
            'vtpm_refs': [],
            'other_config': {},
            'platform': {}
        }
        
        return defaults

    def _memory_sanity_check(self):
        if self['memory_static_min'] == 0:
            self['memory_static_min'] = self['memory_dynamic_min']

        # If the static max is not set, let's set it to dynamic max.
        # If the static max is smaller than static min, then fix it!
        self['memory_static_max'] = max(self['memory_static_max'],
                                        self['memory_dynamic_max'],
                                        self['memory_static_min'])

        for mem_type in ('memory_static_min', 'memory_static_max'):
            if self[mem_type] <= 0:
                raise XendConfigError('Memory value too low for %s: %d' %
                                      (mem_type, self[mem_type]))

    def _actions_sanity_check(self):
        for event in ['shutdown', 'reboot', 'crash']:
            if self['actions_after_' + event] not in CONFIG_RESTART_MODES:
                raise XendConfigError('Invalid event handling mode: ' +
                                      event)

    def _vcpus_sanity_check(self):
        if 'vcpus_number' in self and 'vcpu_avail' not in self:
            self['vcpu_avail'] = (1 << self['vcpus_number']) - 1

    def _uuid_sanity_check(self):
        """Make sure UUID is in proper string format with hyphens."""
        if 'uuid' not in self or not self['uuid']:
            self['uuid'] = uuid.createString()
        else:
            self['uuid'] = uuid.toString(uuid.fromString(self['uuid']))

    def _name_sanity_check(self):
        if 'name_label' not in self:
            self['name_label'] = 'Domain-' + self['uuid']

    def _platform_sanity_check(self):
        if self.is_hvm():
            if 'device_model' not in self['platform']:
                self['platform']['device_model'] = DEFAULT_DM

            # Compatibility hack, can go away soon.
            if 'soundhw' not in self['platform'] and \
               self['platform'].get('enable_audio'):
                self['platform']['soundhw'] = 'sb16'

    def validate(self):
        self._uuid_sanity_check()
        self._name_sanity_check()
        self._memory_sanity_check()
        self._actions_sanity_check()
        self._vcpus_sanity_check()
        self._platform_sanity_check()

    def _dominfo_to_xapi(self, dominfo):
        self['domid'] = dominfo['domid']
        self['online_vcpus'] = dominfo['online_vcpus']
        self['vcpus_number'] = dominfo['max_vcpu_id'] + 1
        self['memory_dynamic_min'] = (dominfo['mem_kb'] + 1023)/1024
        self['memory_dynamic_max'] = (dominfo['maxmem_kb'] + 1023)/1024
        self['cpu_time'] = dominfo['cpu_time']/1e9
        # TODO: i don't know what the security stuff expects here
        if dominfo.get('ssidref'):
            self['security'] = [['ssidref', dominfo['ssidref']]]
        self['shutdown_reason'] = dominfo['shutdown_reason']

        # parse state into Xen API states
        self['running'] = dominfo['running']
        self['crashed'] = dominfo['crashed']
        self['dying'] = dominfo['dying']
        self['shutdown'] = dominfo['shutdown']
        self['paused'] = dominfo['paused']
        self['blocked'] = dominfo['blocked']

        if 'name' in dominfo:
            self['name_label'] = dominfo['name']

        if 'handle' in dominfo:
            self['uuid'] = uuid.toString(dominfo['handle'])
            
    def _parse_sxp(self, sxp_cfg):
        """ Populate this XendConfig using the parsed SXP.

        @param sxp_cfg: Parsed SXP Configuration
        @type sxp_cfg: list of lists
        @rtype: dictionary
        @return: A dictionary containing the parsed options of the SXP.
        """
        cfg = {}

        for key, typ in XENAPI_CFG_TYPES.items():
            val = sxp.child_value(sxp_cfg, key)
            if val is not None:
                cfg[key] = typ(val)

        # Convert deprecated options to current equivalents.
        
        restart = sxp.child_value(sxp_cfg, 'restart')
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
        extract_keys = LEGACY_UNSUPPORTED_BY_XENAPI_CFG
        extract_keys += XENAPI_CFG_TO_LEGACY_CFG.values()
        
        for key in extract_keys:
            val = sxp.child_value(sxp_cfg, key)
            if val != None:
                try:
                    cfg[key] = LEGACY_CFG_TYPES[key](val)
                except KeyError:
                    cfg[key] = val
                except (TypeError, ValueError), e:
                    log.warn("Unable to parse key %s: %s: %s" %
                             (key, str(val), e))

        if 'platform' not in cfg:
            cfg['platform'] = {}
        localtime = sxp.child_value(sxp_cfg, 'localtime')
        if localtime is not None:
            cfg['platform']['localtime'] = localtime

        # Compatibility hack -- can go soon.
        for key in XENAPI_PLATFORM_CFG:
            val = sxp.child_value(sxp_cfg, "platform_" + key, None)
            if val is not None:
                self['platform'][key] = val

        # Compatibility hack -- can go soon.
        boot_order = sxp.child_value(sxp_cfg, 'HVM_boot')
        if boot_order:
            cfg['HVM_boot_policy'] = 'BIOS order'
            cfg['HVM_boot_params'] = { 'order' : boot_order }

        # Parsing the device SXP's. In most cases, the SXP looks
        # like this:
        #
        # [device, [vif, [mac, xx:xx:xx:xx:xx:xx], [ip 1.3.4.5]]]
        #
        # However, for PCI devices it looks like this:
        #
        # [device, [pci, [dev, [domain, 0], [bus, 0], [slot, 1]]]]
        #
        # It seems the reasoning for this difference is because
        # pciif.py needs all the PCI device configurations at
        # the same time when creating the devices.
        #
        # To further complicate matters, Xen 2.0 configuration format
        # uses the following for pci device configuration:
        #
        # [device, [pci, [domain, 0], [bus, 0], [dev, 1], [func, 2]]]
        #
        # Hence we deal with pci device configurations outside of
        # the regular device parsing.
        
        cfg['devices'] = {}
        for dev in sxp.children(sxp_cfg, 'device'):
            config = sxp.child0(dev)
            dev_type = sxp.name(config)
            dev_info = {}
            
            if dev_type == 'pci':
                pci_devs_uuid = sxp.child_value(config, 'uuid',
                                                uuid.createString())
                pci_devs = []
                for pci_dev in sxp.children(config, 'dev'):
                    pci_dev_info = {}
                    for opt_val in pci_dev[1:]:
                        try:
                            opt, val = opt_val
                            pci_dev_info[opt] = val
                        except TypeError:
                            pass
                    pci_devs.append(pci_dev_info)
                
                cfg['devices'][pci_devs_uuid] = (dev_type,
                                                 {'devs': pci_devs,
                                                  'uuid': pci_devs_uuid})
                
                log.debug("XendConfig: reading device: %s" % pci_devs)
            else:
                self.device_add(dev_type, cfg_sxp = config, target = cfg)
                log.debug("XendConfig: reading device: %s" % scrub_password(dev_info))

        # Extract missing data from configuration entries
        image_sxp = sxp.child_value(sxp_cfg, 'image', [])
        if image_sxp:
            image_vcpus = sxp.child_value(image_sxp, 'vcpus')
            if image_vcpus != None:
                try:
                    if 'vcpus_number' not in cfg:
                        cfg['vcpus_number'] = int(image_vcpus)
                    elif cfg['vcpus_number'] != int(image_vcpus):
                        cfg['vcpus_number'] = int(image_vcpus)
                        log.warn('Overriding vcpus from %d to %d using image'
                                 'vcpus value.', cfg['vcpus_number'])
                except ValueError, e:
                    raise XendConfigError('integer expeceted: %s: %s' %
                                          image_sxp, e)

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
            if 'cpus' in cfg and type(cfg['cpus']) != list:
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

        if 'security' in cfg and isinstance(cfg['security'], str):
            cfg['security'] = sxp.from_string(cfg['security'])

        old_state = sxp.child_value(sxp_cfg, 'state')
        if old_state:
            for i in range(len(CONFIG_OLD_DOM_STATES)):
                cfg[CONFIG_OLD_DOM_STATES[i]] = int(old_state[i] != '-')

        return cfg
    

    def _sxp_to_xapi(self, sxp_cfg):
        """Read in an SXP Configuration object and
        populate at much of the Xen API with valid values.
        """
        log.debug('_sxp_to_xapi(%s)' % scrub_password(sxp_cfg))

        cfg = self._parse_sxp(sxp_cfg)

        for key, typ in XENAPI_CFG_TYPES.items():
            val = cfg.get(key)
            if val is not None:
                self[key] = typ(val)

        # Convert parameters that can be directly mapped from
        # the Legacy Config to Xen API Config
        
        for apikey, cfgkey in XENAPI_CFG_TO_LEGACY_CFG.items():
            try:
                type_conv = XENAPI_CFG_TYPES.get(apikey)
                if callable(type_conv):
                    self[apikey] = type_conv(cfg[cfgkey])
                else:
                    log.warn("Unconverted key: " + apikey)
                    self[apikey] = cfg[cfgkey]
            except KeyError:
                pass

        def update_with(n, o):
            if not self.get(n):
                self[n] = cfg.get(o, '')

        update_with('PV_bootloader',      'bootloader')
        update_with('PV_bootloader_args', 'bootloader_args')

        image_sxp = sxp.child_value(sxp_cfg, 'image', [])
        if image_sxp:
            self.update_with_image_sxp(image_sxp)

        # Convert Legacy HVM parameters to Xen API configuration
        for key in XENAPI_PLATFORM_CFG:
            if key in cfg:
                self['platform'][key] = cfg[key]

        # make sure a sane maximum is set
        if self['memory_static_max'] <= 0:
            self['memory_static_max'] = self['memory_static_min']
            
        self['memory_dynamic_max'] = self['memory_static_max']
        self['memory_dynamic_min'] = self['memory_static_min']

        # set device references in the configuration
        self['devices'] = cfg.get('devices', {})
        self['console_refs'] = cfg.get('console_refs', [])
        self['vif_refs'] = cfg.get('vif_refs', [])
        self['vbd_refs'] = cfg.get('vbd_refs', [])
        self['vtpm_refs'] = cfg.get('vtpm_refs', [])

        # coalesce hvm vnc frame buffer with vfb config
        if self.is_hvm() and self['platform'].get('vnc', 0):
            # add vfb device if it isn't there already
            has_rfb = False
            for console_uuid in self['console_refs']:
                if self['devices'][console_uuid][1].get('protocol') == 'rfb':
                    has_rfb = True
                    break
                if self['devices'][console_uuid][0] == 'vfb':
                    has_rfb = True
                    break

            if not has_rfb:
                dev_config = ['vfb']
                # copy VNC related params from platform config to vfb dev conf
                for key in ['vncpasswd', 'vncunused', 'vncdisplay',
                            'vnclisten']:
                    if key in self['platform']:
                        dev_config.append([key, self['platform'][key]])

                self.device_add('vfb', cfg_sxp = dev_config)


    def _sxp_to_xapi_unsupported(self, sxp_cfg):
        """Read in an SXP configuration object and populate
        values are that not related directly supported in
        the Xen API.
        """

        log.debug('_sxp_to_xapi_unsupported(%s)' % scrub_password(sxp_cfg))

        # Parse and convert parameters used to configure
        # the image (as well as HVM images)
        image_sxp = sxp.child_value(sxp_cfg, 'image', [])
        if image_sxp:
            image_type = sxp.name(image_sxp)
            if image_type != 'hvm' and image_type != 'linux':
                self['platform']['image_type'] = image_type
            
            for key in XENAPI_PLATFORM_CFG:
                val = sxp.child_value(image_sxp, key, None)
                if val is not None:
                    self['platform'][key] = val
            
            notes = sxp.children(image_sxp, 'notes')
            if notes:
                self['notes'] = self.notes_from_sxp(notes[0])

            self._hvm_boot_params_from_sxp(image_sxp)

        # extract backend value
                    
        backend = []
        for c in sxp.children(sxp_cfg, 'backend'):
            backend.append(sxp.name(sxp.child0(c)))
        if backend:
            self['backend'] = backend

        # Parse and convert other Non Xen API parameters.
        def _set_cfg_if_exists(sxp_arg):
            val = sxp.child_value(sxp_cfg, sxp_arg)
            if val != None:
                if LEGACY_CFG_TYPES.get(sxp_arg):
                    self[sxp_arg] = LEGACY_CFG_TYPES[sxp_arg](val)
                else:
                    self[sxp_arg] = val

        _set_cfg_if_exists('shadow_memory')
        _set_cfg_if_exists('security')
        _set_cfg_if_exists('features')
        _set_cfg_if_exists('on_xend_stop')
        _set_cfg_if_exists('on_xend_start')
        _set_cfg_if_exists('vcpu_avail')
        _set_cfg_if_exists('cpu_weight')
        _set_cfg_if_exists('cpu_cap')
        
        # Parse and store runtime configuration 
        _set_cfg_if_exists('start_time')
        _set_cfg_if_exists('cpu_time')
        _set_cfg_if_exists('shutdown_reason')
        _set_cfg_if_exists('up_time')
        _set_cfg_if_exists('status') # TODO, deprecated  

    def _get_old_state_string(self):
        """Returns the old xm state string.
        @rtype: string
        @return: old state string
        """
        state_string = ''
        for state_name in CONFIG_OLD_DOM_STATES:
            on_off = self.get(state_name, 0)
            if on_off:
                state_string += state_name[0]
            else:
                state_string += '-'

        return state_string


    def update_config(self, dominfo):
        """Update configuration with the output from xc.domain_getinfo().

        @param dominfo: Domain information via xc.domain_getinfo()
        @type dominfo: dict
        """
        self._dominfo_to_xapi(dominfo)
        self.validate()

    def update_with_xenapi_config(self, xapi):
        """Update configuration with a Xen API VM struct

        @param xapi: Xen API VM Struct
        @type xapi: dict
        """

        log.debug('update_with_xenapi_config: %s' % scrub_password(xapi))

        for key, val in xapi.items():
            type_conv = XENAPI_CFG_TYPES.get(key)
            if type_conv is None:
                key = key.lower()
                type_conv = XENAPI_CFG_TYPES.get(key)
            if callable(type_conv):
                self[key] = type_conv(val)
            else:
                self[key] = val

    def to_sxp(self, domain = None, ignore_devices = False, ignore = [],
               legacy_only = True):
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

        if domain.getDomid() is not None:
            sxpr.append(['domid', domain.getDomid()])

        if not legacy_only:
            for name, typ in XENAPI_CFG_TYPES.items():
                if name in self and self[name] not in (None, []):
                    if typ == dict:
                        s = self[name].items()
                    else:
                        s = str(self[name])
                    sxpr.append([name, s])

        for xenapi, legacy in XENAPI_CFG_TO_LEGACY_CFG.items():
            if self.has_key(xenapi) and self[xenapi] not in (None, []):
                if type(self[xenapi]) == bool:
                    # convert booleans to ints before making an sxp item
                    sxpr.append([legacy, int(self[xenapi])])
                else:
                    sxpr.append([legacy, self[xenapi]])

        for legacy in LEGACY_UNSUPPORTED_BY_XENAPI_CFG:
            if legacy in ('domid', 'uuid'): # skip these
                continue
            if self.has_key(legacy) and self[legacy] not in (None, []):
                sxpr.append([legacy, self[legacy]])

        sxpr.append(['image', self.image_sxpr()])
        sxpr.append(['status', domain.state])
        sxpr.append(['memory_dynamic_min',  self.get('memory_dynamic_min')])
        sxpr.append(['memory_dynamic_max',  self.get('memory_dynamic_max')])

        if domain.getDomid() is not None:
            sxpr.append(['state', self._get_old_state_string()])

        if domain:
            if domain.store_mfn:
                sxpr.append(['store_mfn', domain.store_mfn])
            if domain.console_mfn:
                sxpr.append(['console_mfn', domain.console_mfn])


        # Marshall devices (running or from configuration)
        if not ignore_devices:
            for cls in XendDevices.valid_devices():
                found = False
                
                # figure if there is a dev controller is valid and running
                if domain and domain.getDomid() != None:
                    try:
                        controller = domain.getDeviceController(cls)
                        configs = controller.configurations()
                        for config in configs:
                            if sxp.name(config) in ('vbd', 'tap'):
                                # The bootable flag is never written to the
                                # store as part of the device config.
                                dev_uuid = sxp.child_value(config, 'uuid')
                                dev_type, dev_cfg = self['devices'][dev_uuid]
                                is_bootable = dev_cfg.get('bootable', 0)
                                config.append(['bootable', int(is_bootable)])

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
    
    def device_add(self, dev_type, cfg_sxp = None, cfg_xenapi = None,
                   target = None):
        """Add a device configuration in SXP format or XenAPI struct format.

        For SXP, it could be either:

        [device, [vbd, [uname ...]]

        or:

        [vbd, [uname ..]]

        @type cfg_sxp: list of lists (parsed sxp object)
        @param cfg_sxp: SXP configuration object
        @type cfg_xenapi: dict
        @param cfg_xenapi: A device configuration from Xen API (eg. vbd,vif)
        @param target: write device information to
        @type target: None or a dictionary
        @rtype: string
        @return: Assigned UUID of the device.
        """
        if target == None:
            target = self
        
        if dev_type not in XendDevices.valid_devices():
            raise XendConfigError("XendConfig: %s not a valid device type" %
                            dev_type)

        if cfg_sxp == None and cfg_xenapi == None:
            raise XendConfigError("XendConfig: device_add requires some "
                                  "config.")

        #if cfg_sxp:
        #    log.debug("XendConfig.device_add: %s" % str(cfg_sxp))
        #if cfg_xenapi:
        #    log.debug("XendConfig.device_add: %s" % str(cfg_xenapi))

        if cfg_sxp:
            if sxp.child0(cfg_sxp) == 'device':
                config = sxp.child0(cfg_sxp)
            else:
                config = cfg_sxp

            dev_type = sxp.name(config)
            dev_info = {}

            for opt_val in config[1:]:
                try:
                    opt, val = opt_val
                    dev_info[opt] = val
                except (TypeError, ValueError): # unpack error
                    pass

            if dev_type == 'vbd':
                dev_info['bootable'] = 0
                if dev_info.get('dev', '').startswith('ioemu:'):
                    dev_info['driver'] = 'ioemu'
                else:
                    dev_info['driver'] = 'paravirtualised'

            # create uuid if it doesn't exist
            dev_uuid = dev_info.get('uuid', None)
            if not dev_uuid:
                dev_uuid = uuid.createString()
            dev_info['uuid'] = dev_uuid

            # store dev references by uuid for certain device types
            target['devices'][dev_uuid] = (dev_type, dev_info)
            if dev_type in ('vif', 'vbd', 'vtpm'):
                param = '%s_refs' % dev_type
                if param not in target:
                    target[param] = []
                if dev_uuid not in target[param]:
                    if dev_type == 'vbd' and not target[param]:
                        # Compat hack -- this is the first disk, so mark it
                        # bootable.
                        dev_info['bootable'] = 1
                    target[param].append(dev_uuid)
            elif dev_type == 'tap':
                if 'vbd_refs' not in target:
                    target['vbd_refs'] = []
                if dev_uuid not in target['vbd_refs']:
                    if not target['vbd_refs']:
                        # Compat hack -- this is the first disk, so mark it
                        # bootable.
                        dev_info['bootable'] = 1
                    target['vbd_refs'].append(dev_uuid)
                    
            elif dev_type == 'vfb':
                # Populate other config with aux data that is associated
                # with vfb

                other_config = {}
                for key in ['vncunused', 'vncdisplay', 'vnclisten',
                            'vncpasswd', 'type', 'display', 'xauthority',
                            'keymap']:
                    if key in dev_info:
                        other_config[key] = dev_info[key]
                target['devices'][dev_uuid][1]['other_config'] =  other_config
                
                
                if 'console_refs' not in target:
                    target['console_refs'] = []

                # Treat VFB devices as console devices so they are found
                # through Xen API
                if dev_uuid not in target['console_refs']:
                    target['console_refs'].append(dev_uuid)

            elif dev_type == 'console':
                if 'console_refs' not in target:
                    target['console_refs'] = []
                if dev_uuid not in target['console_refs']:
                    target['console_refs'].append(dev_uuid)
                    
            return dev_uuid

        if cfg_xenapi:
            dev_info = {}
            dev_uuid = ''
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
                if cfg_xenapi.get('name'):
                    dev_info['name'] = cfg_xenapi.get('name')
                
                dev_uuid = cfg_xenapi.get('uuid', None)
                if not dev_uuid:
                    dev_uuid = uuid.createString()
                dev_info['uuid'] = dev_uuid
                target['devices'][dev_uuid] = (dev_type, dev_info)
                target['vif_refs'].append(dev_uuid)
            
            elif dev_type in ('vbd', 'tap'):
                dev_info['type'] = cfg_xenapi.get('type', 'Disk')
                if dev_info['type'] == 'CD':
                    old_vbd_type = 'cdrom'
                else:
                    old_vbd_type = 'disk'
                    
                dev_info['uname'] = cfg_xenapi.get('image', '')
                dev_info['dev'] = '%s:%s' % (cfg_xenapi.get('device'),
                                             old_vbd_type)
                dev_info['bootable'] = int(cfg_xenapi.get('bootable', 0))
                dev_info['driver'] = cfg_xenapi.get('driver', '')
                dev_info['VDI'] = cfg_xenapi.get('VDI', '')
                    
                if cfg_xenapi.get('mode') == 'RW':
                    dev_info['mode'] = 'w'
                else:
                    dev_info['mode'] = 'r'

                dev_uuid = cfg_xenapi.get('uuid', None)
                if not dev_uuid:
                    dev_uuid = uuid.createString()
                dev_info['uuid'] = dev_uuid
                target['devices'][dev_uuid] = (dev_type, dev_info)
                target['vbd_refs'].append(dev_uuid)                

            elif dev_type == 'vtpm':
                if cfg_xenapi.get('type'):
                    dev_info['type'] = cfg_xenapi.get('type')

                dev_uuid = cfg_xenapi.get('uuid', None)
                if not dev_uuid:
                    dev_uuid = uuid.createString()
                dev_info['uuid'] = dev_uuid
                target['devices'][dev_uuid] = (dev_type, dev_info)
                target['vtpm_refs'].append(dev_uuid)

            elif dev_type == 'console':
                dev_uuid = cfg_xenapi.get('uuid', None)
                if not dev_uuid:
                    dev_uuid = uuid.createString()
                dev_info['uuid'] = dev_uuid
                dev_info['protocol'] = cfg_xenapi.get('protocol', 'rfb')
                dev_info['other_config'] = cfg_xenapi.get('other_config', {})
                if dev_info['protocol'] == 'rfb':
                    # collapse other config into devinfo for things
                    # such as vncpasswd, vncunused, etc.                    
                    dev_info.update(cfg_xenapi.get('other_config', {}))
                    dev_info['type'] = 'vnc'                        
                    target['devices'][dev_uuid] = ('vfb', dev_info)
                    target['console_refs'].append(dev_uuid)

                    # Finally, if we are a pvfb, we need to make a vkbd
                    # as well that is not really exposed to Xen API
                    vkbd_uuid = uuid.createString()
                    target['devices'][vkbd_uuid] = ('vkbd', {})
                    
                elif dev_info['protocol'] == 'vt100':
                    # if someone tries to create a VT100 console
                    # via the Xen API, we'll have to ignore it
                    # because we create one automatically in
                    # XendDomainInfo._update_consoles
                    raise XendConfigError('Creating vt100 consoles via '
                                          'Xen API is unsupported')

            return dev_uuid

        # no valid device to add
        return ''

    def phantom_device_add(self, dev_type, cfg_xenapi = None,
                   target = None):
        """Add a phantom tap device configuration in XenAPI struct format.
        """

        if target == None:
            target = self
        
        if dev_type not in XendDevices.valid_devices() and \
           dev_type not in XendDevices.pseudo_devices():        
            raise XendConfigError("XendConfig: %s not a valid device type" %
                            dev_type)

        if cfg_xenapi == None:
            raise XendConfigError("XendConfig: device_add requires some "
                                  "config.")

        if cfg_xenapi:
            log.debug("XendConfig.phantom_device_add: %s" % str(cfg_xenapi))
 
        if cfg_xenapi:
            dev_info = {}            
            if dev_type in ('vbd', 'tap'):
                if dev_type == 'vbd':
                    dev_info['uname'] = cfg_xenapi.get('image', '')
                    dev_info['dev'] = '%s:disk' % cfg_xenapi.get('device')
                elif dev_type == 'tap':
                    if cfg_xenapi.get('image').find('tap:') == -1:
                        dev_info['uname'] = 'tap:qcow:%s' % cfg_xenapi.get('image')
                    dev_info['dev'] =  '/dev/%s' % cfg_xenapi.get('device')
                    dev_info['uname'] = cfg_xenapi.get('image')
                dev_info['mode'] = cfg_xenapi.get('mode')
                dev_info['backend'] = '0'
                dev_uuid = cfg_xenapi.get('uuid', uuid.createString())
                dev_info['uuid'] = dev_uuid
                self['devices'][dev_uuid] = (dev_type, dev_info)
                self['vbd_refs'].append(dev_uuid)
                return dev_uuid

        return ''

    def console_add(self, protocol, location, other_config = {}):
        dev_uuid = uuid.createString()
        if protocol == 'vt100':
            dev_info = {
                'uuid': dev_uuid,
                'protocol': protocol,
                'location': location,
                'other_config': other_config,
            }

            if 'devices' not in self:
                self['devices'] = {}
            
            self['devices'][dev_uuid] = ('console', dev_info)
            self['console_refs'].append(dev_uuid)
            return dev_info

        return {}

    def console_update(self, console_uuid, key, value):
        for dev_uuid, (dev_type, dev_info) in self['devices'].items():
            if dev_uuid == console_uuid:
                dev_info[key] = value
                break

    def console_get_all(self, protocol):
        if protocol == 'vt100':
            consoles = [dinfo for dtype, dinfo in self['devices'].values()
                        if dtype == 'console']
            return [c for c in consoles if c.get('protocol') == protocol]

        elif protocol == 'rfb':
            vfbs = [dinfo for dtype, dinfo in self['devices'].values()
                   if dtype == 'vfb']

            # move all non-console key values to other_config before
            # returning console config
            valid_keys = ['uuid', 'location']
            for vfb in vfbs:
                other_config = {}
                for key, val in vfb.items():
                    if key not in valid_keys:
                        other_config[key] = vfb[key]
                    del vfb[key]
                vfb['other_config'] = other_config
                vfb['protocol'] = 'rfb'
                        
            return vfbs

        else:
            return []

    def device_update(self, dev_uuid, cfg_sxp = [], cfg_xenapi = {}):
        """Update an existing device with the new configuration.

        @rtype: boolean
        @return: Returns True if succesfully found and updated a device conf
        """
        if dev_uuid in self['devices'] and cfg_sxp:
            if sxp.child0(cfg_sxp) == 'device':            
                config = sxp.child0(cfg_sxp)
            else:
                config = cfg_sxp

            dev_type, dev_info = self['devices'][dev_uuid]
            for opt_val in config[1:]:
                try:
                    opt, val = opt_val
                    dev_info[opt] = val
                except (TypeError, ValueError):
                    pass # no value for this config option

            self['devices'][dev_uuid] = (dev_type, dev_info)
            return True
        
        elif dev_uuid in self['devices'] and cfg_xenapi:
            dev_type, dev_info = self['devices'][dev_uuid]
            for key, val in cfg_xenapi.items():
                dev_info[key] = val
            self['devices'][dev_uuid] = (dev_type, dev_info)

        return False


    def device_sxpr(self, dev_uuid = None, dev_type = None, dev_info = None):
        """Get Device SXPR by either giving the device UUID or (type, config).

        @rtype: list of lists
        @return: device config sxpr
        """
        sxpr = []
        if dev_uuid != None and dev_uuid in self['devices']:
            dev_type, dev_info = self['devices'][dev_uuid]

        if dev_type == None or dev_info == None:
            raise XendConfigError("Required either UUID or device type and "
                                  "configuration dictionary.")
            
        sxpr.append(dev_type)
        if dev_type in ('console', 'vfb'):
            config = [(opt, val) for opt, val in dev_info.items()
                      if opt != 'other_config']
        else:
            config = [(opt, val) for opt, val in dev_info.items()]
            
        sxpr += config

        return sxpr

    def ordered_device_refs(self):
        result = (self['console_refs'] +
                  self['vbd_refs'] +
                  self['vif_refs'] +
                  self['vtpm_refs'])
        result.extend([u for u in self['devices'].keys() if u not in result])
        return result

    def all_devices_sxpr(self):
        """Returns the SXPR for all devices in the current configuration."""
        sxprs = []
        pci_devs = []

        if 'devices' not in self:
            return sxprs
        
        ordered_refs = self.ordered_device_refs()
        for dev_uuid in ordered_refs:
            dev_type, dev_info = self['devices'][dev_uuid]
            if dev_type == 'pci': # special case for pci devices
                sxpr = [['uuid', dev_info['uuid']]]
                for pci_dev_info in dev_info['devs']:
                    pci_dev_sxpr = ['dev']
                    for opt, val in pci_dev_info.items():
                        pci_dev_sxpr.append([opt, val])
                    sxpr.append(pci_dev_sxpr)
                sxprs.append((dev_type, sxpr))
            else:
                sxpr = self.device_sxpr(dev_type = dev_type,
                                        dev_info = dev_info)
                sxprs.append((dev_type, sxpr))

        return sxprs

    def image_sxpr(self):
        """Returns a backwards compatible image SXP expression that is
        used in xenstore's /vm/<uuid>/image value and xm list."""
        image = [self.image_type()]
        if self.has_key('PV_kernel'):
            image.append(['kernel', self['PV_kernel']])
        if self.has_key('PV_ramdisk') and self['PV_ramdisk']:
            image.append(['ramdisk', self['PV_ramdisk']])
        if self.has_key('PV_args') and self['PV_args']:
            image.append(['args', self['PV_args']])

        for key in XENAPI_PLATFORM_CFG:
            if key in self['platform']:
                image.append([key, self['platform'][key]])

        if 'notes' in self:
            image.append(self.notes_sxp(self['notes']))

        return image

    def update_with_image_sxp(self, image_sxp, bootloader = False):
        # Convert Legacy "image" config to Xen API PV_*
        # configuration
        log.debug("update_with_image_sxp(%s)" % scrub_password(image_sxp))

        # user-specified args must come last: previous releases did this and
        # some domU kernels rely upon the ordering.
        kernel_args = sxp.child_value(image_sxp, 'args', '')

        # attempt to extract extra arguments from SXP config
        arg_ip = sxp.child_value(image_sxp, 'ip')
        if arg_ip and not re.search(r'ip=[^ ]+', kernel_args):
            kernel_args = 'ip=%s ' % arg_ip + kernel_args
        arg_root = sxp.child_value(image_sxp, 'root')
        if arg_root and not re.search(r'root=', kernel_args):
            kernel_args = 'root=%s ' % arg_root + kernel_args

        if bootloader:
            self['_temp_using_bootloader'] = '1'
            self['_temp_kernel'] = sxp.child_value(image_sxp, 'kernel','')
            self['_temp_ramdisk'] = sxp.child_value(image_sxp, 'ramdisk','')
            self['_temp_args'] = kernel_args
        else:
            self['PV_kernel'] = sxp.child_value(image_sxp, 'kernel','')
            self['PV_ramdisk'] = sxp.child_value(image_sxp, 'ramdisk','')
            self['PV_args'] = kernel_args

        for key in XENAPI_PLATFORM_CFG:
            val = sxp.child_value(image_sxp, key, None)
            if val is not None:
                self['platform'][key] = val

        notes = sxp.children(image_sxp, 'notes')
        if notes:
            self['notes'] = self.notes_from_sxp(notes[0])

        self._hvm_boot_params_from_sxp(image_sxp)

    def set_notes(self, notes):
        'Add parsed elfnotes to image'
        self['notes'] = notes

    def get_notes(self):
        try:
            return self['notes'] or {}
        except KeyError:
            return {}

    def notes_from_sxp(self, nsxp):
        notes = {}
        for note in sxp.children(nsxp):
            notes[note[0]] = note[1]
        return notes

    def notes_sxp(self, notes):
        nsxp = ['notes']
        for k, v in notes.iteritems():
            nsxp.append([k, str(v)])
        return nsxp
        
    def _hvm_boot_params_from_sxp(self, image_sxp):
        boot = sxp.child_value(image_sxp, 'boot', None)
        if boot is not None:
            self['HVM_boot_policy'] = 'BIOS order'
            self['HVM_boot_params'] = { 'order' : boot }

    def is_hvm(self):
        return self['HVM_boot_policy'] != ''

    def image_type(self):
        stored_type = self['platform'].get('image_type')
        return stored_type or (self.is_hvm() and 'hvm' or 'linux')
