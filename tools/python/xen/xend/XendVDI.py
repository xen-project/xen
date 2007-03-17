#!/usr/bin/python
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
# Copyright (C) 2006 XenSource Ltd.
#============================================================================
#
# Representation of a Xen API VDI
#

import os

from xen.util.xmlrpclib2 import stringify
from xmlrpclib import dumps, loads

KB = 1024
MB = 1024 * 1024

class AutoSaveObject(object):
    
    def __init__(self):
        self.cfg_path = None
        self.auto_save = True
        object

    def save_config(self, cfg_file = None):
        raise NotImplementedError()
    
    def __setattr__(self, name, value):
        """A very simple way of making sure all attribute changes are
        flushed to disk.
        """
        object.__setattr__(self, name, value)
        if name != 'auto_save' and getattr(self, 'auto_save', False):
            self.save_config()

class XendVDI(AutoSaveObject):
    """Generic Xen API compatible VDI representation.

    @cvar SAVED_CFG: list of configuration attributes to save.
    @cvar SAVED_CFG_INT: list of configurations that should be ints.
    """
    
    SAVED_CFG = ['name_label',
                 'name_description',
                 'virtual_size',
                 'physical_utilisation',
                 'sharable',
                 'read_only']

    SAVED_CFG_INT = ['sector_size', 'virtual_size', 'physical_utilisation']
    
    def __init__(self, uuid, sr_uuid):
        self.uuid = uuid
        self.sr_uuid = sr_uuid
        self.name_label = ""
        self.name_description = ""
        self.virtual_size = 0
        self.physical_utilisation = 0
        self.sharable = False
        self.read_only = False
        self.type = "system"
        self.other_config = {}

    def load_config_dict(self, cfg):
        """Loads configuration into the object from a dict.

        @param cfg: configuration dict
        @type  cfg: dict
        """
        self.auto_save = False
        for key in self.SAVED_CFG:
            if key in cfg:
                if key in self.SAVED_CFG_INT:
                    setattr(self, key, int(cfg[key]))
                else:
                    setattr(self, key, cfg[key])
        self.auto_save = True

    def load_config(self, cfg_path):
        """Loads configuration from an XMLRPC parameter format.

        @param cfg_path: configuration file path
        @type  cfg_path: type
        @rtype: bool
        @return: Successful or not.
        """
        try:
            cfg, _ = loads(open(cfg_path).read())
            cfg = cfg[0]
            self.load_config_dict(cfg)
            self.cfg_path = cfg_path
        except IOError, e:
            return False
        
        return True

    def save_config(self, cfg_path = None):
        """Saves configuration at give path in XMLRPC parameter format.

        If cfg_path is not give, it defaults to the where the VDI
        configuration as loaded if it load_config was called.

        @keyword cfg_path: optional configuration file path
        @rtype: bool
        @return: Successful or not.
        """
        try:
            if not cfg_path and not self.cfg_path:
                return False

            if not cfg_path:
                cfg_path = self.cfg_path
                
            cfg = {}
            for key in self.SAVED_CFG:
                try:
                    cfg[key] = getattr(self, key)
                except AttributeError:
                    pass
            open(cfg_path, 'w').write(dumps((stringify(cfg),),
                                            allow_none = True))
        except IOError, e:
            return False

        return True

    def get_record(self, transient = True):
        return {'uuid': self.uuid,
                'name_label': self.name_label,
                'name_description': self.name_description,
                'virtual_size': self.virtual_size,
                'physical_utilisation': self.physical_utilisation,
                'sharable': False,
                'readonly': False,
                'SR': self.sr_uuid,
                'other_config': self.other_config,
                'VBDs': []}

    def get_location(self):
        raise NotImplementedError()
                

class XendQCoWVDI(XendVDI):
    def __init__(self, uuid, sr_uuid, qcow_path, cfg_path, vsize, psize):
        XendVDI.__init__(self, uuid, sr_uuid)
        self.auto_save = False
        self.qcow_path = qcow_path
        self.cfg_path = cfg_path
        self.physical_utilisation = psize
        self.virtual_size = vsize
        self.auto_save = True
        self.other_config['location'] = 'tap:qcow:%s' % self.qcow_path

    def get_location(self):
        return self.other_config['location']

class XendLocalVDI(XendVDI):
    def __init__(self, vdi_struct):
        vdi_uuid = vdi_struct['uuid']
        sr_uuid = vdi_struct['SR']
        XendVDI.__init__(self, vdi_uuid, sr_uuid)
        
        self.auto_save = False
        self.cfg_path = None
        self.name_label = vdi_struct.get('name_label','')
        self.name_description = vdi_struct.get('name_description', '')
        self.physical_utilisation = 0
        self.virtual_size = 0
        self.type = vdi_struct.get('type', '')
        self.sharable = vdi_struct.get('sharable', False)
        self.read_only = vdi_struct.get('read_only', False)
        self.other_config = vdi_struct.get('other_config', {})

    def get_location(self):
        return self.other_config['location']
