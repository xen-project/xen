# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Xend root class.
Creates the event server and handles configuration.
"""

import os
import os.path
import sys

import EventServer
from XendLogging import XendLogging

# Initial create of the event server.
eserver = EventServer.instance()

import sxp

def reboots():
    """Get a list of system reboots from wtmp.
    """
    out = os.popen('last reboot', 'r')
    list = [ x.strip() for x in out if x.startswith('reboot') ]
    return list

def last_reboot():
    """Get the last known system reboot.
    """
    l = reboots()
    return (l and l[-1]) or None

class XendRoot:
    """Root of the management classes."""

    lastboot_default = "/var/xen/lastboot"

    """Default path to the root of the database."""
    dbroot_default = "/var/xen/xend-db"

    """Default path to the config file."""
    config_default = "/etc/xen/xend-config.sxp"

    """Environment variable used to override config_default."""
    config_var     = "XEND_CONFIG"

    """Where network control scripts live."""
    network_script_dir = "/etc/xen/scripts"

    logfile_default = "/var/log/xend.log"

    loglevel_default = 'DEBUG'

    components = {}

    def __init__(self):
        self.rebooted = 0
        self.last_reboot = None
        self.dbroot = None
        self.config_path = None
        self.config = None
        self.configure()
        self.check_lastboot()
        eserver.subscribe('xend.*', self.event_handler)
        #eserver.subscribe('xend.domain.created', self.event_handler)
        #eserver.subscribe('xend.domain.died', self.event_handler)

    def add_component(self, name, val):
        """Add a xend component.

        @param name: component name
        @param val:  component object
        """
        self.components[name] = val

    def get_component(self, name):
        """Get a xend component from its name.
        This is used as a work-round for problems caused by mutually
        recursive imports.

        @param name: component name
        @return: component object (or None)
        """
        return self.components.get(name)

    def start(self):
        eserver.inject('xend.start', self.rebooted)

    def event_handler(self, event, val):
        print >> sys.stderr, "EVENT>", event, val

    def read_lastboot(self):
        try:
            val = file(self.lastboot, 'rb').readlines()[0]
        except StandardError, ex:
            print 'warning: Error reading', self.lastboot, ex
            val = None
        return val

    def write_lastboot(self, val):
        if not val: return
        try:
            fdir = os.path.dirname(self.lastboot)
            if not os.path.isdir(fdir):
                os.makedirs(fdir)
            out = file(self.lastboot, 'wb+')
            out.write(val)
            out.close()
        except IOError, ex:
            print 'warning: Error writing', self.lastboot, ex
            pass

    def check_lastboot(self):
        """Check if there has been a system reboot since we saved lastboot.
        """
        last_val = self.read_lastboot()
        this_val = last_reboot()
        if this_val == last_val:
            self.rebooted = 0
        else:
            self.rebooted = 1
            self.write_lastboot(this_val)
        self.last_reboot = this_val

    def get_last_reboot(self):
        return self.last_reboot

    def get_rebooted(self):
        return self.rebooted

    def configure(self):
        print 'XendRoot>configure>'
        self.set_config()
        self.configure_logger()
        self.dbroot = self.get_config_value("dbroot", self.dbroot_default)
        self.lastboot = self.get_config_value("lastboot", self.lastboot_default)

    def configure_logger(self):
        logfile = self.get_config_value("logfile", self.logfile_default)
        loglevel = self.get_config_value("loglevel", self.loglevel_default)
        self.logging = XendLogging(logfile, level=loglevel)

    def get_logging(self):
        return self.logging

    def get_logger(self):
        return self.logging.getLogger()

    def get_dbroot(self):
        """Get the path to the database root.
        """
        return self.dbroot

    def set_config(self):
        """If the config file exists, read it. If not, ignore it.

        The config file is a sequence of sxp forms.
        """
        self.config_path = os.getenv(self.config_var, self.config_default)
        print 'XendRoot>set_config> config_path=', self.config_path
        if os.path.exists(self.config_path):
            print 'XendRoot>set_config> loading'
            fin = file(self.config_path, 'rb')
            try:
                config = sxp.parse(fin)
                config.insert(0, 'xend-config')
                self.config = config
            finally:
                fin.close()
        else:
            print 'XendRoot>set_config> not found'
            self.config = ['xend-config']
        print 'XendRoot> config=', self.config

    def get_config(self, name=None):
        """Get the configuration element with the given name, or
        the whole configuration if no name is given.

        @param name: element name (optional)
        @return: config or none
        """
        if name is None:
            val = self.config
        else:
            val = sxp.child(self.config, name)
        return val

    def get_config_value(self, name, val=None):
        """Get the value of an atomic configuration element.

        @param name: element name
        @param val:  default value (optional, defaults to None)
        @return: value
        """
        return sxp.child_value(self.config, name, val=val)

    def get_xend_port(self):
        return int(self.get_config_value('xend-port', '8000'))

    def get_xend_address(self):
        return self.get_config_value('xend-address', '')

    def get_network_script(self):
        return self.get_config_value('network-script', 'network')

    def get_vif_bridge(self):
        return self.get_config_value('vif-bridge', 'xen-br0')

    def get_vif_script(self):
        return self.get_config_value('vif-script', 'vif-bridge')

    def get_vif_antispoof(self):
        v = self.get_config_value('vif-antispoof', 'yes')
        return v in ['yes', '1', 'on']

def instance():
    global inst
    try:
        inst
    except:
        inst = XendRoot()
    return inst

def logger():
    return instance().get_logger()

def add_component(name, val):
    return instance().add_component(name, val)

def get_component(name):
    return instance().get_component(name)
