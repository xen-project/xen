# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Xend root class.
Creates the event server and handles configuration.
"""

import os
import os.path
import sys
import EventServer

# Initial create of the event server.
eserver = EventServer.instance()

import sxp

def reboots():
    """Get a list of system reboots from wtmp.
    """
    out = os.popen('/usr/bin/last reboot', 'r')
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
        self.set_config()
        self.dbroot = self.get_config_value("dbroot", self.dbroot_default)
        self.lastboot = self.get_config_value("lastboot", self.lastboot_default)

    def get_dbroot(self):
        """Get the path to the database root.
        """
        return self.dbroot

    def set_config(self):
        """If the config file exists, read it. If not, ignore it.

        The config file is a sequence of sxp forms.
        """
        self.config_path = os.getenv(self.config_var, self.config_default)
        if os.path.exists(self.config_path):
            fin = file(self.config_path, 'rb')
            try:
                config = sxp.parse(fin)
                config.insert(0, 'config')
                self.config = config
            finally:
                fin.close()
        else:
            self.config = ['config']

    def get_config(self, name=None):
        """Get the configuration element with the given name, or
        the whole configuration if no name is given.

        name	element name (optional)
        returns config or none
        """
        if name is None:
            val = self.config
        else:
            val = sxp.child(self.config, name)
        return val

    def get_config_value(self, name, val=None):
        """Get the value of an atomic configuration element.

        name	element name
        val	default value (optional, defaults to None)
        returns value
        """
        return sxp.child_value(self.config, name) or val

def instance():
    global inst
    try:
        inst
    except:
        inst = XendRoot()
    return inst
