# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for persistent domain configs.

"""

import sxp
import XendDB
import XendDomain

__all__ = [ "XendDomainConfig" ]

class XendDomainConfig:

    dbpath = 'config'

    def __init__(self):
        self.db = XendDB.XendDB(self.dbpath)

    def domain_config_ls(self, path):
        return self.db.ls(path)

    def domain_config_create(self, path, sxpr):
        self.db.save(path, sxpr)
        pass

    def domain_config_delete(self, path):
        self.db.delete(path)

    def domain_config_instance(self, path):
        """Create a domain from a config.
        """
        config = self.db.fetch(path)
        xd = XendDomain.instance()
        newdom = xd.domain_create(config)
        return newdom

def instance():
    global inst
    try:
        inst
    except:
        inst = XendDomainConfig()
    return inst
