#!/usr/bin/env python

import xmlrpclib

from xen.xend.XendClient import server
from xen.xend import sxp
# XXX XendDomain is voodoo to let balloon import succeed
from xen.xend import XendDomain, balloon

import vif
import blkdev
# need a nicer way to load disk drivers
import vbd

class VMException(Exception): pass

class VM(object):
    "Representation of a virtual machine"
    def __init__(self, domid=None, dominfo=None):
        self.dominfo = dominfo

        self.domid = -1
        self.name = 'unknown'
        self.dom = {}
        self.disks = []
        self.vifs = []

        if domid:
            try:
                self.dominfo = server.xend.domain(domid, 'all')
            except xmlrpclib.Fault:
                raise VMException('error looking up domain %s' % str(domid))

        if self.dominfo:
            self.loaddominfo()

    def loaddominfo(self):
        self.dom = parsedominfo(self.dominfo)
        self.domid = self.dom['domid']
        self.name = self.dom['name']

        self.disks = getdisks(self.dom)
        self.vifs = getvifs(self.dom)

    def __str__(self):
        return 'VM %d (%s), MACs: [%s], disks: [%s]' % \
               (self.domid, self.name, self.epoch, ', '.join(self.macs),
                ', '.join([str(d) for d in self.disks]))

def parsedominfo(dominfo):
    "parses a dominfo sexpression in the form of python lists of lists"
    def s2d(s):
        r = {}
        for elem in s:
            if len(elem) == 0:
                continue
            name = elem[0]
            if len(elem) == 1:
                val = None
            else:
                val = elem[1]
            if isinstance(val, list):
                val = s2d(elem[1:])
            if isinstance(name, list):
                # hack for ['cpus', [[1]]]
                return s2d(elem)
            if name in r:
                for k, v in val.iteritems():
                    if k in r[name]:
                        if not isinstance(r[name][k], list):
                            r[name][k] = [r[name][k]]
                        r[name][k].append(v)
                    else:
                        r[name][k] = v
            else:
                r[name] = val
        return r

    return s2d(dominfo[1:])

def domtosxpr(dom):
    "convert a dominfo into a python sxpr"
    def d2s(d):
        r = []
        for k, v in d.iteritems():
            elem = [k]
            if isinstance(v, dict):
                elem.extend(d2s(v))
            else:
                if v is None:
                    v = ''
                elem.append(v)
            r.append(elem)
        return r

    sxpr = ['domain']
    sxpr.extend(d2s(dom))
    return sxpr

def strtosxpr(s):
    "convert a string to a python sxpr"
    p = sxp.Parser()
    p.input(s)
    return p.get_val()

def sxprtostr(sxpr):
    "convert an sxpr to string"
    return sxp.to_string(sxpr)

def getvifs(dom):
    "return vif objects for devices in dom"
    vifs = dom['device'].get('vif', [])
    if type(vifs) != list:
        vifs = [vifs]

    return [vif.parse(v) for v in vifs]

def getdisks(dom):
    "return block device objects for devices in dom"
    disks = dom['device'].get('vbd', [])
    if type(disks) != list:
        disks = [disks]

    # tapdisk1 devices
    tap1s = dom['device'].get('tap', [])
    if type(tap1s) != list:
        disks.append(tap1s)
    else:
        disks.extend(tap1s)

    # tapdisk2 devices
    tap2s = dom['device'].get('tap2', [])
    if type(tap2s) != list:
        disks.append(tap2s)
    else:
        disks.extend(tap2s)

    return [blkdev.parse(disk) for disk in disks]

def fromxend(domid):
    "create a VM object from xend information"
    return VM(domid)

def getshadowmem(vm):
    "Balloon down domain0 to create free memory for shadow paging."
    maxmem = int(vm.dom['maxmem'])
    shadow = int(vm.dom['shadow_memory'])
    vcpus = int(vm.dom['vcpus'])

    # from XendDomainInfo.checkLiveMigrateMemory:
    # 1MB per vcpu plus 4Kib/Mib of RAM.  This is higher than
    # the minimum that Xen would allocate if no value were given.
    needed = vcpus * 1024 + maxmem * 4 - shadow * 1024
    if needed > 0:
        print "Freeing %d kB for shadow mode" % needed
        balloon.free(needed, vm.dominfo)
