#code to play with vdis and snapshots

import os

def run(cmd):
    fd = os.popen(cmd)
    res = [l for l in fd if l.rstrip()]
    return not fd.close(), res


_blockstore = '/blockstore.dat'

def set_blockstore(blockstore):
    global _blockstore
    __blockstore = blockstore


class SnapShot:
    def __init__(self, vdi, block, index):
       self.__vdi = vdi
       self.__block = block
       self.__index = index

       #TODO add snapshot date and radix

    def __str__(self):
       return '%d %d %d' % (self.__vdi.id(), self.__block, self.__index)

    def vdi(self):
       return self.__vdi

    def block(self):
       return self.__block

    def index(self):
       return self.__index

    def match(self, block, index):
       return self.__block == block and self.__index == index


class VDIException(Exception):
       pass


class VDI:
    def __init__(self, id, name):
       self.__id = id
       self.__name = name

    def __str__(self):
       return 'vdi: %d %s' % (self.__id, self.__name)

    def id(self):
       return self.__id

    def name(self):
       return self.__name

    def list_snapshots(self):
       res, ls = run('vdi_snap_list %s %d' % (_blockstore, self.__id))
       if res:
           return [SnapShot(self, int(l[0]), int(l[1])) for l in [l.split() for l in ls[1:]]]
       else:
           raise VDIException("Error reading snapshot list")

    def snapshot(self):
       res, ls = run('vdi_checkpoint %s %d' % (_blockstore, self.__id))
       if res:
           _, block, idx = ls[0].split()
           return SnapShot(self, int(block), int(idx))
       else:
           raise VDIException("Error taking vdi snapshot")


def create(name, snap):
    res, _ = run('vdi_create %s %s %d %d'
                % (_blockstore, name, snap.block(), snap.index()))
    if res:
       return lookup_by_name(name)
    else:
       raise VDIException('Unable to create vdi from snapshot')


def fill(name, img_file):
    res, _ = run('vdi_create %s %s' % (_blockstore, name))

    if res:
       vdi = lookup_by_name(name)
       res, _ = run('vdi_fill %d %s' % (vdi.id(), img_file))
       if res:
           return vdi
    raise VDIException('Unable to create vdi from disk img file')


def list_vdis():
    vdis = []
    res, lines = run('vdi_list %s' % _blockstore)
    if res:
       for l in lines:
           r = l.split()
           vdis.append(VDI(int(r[0]), r[1]))
       return vdis
    else:
       raise VDIException("Error doing vdi list")


def lookup_by_id(id):
    vdis = list_vdis()
    for v in vdis:
       if v.id() == id:
           return v
    raise VDIException("No match from vdi id")


def lookup_by_name(name):
    vdis = list_vdis()
    for v in vdis:
       if v.name() == name:
           return v
    raise VDIException("No match for vdi name")
