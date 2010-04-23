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
# Copyright (c) 2009 Fujitsu Technology Solutions.
#============================================================================

""" CPU Pool support including XEN-API and Legacy API.
"""

import types
import threading
import re
import xen.lowlevel.xc
import XendNode
import XendDomain
from xen.xend.XendLogging import log
from xen.xend.XendBase import XendBase
from xen.xend import XendAPIStore
from xen.xend.XendConstants import XS_POOLROOT
from xen.xend import uuid as genuuid
from xen.xend.XendError import VmError, XendAPIError, PoolError
from xen.xend.xenstore.xstransact import xstransact
from xen.util.sxputils import sxp2map, map2sxp


XEND_ERROR_INTERNAL             = 'INTERNAL_ERROR'
XEND_ERROR_UNKOWN_SCHED_POLICY  = 'UNKOWN_SCHED_POLICY'
XEND_ERROR_BAD_POOL_STATE       = 'POOL_BAD_STATE'
XEND_ERROR_POOL_PARAM           = 'PARAMETER_ERROR'
XEND_ERROR_INSUFFICIENT_CPUS    = 'INSUFFICIENT_CPUS'
XEND_ERROR_POOL_RECONF          = 'POOL_RECONF'
XEND_ERROR_INVALID_CPU          = 'INVAILD_CPU'
XEND_ERROR_LAST_CPU_NOT_REM     = 'LAST_CPU_NOT_REMOVEABLE'


XEN_SCHEDULER_TO_ID = {
    'credit2': xen.lowlevel.xc.XEN_SCHEDULER_CREDIT2,
    'credit' : xen.lowlevel.xc.XEN_SCHEDULER_CREDIT,
    'sedf'   : xen.lowlevel.xc.XEN_SCHEDULER_SEDF,
    }

xc = xen.lowlevel.xc.xc()

class XendCPUPool(XendBase):
    """ CPU Pool management.
        @ivar pool_lock: Lock to secure modification of pool data
        @type pool_lock: Rlock
    """

    pool_lock = threading.RLock()

    def getClass(cls):
        return "cpu_pool"

    def getAttrRO(cls):
        attrRO = ['resident_on',
                  'started_VMs',
                  'host_CPUs',
                  'activated',
                 ]
        return XendBase.getAttrRO() + attrRO

    def getAttrRW(cls):
        attrRW = ['name_label',
                  'name_description',
                  'auto_power_on',
                  'ncpu',
                  'sched_policy',
                  'proposed_CPUs',
                  'other_config',
                 ]
        return XendBase.getAttrRW() + attrRW

    def getMethods(cls):
        methods = ['destroy',
                   'activate',
                   'deactivate',
                   'add_host_CPU_live',
                   'remove_host_CPU_live',
                   'add_to_proposed_CPUs',
                   'remove_from_proposed_CPUs',
                   'add_to_other_config',
                   'remove_from_other_config',
                  ]
        return XendBase.getMethods() + methods

    def getFuncs(cls):
        funcs = ['create',
                 'get_by_name_label',
                ]
        return XendBase.getFuncs() + funcs

    getClass    = classmethod(getClass)
    getAttrRO   = classmethod(getAttrRO)
    getAttrRW   = classmethod(getAttrRW)
    getMethods  = classmethod(getMethods)
    getFuncs    = classmethod(getFuncs)


    #
    # XenAPI function calls
    #

    def create(cls, record):
        """ Create a new managed pool instance.
            @param record: attributes of pool
            @type record:  dict
            @return: uuid of created pool
            @rtype:  str
        """
        new_uuid = genuuid.createString()
        XendCPUPool(record, new_uuid)
        XendNode.instance().save_cpu_pools()
        return new_uuid

    create = classmethod(create)


    def get_by_name_label(cls, name_label):
        """ Query a Pool(ref) by its name.
            @return: ref of pool
            @rtype:  str
        """
        cls.pool_lock.acquire()
        try:
            return [ inst.get_uuid()
                     for inst in XendAPIStore.get_all(cls.getClass())
                     if inst.name_label == name_label
                   ]
        finally:
            cls.pool_lock.release()

    get_by_name_label = classmethod(get_by_name_label)


    def get_cpu_pool_by_cpu_ref(cls, host_cpu):
        """ Query cpu_pool ref the given cpu belongs to.
            @param host_cpu: ref of host_cpu to lookup
            @type host_cpu:  str
            @return: list cpu_pool refs (list contains not more than one element)
            @rtype:  list of str
        """
        node = XendNode.instance()
        cpu_nr = node.get_host_cpu_field(host_cpu, 'number')
        for pool_rec in xc.cpupool_getinfo():
            if cpu_nr in pool_rec['cpulist']:
                # pool found; return the ref
                return cls.query_pool_ref(pool_rec['cpupool'])
        return []

    get_cpu_pool_by_cpu_ref = classmethod(get_cpu_pool_by_cpu_ref)


    def get_all_managed(cls):
        """ Query all managed pools.
            @return: uuids of all managed pools
            @rtype:  list of str
        """
        cls.pool_lock.acquire()
        try:
            managed_pools = [ inst.get_uuid()
                              for inst in XendAPIStore.get_all(cls.getClass())
                              if inst.is_managed() ]
        finally:
            cls.pool_lock.release()
        return managed_pools

    get_all_managed = classmethod(get_all_managed)


    #
    # XenAPI methods calls
    #

    def __init__(self, record, new_uuid, managed_pool=True):
        XendBase.__init__(self, new_uuid, record)
        try:
            self._managed = managed_pool
            self.name_label = None

            name = record.get('name_label', 'Pool-Unnamed')
            self._checkName(name)
            self.name_label = name
            self.name_description = record.get('name_description',
                                               self.name_label)
            self.proposed_cpus = [ int(cpu)
                                   for cpu in record.get('proposed_CPUs', []) ]
            self.auto_power_on = bool(record.get('auto_power_on', False))
            self.ncpu = int(record.get('ncpu', 1))
            self.sched_policy = record.get('sched_policy', '')
            self.other_config = record.get('other_config', {})
        except Exception, ex:
            XendBase.destroy(self)
            raise ex


    def get_resident_on(self):
        """ Always return uuid of own node.
            @return: uuid of this node
            @rytpe:  str
        """
        return XendNode.instance().uuid

    def get_started_VMs(self):
        """ Query all VMs currently assigned to pool.
            @return: ref of all VMs assigned to pool; if pool is not active,
                     an empty list will be returned
            @rtype:  list of str
        """
        if self.get_activated():
            # search VMs related to this pool
            pool_id = self.query_pool_id()
            started_VMs = [ vm.get_uuid()
                            for vm in XendDomain.instance().list('all')
                            if vm.get_cpu_pool() == pool_id ]
        else:
            # pool not active, so it couldn't have any started VMs
            started_VMs = []

        return started_VMs

    def get_host_CPUs(self):
        """ Query all cpu refs of this pool currently asisgned .
            - Read pool id of this pool from xenstore
            - Read cpu configuration from hypervisor
            - lookup cpu number -> cpu ref
            @return: host_cpu refs
            @rtype:  list of str
        """
        if self.get_activated():
            node = XendNode.instance()
            pool_id = self.query_pool_id()
            if pool_id == None:
                raise PoolError(XEND_ERROR_INTERNAL,
                                [self.getClass(), 'get_host_CPUs'])
            cpus = []
            for pool_rec in xc.cpupool_getinfo():
                if pool_rec['cpupool'] == pool_id:
                    cpus = pool_rec['cpulist']

            # query host_cpu ref for any cpu of the pool
            host_CPUs = [ cpu_ref
                          for cpu_ref in node.get_host_cpu_refs()
                          if node.get_host_cpu_field(cpu_ref, 'number')
                              in cpus ]
        else:
            # pool not active, so it couldn't have any assigned cpus
            host_CPUs = []

        return host_CPUs

    def get_activated(self):
        """ Query if the pool is registered in XendStore.
            If pool uuid is not in XenStore, the pool is not activated.
            @return: True, if activated
            @rtype:  bool
        """
        return self.query_pool_id() != None

    def get_name_label(self):
        return self.name_label

    def get_name_description(self):
        return self.name_description

    def get_auto_power_on(self):
        return self.auto_power_on

    def get_ncpu(self):
        return self.ncpu

    def get_sched_policy(self):
        if len(self.sched_policy) == 0:
            # default scheduler selected
            return XendNode.instance().get_vcpus_policy()
        else:
            return self.sched_policy

    def get_proposed_CPUs(self):
        return [ str(cpu) for cpu in self.proposed_cpus ]

    def get_other_config(self):
        return self.other_config

    def set_name_label(self, name_label):
        self._checkName(name_label)
        self.name_label = name_label
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def set_name_description(self, name_descr):
        self.name_description = name_descr
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def set_auto_power_on(self, auto_power_on):
        self.auto_power_on = bool(int(auto_power_on))
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def set_ncpu(self, ncpu):
        _ncpu = int(ncpu)
        if _ncpu < 1:
            raise PoolError(XEND_ERROR_POOL_PARAM, 'ncpu')
        self.ncpu = _ncpu
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def set_sched_policy(self, sched_policy):
        if self.get_activated():
            raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'activated')
        self.sched_policy = sched_policy
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def set_proposed_CPUs(self, proposed_cpus):
        if self.get_activated():
            raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'activated')
        self.proposed_cpus = [ int(cpu) for cpu in proposed_cpus ]
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def set_other_config(self, other_config):
        self.other_config = other_config
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def destroy(self):
        """ In order to destroy a cpu pool, it must be deactivated """
        self.pool_lock.acquire()
        try:
            if self.get_activated():
                raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'activated')
            XendBase.destroy(self)
        finally:
            self.pool_lock.release()
        XendNode.instance().save_cpu_pools()

    def activate(self):
        """ Create pool in hypervisor and add cpus.
            Preconditions:
            - pool not already active
            - enough unbound cpus available
            Actions:
            - create pool in hypervisor
            - select free cpus (preferred from proposed_CPUs list) and bind it to
              the pool
            - create entries in Xenstore
        """
        self.pool_lock.acquire()
        try:
            if self.get_activated():
                raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'activated')
            sched_policy = self.get_sched_policy()
            if sched_policy not in XEN_SCHEDULER_TO_ID.keys():
                raise PoolError(XEND_ERROR_UNKOWN_SCHED_POLICY)
            unbound_cpus = set(self.unbound_cpus())
            if len(unbound_cpus) < self.ncpu:
                raise PoolError(XEND_ERROR_INSUFFICIENT_CPUS,
                                [str(self.ncpu), str(len(unbound_cpus))])

            # build list of cpu numbers to bind to pool
            cpu_set = set(self.proposed_cpus).intersection(unbound_cpus)
            if len(cpu_set) < self.ncpu:
                pool_cpus = (list(cpu_set) +
                             list(unbound_cpus.difference(cpu_set)))
            else:
                pool_cpus = list(cpu_set)
            pool_cpus = pool_cpus[0:self.ncpu]

            # create pool in hypervisor
            pool_id = xc.cpupool_create(
                sched = XEN_SCHEDULER_TO_ID.get(sched_policy, 0))

            self.update_XS(pool_id)
            # add cpus
            for cpu in pool_cpus:
                xc.cpupool_addcpu(pool_id, cpu)

        finally:
            self.pool_lock.release()

    def deactivate(self):
        """ Delete pool in hypervisor
            Preconditions:
            - pool is activated
            - no running VMs in pool
            Actions:
            - call hypervisor for deletion
            - remove path of pool in xenstore
        """
        self.pool_lock.acquire()
        try:
            if not self.get_activated():
                raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'deactivated')
            if len(self.get_started_VMs()) != 0:
                raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'in use')

            pool_id = self.query_pool_id()
            # remove cpus from pool
            cpus = []
            for pool_rec in xc.cpupool_getinfo():
                if pool_rec['cpupool'] == pool_id:
                    cpus = pool_rec['cpulist']
            for cpu_number in cpus:
                xc.cpupool_removecpu(pool_id, cpu_number)
            xc.cpupool_destroy(pool_id)

            # update XenStore
            xs_path = XS_POOLROOT + "%s/" % pool_id
            xstransact.Remove(xs_path)
        finally:
            self.pool_lock.release()

    def add_host_CPU_live(self, cpu_ref):
        """ Add cpu to pool, if it is currently not assigned to a pool.
            @param cpu_ref: reference of host_cpu instance to add
            @type  cpu_ref: str
        """
        if not self.get_activated():
            raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'deactivated')
        node = XendNode.instance()
        number = node.get_host_cpu_field(cpu_ref, 'number')

        self.pool_lock.acquire()
        try:
            pool_id = self.query_pool_id()
            other_pool_ref = self.get_cpu_pool_by_cpu_ref(cpu_ref)
            if len(other_pool_ref) != 0:
                raise PoolError(XEND_ERROR_INVALID_CPU,
                            'cpu already assigned to pool "%s"' % other_pool_ref[0])
            xc.cpupool_addcpu(pool_id, number)
        finally:
            self.pool_lock.release()

        if number not in self.proposed_cpus:
            self.proposed_cpus.append(number)
        self._update_ncpu(pool_id)
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def remove_host_CPU_live(self, cpu_ref):
        """ Remove cpu from pool.
            After successfull call, the cpu is free.
            Remove of the last cpu of the pool is rejected.
            @param cpu_ref: reference of host_cpu instance to remove
            @type  cpu_ref: str
        """
        if not self.get_activated():
            raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'deactivated')
        node = XendNode.instance()
        number = node.get_host_cpu_field(cpu_ref, 'number')

        self.pool_lock.acquire()
        try:
            pool_id = self.query_pool_id()
            pool_rec = {}
            for pool in xc.cpupool_getinfo():
                if pool['cpupool'] == pool_id:
                    pool_rec = pool
                    break

            if number in pool_rec['cpulist']:
                if len(pool_rec['cpulist']) < 2 and pool_rec['n_dom'] > 0:
                    raise PoolError(XEND_ERROR_LAST_CPU_NOT_REM,
                                    'could not remove last cpu')
                xc.cpupool_removecpu(pool_id, number)
            else:
                raise PoolError(XEND_ERROR_INVALID_CPU,
                                'CPU not assigned to pool')
        finally:
            self.pool_lock.release()

        if number in self.proposed_cpus:
            self.proposed_cpus.remove(number)
        self._update_ncpu(pool_id)
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def add_to_proposed_CPUs(self, cpu):
        if self.get_activated():
            raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'activated')

        _cpu = int(cpu)
        if _cpu not in self.proposed_cpus:
            self.proposed_cpus.append(_cpu)
            self.proposed_cpus.sort()
            if self._managed:
                XendNode.instance().save_cpu_pools()

    def remove_from_proposed_CPUs(self, cpu):
        if self.get_activated():
            raise PoolError(XEND_ERROR_BAD_POOL_STATE, 'activated')
        _cpu = int(cpu)
        if _cpu in self.proposed_cpus:
            self.proposed_cpus.remove(_cpu)
            if self._managed:
                XendNode.instance().save_cpu_pools()

    def add_to_other_config(self, key, value):
        self.other_config[key] = value
        if self._managed:
            XendNode.instance().save_cpu_pools()

    def remove_from_other_config(self, key):
        if key in self.other_config:
            del self.other_config[key]
        if self._managed:
            XendNode.instance().save_cpu_pools()


    #
    # Legacy RPC calls
    #
    def pool_new(cls, config):
        try:
            record = sxp2map(config)
            if record.has_key('proposed_CPUs') and \
               not isinstance(record['proposed_CPUs'], types.ListType):
                record['proposed_CPUs'] = [record['proposed_CPUs']]
            new_uuid = cls.create(record)
        except XendAPIError, ex:
            raise VmError(ex.get_api_error())
        return new_uuid

    def pool_create(cls, config):
        try:
            record = sxp2map(config)
            if record.has_key('proposed_CPUs') and \
               not isinstance(record['proposed_CPUs'], types.ListType):
                record['proposed_CPUs'] = [record['proposed_CPUs']]
            new_uuid = genuuid.createString()
            pool = XendCPUPool(record, new_uuid, False)
            pool.activate()
        except XendAPIError, ex:
            raise VmError(ex.get_api_error())

    def pool_start(cls, poolname):
        pool = cls.lookup_pool(poolname)
        if not pool:
            raise VmError('unknown pool %s' % poolname)
        try:
            pool.activate()
        except XendAPIError, ex:
            raise VmError(ex.get_api_error())

    def pool_list(cls, names):
        sxprs = []
        try:
            node = XendNode.instance()
            xd = XendDomain.instance()
            pools = cls.get_all_records()
            for (pool_uuid, pool_vals) in pools.items():
                if pool_vals['name_label'] in names or len(names) == 0:
                    # conv host_cpu refs to cpu number
                    cpus = [ node.get_host_cpu_field(cpu_ref, 'number')
                             for cpu_ref in pool_vals['host_CPUs'] ]
                    cpus.sort()
                    pool_vals['host_CPU_numbers'] = cpus
                    # query VMs names. Take in account, that a VM
                    # returned by get_all_records could be destroy, now
                    vm_names = [ vm.getName()
                                 for vm in map(xd.get_vm_by_uuid,
                                               pool_vals['started_VMs'])
                                 if vm ]
                    pool_vals['started_VM_names'] = vm_names
                    pool_vals['auto_power_on'] = int(pool_vals['auto_power_on'])
                    sxprs += [[pool_uuid] + map2sxp(pool_vals)]
        except XendAPIError, ex:
            raise VmError(ex.get_api_error())
        return sxprs

    def pool_destroy(cls, poolname):
        pool = cls.lookup_pool(poolname)
        if not pool:
            raise VmError('unknown pool %s' % poolname)
        try:
            pool.deactivate()
            if not pool.is_managed():
                pool.destroy()
        except XendAPIError, ex:
            raise VmError(ex.get_api_error())

    def pool_delete(cls, poolname):
        pool = cls.lookup_pool(poolname)
        if not pool:
            raise VmError('unknown pool %s' % poolname)
        try:
            pool.destroy()
        except XendAPIError, ex:
            raise VmError(ex.get_api_error())

    def pool_cpu_add(cls, poolname, cpu):
        pool = cls.lookup_pool(poolname)
        if not pool:
            raise VmError('unknown pool %s' % poolname)
        try:
            cpu_ref = cls._cpu_number_to_ref(int(cpu))
            if cpu_ref:
                pool.add_host_CPU_live(cpu_ref)
            else:
                raise PoolError(XEND_ERROR_INVALID_CPU,
                                'CPU unknown')
        except XendAPIError, ex:
            raise VmError(ex.get_api_error())

    def pool_cpu_remove(cls, poolname, cpu):
        pool = cls.lookup_pool(poolname)
        if not pool:
            raise VmError('unknown pool %s' % poolname)
        try:
            cpu_ref = cls._cpu_number_to_ref(int(cpu))
            if cpu_ref:
                pool.remove_host_CPU_live(cpu_ref)
            else:
                raise PoolError(XEND_ERROR_INVALID_CPU,
                                'CPU unknown')
        except XendAPIError, ex:
            raise VmError(ex.get_api_error())

    def pool_migrate(cls, domname, poolname):
        dom = XendDomain.instance()
        pool = cls.lookup_pool(poolname)
        if not pool:
            raise VmError('unknown pool %s' % poolname)
        dominfo = dom.domain_lookup_nr(domname)
        if not dominfo:
            raise VmError('unknown domain %s' % domname)
        domid = dominfo.getDomid()
        if domid is not None:
            if domid == 0:
                raise VmError('could not move Domain-0')
            try:
                cls.move_domain(pool.get_uuid(), domid)
            except Exception, ex:
                raise VmError('could not move domain')
        dominfo.info['pool_name'] = poolname
        dom.managed_config_save(dominfo)

    pool_new        = classmethod(pool_new)
    pool_create     = classmethod(pool_create)
    pool_start      = classmethod(pool_start)
    pool_list       = classmethod(pool_list)
    pool_destroy    = classmethod(pool_destroy)
    pool_delete     = classmethod(pool_delete)
    pool_cpu_add    = classmethod(pool_cpu_add)
    pool_cpu_remove = classmethod(pool_cpu_remove)
    pool_migrate    = classmethod(pool_migrate)


    #
    # methods
    #

    def is_managed(self):
        """ Check, if pool is managed.
            @return: True, if managed
            @rtype: bool
        """
        return self._managed

    def query_pool_id(self):
        """ Get corresponding pool-id of pool instance from XenStore.
            @return: pool id or None
            @rytpe:  int
        """
        self.pool_lock.acquire()
        try:
            for pool_id in xstransact.List(XS_POOLROOT):
                uuid = xstransact.Read(XS_POOLROOT + "%s/" % pool_id, 'uuid')
                if uuid == self.get_uuid():
                    return int(pool_id)
        finally:
            self.pool_lock.release()

        return None

    def update_XS(self, pool_id):
        """ Write (or update) data in xenstore taken from instance.
            @param pool_id: Pool id to build path to pool data in xenstore
            @type  pool_id: int
        """
        self.pool_lock.acquire()
        try:
            xs_path = XS_POOLROOT + "%s/" % pool_id
            xs_entries = { 'uuid' : self.get_uuid(),
                           'name' : self.name_label,
                           'description' : self.name_description
                         }
            xstransact.Mkdir(xs_path)
            xstransact.Mkdir(xs_path, 'other_config')
            xstransact.Write(xs_path, xs_entries)
            xstransact.Write('%s%s' % (xs_path, 'other_config'),
                             self.other_config)
        finally:
            self.pool_lock.release()

    def _update_ncpu(self, pool_id):
        for pool_rec in xc.cpupool_getinfo():
            if pool_rec['cpupool'] == pool_id:
                self.ncpu = len(pool_rec['cpulist'])

    def _checkName(self, name):
        """ Check if a pool name is valid. Valid names contain alphabetic
            characters, digits, or characters in '_-.:/+'.
            The same name cannot be used for more than one pool at the same
            time.
            @param name: name
            @type name:  str
            @raise: PoolError if invalid
        """
        if name is None or name == '':
            raise PoolError(XEND_ERROR_POOL_PARAM, 'Missing Pool Name')
        if not re.search(r'^[A-Za-z0-9_\-\.\:\/\+]+$', name):
            raise PoolError(XEND_ERROR_POOL_PARAM, 'Invalid Pool Name')

        pool = self.lookup_pool(name)
        if pool and pool.get_uuid() != self.get_uuid():
            raise PoolError(XEND_ERROR_POOL_PARAM,
                'Pool name "%s" already exists' % name)


    #
    # class methods
    #

    def recreate_active_pools(cls):
        """ Read active pool config from hypervisor and create pool instances.
            - Query pool ids and assigned CPUs from hypervisor.
            - Query additional information for any pool from xenstore.
              If an entry for a pool id is missing in xenstore, it will be
              recreated with a new uuid and generic name (this is an error case)
            - Create an XendCPUPool instance for any pool id
            Function have to be called after recreation of managed pools.
        """
        log.debug('recreate_active_pools')

        for pool_rec in xc.cpupool_getinfo():
            pool = pool_rec['cpupool']

            # read pool data from xenstore
            path = XS_POOLROOT + "%s/" % pool
            uuid = xstransact.Read(path, 'uuid')
            if not uuid:
                # xenstore entry missing / invaild; create entry with new uuid
                uuid = genuuid.createString()
                name = "Pool-%s" % pool
                try:
                    inst = XendCPUPool( { 'name_label' : name }, uuid, False )
                    inst.update_XS(pool)
                except PoolError, ex:
                    # log error and skip domain
                    log.error('cannot recreate pool %s; skipping (reason: %s)' \
                        % (name, ex))
            else:
                (name, descr) = xstransact.Read(path, 'name', 'description')
                other_config = {}
                for key in xstransact.List(path + 'other_config'):
                    other_config[key] = xstransact.Read(
                        path + 'other_config/%s' % key)

                # check existance of pool instance
                inst = XendAPIStore.get(uuid, cls.getClass())
                if inst:
                    # update attributes of existing instance
                    inst.name_label = name
                    inst.name_description = descr
                    inst.other_config = other_config
                else:
                    # recreate instance
                    try:
                        inst = XendCPUPool(
                            { 'name_label' : name,
                              'name_description' : descr,
                              'other_config' : other_config,
                              'proposed_CPUs' : pool_rec['cpulist'],
                              'ncpu' : len(pool_rec['cpulist']),
                            },
                            uuid, False )
                    except PoolError, ex:
                        # log error and skip domain
                        log.error(
                            'cannot recreate pool %s; skipping (reason: %s)' \
                            % (name, ex))

    recreate_active_pools = classmethod(recreate_active_pools)


    def recreate(cls, record, current_uuid):
        """ Recreate a pool instance while xend restart.
            @param record: attributes of pool
            @type record:  dict
            @param current_uuid: uuid of pool to create
            @type current_uuid:  str
        """
        XendCPUPool(record, current_uuid)

    recreate = classmethod(recreate)


    def autostart_pools(cls):
        """ Start managed pools that are marked as autostart pools.
            Function is called after recreation of managed domains while
            xend restart.
        """
        cls.pool_lock.acquire()
        try:
            for inst in XendAPIStore.get_all(cls.getClass()):
                if inst.is_managed() and inst.auto_power_on and \
                   inst.query_pool_id() == None:
                    inst.activate()
        finally:
            cls.pool_lock.release()

    autostart_pools = classmethod(autostart_pools)


    def move_domain(cls, pool_ref, domid):
        cls.pool_lock.acquire()
        try:
            pool = XendAPIStore.get(pool_ref, cls.getClass())
            pool_id = pool.query_pool_id()

            xc.cpupool_movedomain(pool_id, domid)
        finally:
            cls.pool_lock.release()

    move_domain = classmethod(move_domain)


    def query_pool_ref(cls, pool_id):
        """ Get pool ref by pool id.
            Take the ref from xenstore.
            @param pool_id:
            @type  pool_id: int
            @return: ref
            @rtype:  str
        """
        uuid = xstransact.Read(XS_POOLROOT + "%s/" % pool_id, 'uuid')
        if uuid:
            return [uuid]
        else:
            return []

    query_pool_ref = classmethod(query_pool_ref)


    def lookup_pool(cls, id_or_name):
        """ Search XendCPUPool instance with given id_or_name.
            @param id_or_name: pool id or pool nameto search
            @type id_or_name:  [int, str]
            @return: instane or None if not found
            @rtype:  XendCPUPool
        """
        pool_uuid = None
        try:
            pool_id = int(id_or_name)
            # pool id given ?
            pool_uuid = cls.query_pool_ref(pool_id)
            if not pool_uuid:
                # not found -> search name
                pool_uuid = cls.get_by_name_label(id_or_name)
        except ValueError:
            # pool name given
            pool_uuid = cls.get_by_name_label(id_or_name)

        if len(pool_uuid) > 0:
            return XendAPIStore.get(pool_uuid[0], cls.getClass())
        else:
            return None

    lookup_pool = classmethod(lookup_pool)


    def _cpu_number_to_ref(cls, number):
        node = XendNode.instance()
        for cpu_ref in node.get_host_cpu_refs():
            if node.get_host_cpu_field(cpu_ref, 'number') == number:
                return cpu_ref
        return None

    _cpu_number_to_ref = classmethod(_cpu_number_to_ref)


    def unbound_cpus(cls):
        """ Build list containing the numbers of all cpus not bound to a pool.
            Info is taken from Hypervisor.
            @return: list of cpu numbers
            @rytpe:  list of int
        """
        return xc.cpupool_freeinfo()

    unbound_cpus = classmethod(unbound_cpus)

