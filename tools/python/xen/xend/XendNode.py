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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (c) 2006, 2007 Xensource Inc.
#============================================================================

import os
import socket
import time
import xen.lowlevel.xc

from xen.util import Brctl
from xen.util import pci as PciUtil
from xen.util import vscsi_util
from xen.xend import XendAPIStore
from xen.xend import osdep
from xen.xend.XendConstants import *

import uuid, arch
from XendPBD import XendPBD
from XendError import *
from XendOptions import instance as xendoptions
from XendQCoWStorageRepo import XendQCoWStorageRepo
from XendLocalStorageRepo import XendLocalStorageRepo
from XendLogging import log
from XendPIF import *
from XendPIFMetrics import XendPIFMetrics
from XendNetwork import *
from XendStateStore import XendStateStore
from XendMonitor import XendMonitor
from XendPPCI import XendPPCI
from XendPSCSI import XendPSCSI, XendPSCSI_HBA

class XendNode:
    """XendNode - Represents a Domain 0 Host."""
    
    def __init__(self):
        """Initalises the state of all host specific objects such as

        * host
        * host_CPU
        * host_metrics
        * PIF
        * PIF_metrics
        * network
        * Storage Repository
        * PPCI
        * PSCSI
        """
        
        self.xc = xen.lowlevel.xc.xc()
        self.state_store = XendStateStore(xendoptions().get_xend_state_path())
        self.monitor = XendMonitor()
        self.monitor.start()

        # load host state from XML file
        saved_host = self.state_store.load_state('host')
        if saved_host and len(saved_host.keys()) == 1:
            self.uuid = saved_host.keys()[0]
            host = saved_host[self.uuid]
            self.name = host.get('name_label', socket.gethostname())
            self.desc = host.get('name_description', '')
            self.host_metrics_uuid = host.get('metrics_uuid',
                                              uuid.createString())
            try:
                self.other_config = eval(host['other_config'])
            except:
                self.other_config = {}
            self.cpus = {}
        else:
            self.uuid = uuid.createString()
            self.name = socket.gethostname()
            self.desc = ''
            self.other_config = {}
            self.cpus = {}
            self.host_metrics_uuid = uuid.createString()

        # put some arbitrary params in other_config as this
        # is directly exposed via XenAPI
        self.other_config["xen_pagesize"] = self.xeninfo_dict()["xen_pagesize"]
        self.other_config["platform_params"] = self.xeninfo_dict()["platform_params"]
        self.other_config["xen_commandline"] = self.xeninfo_dict()["xen_commandline"]
            
        # load CPU UUIDs
        saved_cpus = self.state_store.load_state('cpu')
        for cpu_uuid, cpu in saved_cpus.items():
            self.cpus[cpu_uuid] = cpu

        cpuinfo = osdep.get_cpuinfo()
        physinfo = self.physinfo_dict()
        cpu_count = physinfo['nr_cpus']
        cpu_features = physinfo['hw_caps']
        virt_caps = physinfo['virt_caps']

        # If the number of CPUs don't match, we should just reinitialise 
        # the CPU UUIDs.
        if cpu_count != len(self.cpus):
            self.cpus = {}
            for i in range(cpu_count):
                u = uuid.createString()
                self.cpus[u] = {'uuid': u, 'number': i }

        for u in self.cpus.keys():
            number = self.cpus[u]['number']
            # We can run off the end of the cpuinfo list if domain0 does not
            # have #vcpus == #pcpus. In that case we just replicate one that's
            # in the hash table.
            if not cpuinfo.has_key(number):
                number = cpuinfo.keys()[0]
            if arch.type == "x86":
                self.cpus[u].update(
                    { 'host'     : self.uuid,
                      'features' : cpu_features,
                      'virt_caps': virt_caps,
                      'speed'    : int(float(cpuinfo[number]['cpu MHz'])),
                      'vendor'   : cpuinfo[number]['vendor_id'],
                      'modelname': cpuinfo[number]['model name'],
                      'stepping' : cpuinfo[number]['stepping'],
                      'flags'    : cpuinfo[number]['flags'],
                    })
            elif arch.type == "ia64":
                self.cpus[u].update(
                    { 'host'     : self.uuid,
                      'features' : cpu_features,
                      'speed'    : int(float(cpuinfo[number]['cpu MHz'])),
                      'vendor'   : cpuinfo[number]['vendor'],
                      'modelname': cpuinfo[number]['family'],
                      'stepping' : cpuinfo[number]['model'],
                      'flags'    : cpuinfo[number]['features'],
                    })
            else:
                self.cpus[u].update(
                    { 'host'     : self.uuid,
                      'features' : cpu_features,
                    })

        self.srs = {}

        self._init_networks()
        self._init_PIFs()

        self._init_SRs()
        self._init_PBDs()

        self._init_PPCIs()

        self._init_PSCSIs()


    def _init_networks(self):
        # Initialise networks
        # First configure ones off disk
        saved_networks = self.state_store.load_state('network')
        if saved_networks:
            for net_uuid, network in saved_networks.items():
                try:
                    XendNetwork.recreate(network, net_uuid)
                except CreateUnspecifiedAttributeError:
                    log.warn("Error recreating network %s", net_uuid)
                
        # Next discover any existing bridges and check
        # they are not already configured

        # 'tmpbridge' is a temporary bridge created by network-bridge script.
        # Wait a couple of seconds for it to be renamed.
        for i in xrange(20):
            bridges = Brctl.get_state().keys()
            if 'tmpbridge' in bridges:
                time.sleep(0.1)
            else:
                break
            
        configured_bridges = [XendAPIStore.get(
                                  network_uuid, "network")
                                      .get_name_label()
                              for network_uuid in XendNetwork.get_all()]
        unconfigured_bridges = [bridge
                                for bridge in bridges
                                if bridge not in configured_bridges]
        for unconfigured_bridge in unconfigured_bridges:
            if unconfigured_bridge != 'tmpbridge':
                XendNetwork.create_phy(unconfigured_bridge)

    def _init_PIFs(self):
        # Initialise PIFs
        # First configure ones off disk
        saved_pifs = self.state_store.load_state('pif')
        if saved_pifs:
            for pif_uuid, pif in saved_pifs.items():
                try:
                    XendPIF.recreate(pif, pif_uuid)
                except CreateUnspecifiedAttributeError:
                    log.warn("Error recreating PIF %s", pif_uuid)
        
        # Next discover any existing PIFs and check
        # they are not already configured
        configured_pifs = [XendAPIStore.get(
                               pif_uuid, "PIF")
                                   .get_interface_name()
                           for pif_uuid in XendPIF.get_all()]
        unconfigured_pifs = [(name, mtu, mac)
                             for name, mtu, mac in linux_get_phy_ifaces()
                             if name not in configured_pifs]

        # Get a mapping from interface to bridge          
        if_to_br = dict([(i,b)
                         for (b,ifs) in Brctl.get_state().items()
                             for i in ifs])

        for name, mtu, mac in unconfigured_pifs:
            # Check PIF is on bridge
            # if not, ignore
            bridge_name = if_to_br.get(name, None)
            if bridge_name is not None:
                # Translate bridge name to network uuid
                for network_uuid in XendNetwork.get_all():
                    network = XendAPIStore.get(
                        network_uuid, 'network')
                    if network.get_name_label() == bridge_name:
                        XendPIF.create_phy(network_uuid, name,
                                           mac, mtu)
                        break
                else:
                    log.debug("Cannot find network for bridge %s "
                              "when configuring PIF %s",
                              (bridge_name, name))     

    def _init_SRs(self):
        # initialise storage
        saved_srs = self.state_store.load_state('sr')
        if saved_srs:
            for sr_uuid, sr_cfg in saved_srs.items():
                if sr_cfg['type'] == 'qcow_file':
                    self.srs[sr_uuid] = XendQCoWStorageRepo(sr_uuid)
                elif sr_cfg['type'] == 'local':
                    self.srs[sr_uuid] = XendLocalStorageRepo(sr_uuid)

        # Create missing SRs if they don't exist
        if not self.get_sr_by_type('local'):
            image_sr_uuid = uuid.createString()
            self.srs[image_sr_uuid] = XendLocalStorageRepo(image_sr_uuid)
            
        if not self.get_sr_by_type('qcow_file'):
            qcow_sr_uuid = uuid.createString()
            self.srs[qcow_sr_uuid] = XendQCoWStorageRepo(qcow_sr_uuid)

    def _init_PBDs(self):
        saved_pbds = self.state_store.load_state('pbd')
        if saved_pbds:
            for pbd_uuid, pbd_cfg in saved_pbds.items():
                try:
                    XendPBD.recreate(pbd_uuid, pbd_cfg)
                except CreateUnspecifiedAttributeError:
                    log.warn("Error recreating PBD %s", pbd_uuid) 

    def _init_PPCIs(self):
        saved_ppcis = self.state_store.load_state('ppci')
        saved_ppci_table = {}
        if saved_ppcis:
            for ppci_uuid, ppci_record in saved_ppcis.items():
                try:
                    saved_ppci_table[ppci_record['name']] = ppci_uuid
                except KeyError:
                    pass

        for pci_dev in PciUtil.get_all_pci_devices():
            ppci_record = {
                'domain':                   pci_dev.domain,
                'bus':                      pci_dev.bus,
                'slot':                     pci_dev.slot,
                'func':                     pci_dev.func,
                'vendor_id':                pci_dev.vendor,
                'vendor_name':              pci_dev.vendorname,
                'device_id':                pci_dev.device,
                'device_name':              pci_dev.devicename,
                'revision_id':              pci_dev.revision,
                'class_code':               pci_dev.classcode,
                'class_name':               pci_dev.classname,
                'subsystem_vendor_id':      pci_dev.subvendor,
                'subsystem_vendor_name':    pci_dev.subvendorname,
                'subsystem_id':             pci_dev.subdevice,
                'subsystem_name':           pci_dev.subdevicename,
                'driver':                   pci_dev.driver
                }
            # If saved uuid exists, use it. Otherwise create one.
            ppci_uuid = saved_ppci_table.get(pci_dev.name, uuid.createString())
            XendPPCI(ppci_uuid, ppci_record)

    def _init_PSCSIs(self):
        # Initialise PSCSIs and PSCSI_HBAs
        saved_pscsis = self.state_store.load_state('pscsi')
        saved_pscsi_table = {}
        if saved_pscsis:
            for pscsi_uuid, pscsi_record in saved_pscsis.items():
                try:
                    saved_pscsi_table[pscsi_record['scsi_id']] = pscsi_uuid
                except KeyError:
                    pass

        saved_pscsi_HBAs = self.state_store.load_state('pscsi_HBA')
        saved_pscsi_HBA_table = {}
        if saved_pscsi_HBAs:
            for pscsi_HBA_uuid, pscsi_HBA_record in saved_pscsi_HBAs.items():
                try:
                    physical_host = int(pscsi_HBA_record['physical_host'])
                    saved_pscsi_HBA_table[physical_host] = pscsi_HBA_uuid
                except (KeyError, ValueError):
                    pass

        pscsi_table = {}
        pscsi_HBA_table = {}

        for pscsi_record in vscsi_util.get_all_scsi_devices():
            scsi_id = pscsi_record['scsi_id']
            if scsi_id:
                saved_HBA_uuid = None

                pscsi_uuid = saved_pscsi_table.get(scsi_id, None)
                if pscsi_uuid is None:
                    pscsi_uuid = uuid.createString()
                    saved_pscsi_table[scsi_id] = pscsi_uuid
                else:
                    saved_HBA_uuid = saved_pscsis[pscsi_uuid].get('HBA', None)

                physical_host = int(pscsi_record['physical_HCTL'].split(':')[0])
                if pscsi_HBA_table.has_key(physical_host):
                    pscsi_HBA_uuid = pscsi_HBA_table[physical_host]
                elif saved_pscsi_HBA_table.has_key(physical_host):
                    pscsi_HBA_uuid = saved_pscsi_HBA_table[physical_host]
                    pscsi_HBA_table[physical_host] = pscsi_HBA_uuid
                else:
                    pscsi_HBA_uuid = uuid.createString()
                    pscsi_HBA_table[physical_host] = pscsi_HBA_uuid

                if saved_HBA_uuid is not None and \
                   saved_HBA_uuid != pscsi_HBA_uuid:
                    log.debug('The PSCSI(%s) host number was changed', scsi_id)
                pscsi_record['HBA'] = pscsi_HBA_uuid
                pscsi_table[pscsi_uuid] = pscsi_record

        for pscsi_uuid, pscsi_record in pscsi_table.items():
            XendPSCSI(pscsi_uuid, pscsi_record)

        for physical_host, pscsi_HBA_uuid in pscsi_HBA_table.items():
            XendPSCSI_HBA(pscsi_HBA_uuid, {'physical_host': physical_host})


    def add_network(self, interface):
        # TODO
        log.debug("add_network(): Not implemented.")


    def remove_network(self, interface):
        # TODO
        log.debug("remove_network(): Not implemented.")


    def add_PPCI(self, pci_name):
        # Update lspci info
        PciUtil.create_lspci_info()

        # Initialise the PPCI
        saved_ppcis = self.state_store.load_state('ppci')
        saved_ppci_table = {}
        if saved_ppcis:
            for ppci_uuid, ppci_record in saved_ppcis.items():
                try:
                    saved_ppci_table[ppci_record['name']] = ppci_uuid
                except KeyError:
                    pass

        pci_dev = PciUtil.PciDevice(PciUtil.parse_pci_name(pci_name))
        ppci_record = {
            'domain':                   pci_dev.domain,
            'bus':                      pci_dev.bus,
            'slot':                     pci_dev.slot,
            'func':                     pci_dev.func,
            'vendor_id':                pci_dev.vendor,
            'vendor_name':              pci_dev.vendorname,
            'device_id':                pci_dev.device,
            'device_name':              pci_dev.devicename,
            'revision_id':              pci_dev.revision,
            'class_code':               pci_dev.classcode,
            'class_name':               pci_dev.classname,
            'subsystem_vendor_id':      pci_dev.subvendor,
            'subsystem_vendor_name':    pci_dev.subvendorname,
            'subsystem_id':             pci_dev.subdevice,
            'subsystem_name':           pci_dev.subdevicename,
            'driver':                   pci_dev.driver
            }
        # If saved uuid exists, use it. Otherwise create one.
        ppci_uuid = saved_ppci_table.get(pci_dev.name, uuid.createString())
        XendPPCI(ppci_uuid, ppci_record)

        self.save_PPCIs()


    def remove_PPCI(self, pci_name):
        # Update lspci info
        PciUtil.create_lspci_info()

        # Remove the PPCI
        (domain, bus, slot, func) = PciUtil.parse_pci_name(pci_name)
        ppci_ref = XendPPCI.get_by_sbdf(domain, bus, slot, func)
        XendAPIStore.get(ppci_ref, "PPCI").destroy()

        self.save_PPCIs()


    def add_PSCSI(self, add_HCTL):
        saved_pscsis = self.state_store.load_state('pscsi')
        saved_pscsi_table = {}
        if saved_pscsis:
            for saved_uuid, saved_record in saved_pscsis.items():
                try:
                    saved_pscsi_table[saved_record['scsi_id']] = saved_uuid
                except KeyError:
                    pass

        saved_pscsi_HBAs = self.state_store.load_state('pscsi_HBA')
        saved_pscsi_HBA_table = {}
        if saved_pscsi_HBAs:
            for saved_HBA_uuid, saved_HBA_record in saved_pscsi_HBAs.items():
                try:
                    physical_host = int(saved_HBA_record['physical_host'])
                    saved_pscsi_HBA_table[physical_host] = saved_HBA_uuid
                except (KeyError, ValueError):
                    pass

        # Initialise the PSCSI and the PSCSI_HBA
        pscsi_record = vscsi_util.get_scsi_device(add_HCTL)
        if pscsi_record and pscsi_record['scsi_id']:
            pscsi_uuid = saved_pscsi_table.get(pscsi_record['scsi_id'], None)
            if pscsi_uuid is None:
                physical_host = int(add_HCTL.split(':')[0])
                pscsi_HBA_uuid = saved_pscsi_HBA_table.get(physical_host, None)
                if pscsi_HBA_uuid is None:
                    pscsi_HBA_uuid = uuid.createString()
                    XendPSCSI_HBA(pscsi_HBA_uuid, {'physical_host': physical_host})
                pscsi_record['HBA'] = pscsi_HBA_uuid

                pscsi_uuid = uuid.createString()
                XendPSCSI(pscsi_uuid, pscsi_record)
                self.save_PSCSIs()
                self.save_PSCSI_HBAs()


    def remove_PSCSI(self, rem_HCTL):
        saved_pscsis = self.state_store.load_state('pscsi')
        if not saved_pscsis:
            return

        # Remove the PSCSI
        for pscsi_record in saved_pscsis.values():
            if rem_HCTL == pscsi_record['physical_HCTL']:
                pscsi_ref = XendPSCSI.get_by_HCTL(rem_HCTL)
                XendAPIStore.get(pscsi_ref, "PSCSI").destroy()
                self.save_PSCSIs()

                physical_host = int(rem_HCTL.split(':')[0])
                pscsi_HBA_ref = XendPSCSI_HBA.get_by_physical_host(physical_host)
                if pscsi_HBA_ref:
                    if not XendAPIStore.get(pscsi_HBA_ref, 'PSCSI_HBA').get_PSCSIs():
                        XendAPIStore.get(pscsi_HBA_ref, 'PSCSI_HBA').destroy()
                self.save_PSCSI_HBAs()

                return


##    def network_destroy(self, net_uuid):
 ##       del self.networks[net_uuid]
  ##      self.save_networks()


    def get_PIF_refs(self):
        log.debug(XendPIF.get_all())
        return XendPIF.get_all()

##   def _PIF_create(self, name, mtu, vlan, mac, network, persist = True,
##                     pif_uuid = None, metrics_uuid = None):
##         for pif in self.pifs.values():
##             if pif.network == network:
##                 raise NetworkAlreadyConnected(pif.uuid)

##         if pif_uuid is None:
##             pif_uuid = uuid.createString()
##         if metrics_uuid is None:
##             metrics_uuid = uuid.createString()

##         metrics = XendPIFMetrics(metrics_uuid)
##         pif = XendPIF(pif_uuid, metrics, name, mtu, vlan, mac, network, self)
##         metrics.set_PIF(pif)

##         self.pif_metrics[metrics_uuid] = metrics
##         self.pifs[pif_uuid] = pif

##         if persist:
##             self.save_PIFs()
##             self.refreshBridges()
##         return pif_uuid

##     def PIF_destroy(self, pif_uuid):
##         pif = self.pifs[pif_uuid]

##         if pif.vlan == -1:
##             raise PIFIsPhysical()

##         del self.pifs[pif_uuid]
##         self.save_PIFs()


    def get_PPCI_refs(self):
        return XendPPCI.get_all()

    def get_ppci_by_uuid(self, ppci_uuid):
        if ppci_uuid in self.get_PPCI_refs():
            return ppci_uuid
        return None


    def get_PSCSI_refs(self):
        return XendPSCSI.get_all()

    def get_pscsi_by_uuid(self, pscsi_uuid):
        if pscsi_uuid in self.get_PSCSI_refs():
            return pscsi_uuid
        return None

    def get_PSCSI_HBA_refs(self):
        return XendPSCSI_HBA.get_all()

    def get_pscsi_HBA_by_uuid(self, pscsi_HBA_uuid):
        if pscsi_HBA_uuid in self.get_PSCSI_HBA_refs():
            return pscsi_HBA_uuid
        return None


    def save(self):
        # save state
        host_record = {self.uuid: {'name_label':self.name,
                                   'name_description':self.desc,
                                   'metrics_uuid': self.host_metrics_uuid,
                                   'other_config': self.other_config}}
        self.state_store.save_state('host',host_record)
        self.state_store.save_state('cpu', self.cpus)
        self.save_PIFs()
        self.save_networks()
        self.save_PBDs()
        self.save_SRs()
        self.save_PPCIs()
        self.save_PSCSIs()
        self.save_PSCSI_HBAs()

    def save_PIFs(self):
        pif_records = dict([(pif_uuid, XendAPIStore.get(
                                 pif_uuid, "PIF").get_record())
                            for pif_uuid in XendPIF.get_all()])
        self.state_store.save_state('pif', pif_records)

    def save_networks(self):
        net_records = dict([(network_uuid, XendAPIStore.get(
                                 network_uuid, "network").get_record())
                            for network_uuid in XendNetwork.get_all()])
        self.state_store.save_state('network', net_records)

    def save_PBDs(self):
        pbd_records = dict([(pbd_uuid, XendAPIStore.get(
                                 pbd_uuid, "PBD").get_record())
                            for pbd_uuid in XendPBD.get_all()])
        self.state_store.save_state('pbd', pbd_records)

    def save_SRs(self):
        sr_records = dict([(k, v.get_record(transient = False))
                            for k, v in self.srs.items()])
        self.state_store.save_state('sr', sr_records)

    def save_PPCIs(self):
        ppci_records = dict([(ppci_uuid, XendAPIStore.get(
                                 ppci_uuid, "PPCI").get_record())
                            for ppci_uuid in XendPPCI.get_all()])
        self.state_store.save_state('ppci', ppci_records)

    def save_PSCSIs(self):
        pscsi_records = dict([(pscsi_uuid, XendAPIStore.get(
                                  pscsi_uuid, "PSCSI").get_record())
                            for pscsi_uuid in XendPSCSI.get_all()])
        self.state_store.save_state('pscsi', pscsi_records)

    def save_PSCSI_HBAs(self):
        pscsi_HBA_records = dict([(pscsi_HBA_uuid, XendAPIStore.get(
                                      pscsi_HBA_uuid, "PSCSI_HBA").get_record())
                                for pscsi_HBA_uuid in XendPSCSI_HBA.get_all()])
        self.state_store.save_state('pscsi_HBA', pscsi_HBA_records)

    def shutdown(self):
        return 0

    def reboot(self):
        return 0

    def notify(self, _):
        return 0
        
    #
    # Ref validation
    #
    
    def is_valid_host(self, host_ref):
        return (host_ref == self.uuid)

    def is_valid_cpu(self, cpu_ref):
        return (cpu_ref in self.cpus)

    def is_valid_sr(self, sr_ref):
        return (sr_ref in self.srs)

    def is_valid_vdi(self, vdi_ref):
        for sr in self.srs.values():
            if sr.is_valid_vdi(vdi_ref):
                return True
        return False

    #
    # Storage Repositories
    #

    def get_sr(self, sr_uuid):
        return self.srs.get(sr_uuid)

    def get_sr_by_type(self, sr_type):
        return [sr.uuid for sr in self.srs.values() if sr.type == sr_type]

    def get_sr_by_name(self, name):
        return [sr.uuid for sr in self.srs.values() if sr.name_label == name]

    def get_all_sr_uuid(self):
        return self.srs.keys()

    def get_vdi_by_uuid(self, vdi_uuid):
        for sr in self.srs.values():
            if sr.is_valid_vdi(vdi_uuid):
                return sr.get_vdi_by_uuid(vdi_uuid)
        return None

    def get_vdi_by_name_label(self, name):
        for sr in self.srs.values():
            vdi = sr.get_vdi_by_name_label(name)
            if vdi:
                return vdi
        return None

    def get_sr_containing_vdi(self, vdi_uuid):
        for sr in self.srs.values():
            if sr.is_valid_vdi(vdi_uuid):
                return sr
        return None
    

    #
    # Host Functions
    #

    def xen_version(self):
        info = self.xc.xeninfo()

        info = {'Xen': '%(xen_major)d.%(xen_minor)d' % info}

        # Add xend_config_format
        info.update(self.xendinfo_dict())

        # Add version info about machine
        info.update(self.nodeinfo_dict())

        # Add specific xen version info
        xeninfo_dict = self.xeninfo_dict()

        info.update({
            "xen_major":         xeninfo_dict["xen_major"],
            "xen_minor":         xeninfo_dict["xen_minor"],
            "xen_extra":         xeninfo_dict["xen_extra"],
            "cc_compiler":       xeninfo_dict["cc_compiler"],
            "cc_compile_by":     xeninfo_dict["cc_compile_by"],
            "cc_compile_domain": xeninfo_dict["cc_compile_domain"],
            "cc_compile_date":   xeninfo_dict["cc_compile_date"],
            "xen_changeset":     xeninfo_dict["xen_changeset"],
            "xen_commandline":   xeninfo_dict["xen_commandline"]
            })
        
        return info

    def get_name(self):
        return self.name

    def set_name(self, new_name):
        self.name = new_name

    def get_description(self):
        return self.desc

    def set_description(self, new_desc):
        self.desc = new_desc

    def get_uuid(self):
        return self.uuid

    def get_capabilities(self):
        return self.xc.xeninfo()['xen_caps'].split(" ")

    #
    # Host CPU Functions
    #

    def get_host_cpu_by_uuid(self, host_cpu_uuid):
        if host_cpu_uuid in self.cpus:
            return host_cpu_uuid
        raise XendError('Invalid CPU UUID')

    def get_host_cpu_refs(self):
        return self.cpus.keys()

    def get_host_cpu_uuid(self, host_cpu_ref):
        if host_cpu_ref in self.cpus:
            return host_cpu_ref
        else:
            raise XendError('Invalid CPU Reference')

    def get_host_cpu_field(self, ref, field):
        try:
            return self.cpus[ref][field]
        except KeyError:
            raise XendError('Invalid CPU Reference')

    def get_host_cpu_load(self, host_cpu_ref):
        host_cpu = self.cpus.get(host_cpu_ref)
        if not host_cpu:
            return 0.0

        vcpu = int(host_cpu['number'])
        cpu_loads = self.monitor.get_domain_vcpus_util()
        if 0 in cpu_loads and vcpu in cpu_loads[0]:
            return cpu_loads[0][vcpu]

        return 0.0

    def get_vcpus_policy(self):
        sched_id = self.xc.sched_id_get()
        if sched_id == xen.lowlevel.xc.XEN_SCHEDULER_SEDF:
            return 'sedf'
        elif sched_id == xen.lowlevel.xc.XEN_SCHEDULER_CREDIT:
            return 'credit'
        else:
            return 'unknown'

    def get_cpu_configuration(self):
        phys_info = self.physinfo_dict()

        cpu_info = {
            "nr_nodes":         phys_info["nr_nodes"],
            "nr_cpus":          phys_info["nr_cpus"],
            "cores_per_socket": phys_info["cores_per_socket"],
            "threads_per_core": phys_info["threads_per_core"]
            }

        return cpu_info
    
    #
    # Network Functions
    #
    
    def bridge_to_network(self, bridge):
        """
        Determine which network a particular bridge is attached to.

        @param bridge The name of the bridge.  If empty, the default bridge
        will be used instead (the first one in the list returned by brctl
        show); this is the behaviour of the vif-bridge script.
        @return The XendNetwork instance to which this bridge is attached.
        @raise Exception if the interface is not connected to a network.
        """
        if not bridge:
            rc, bridge = commands.getstatusoutput(
                'brctl show | cut -d "\n" -f 2 | cut -f 1')
            if rc != 0 or not bridge:
                raise Exception(
                    'Could not find default bridge, and none was specified')

        for network_uuid in XendNetwork.get_all():
            network = XendAPIStore.get(network_uuid, "network")
            if network.get_name_label() == bridge:
                return network
        else:
            raise Exception('Cannot find network for bridge %s' % bridge)

    #
    # Debug keys.
    #

    def send_debug_keys(self, keys):
        return self.xc.send_debug_keys(keys)

    #
    # Getting host information.
    #

    def info(self):
        return (self.nodeinfo() + self.physinfo() + self.xeninfo() +
                self.xendinfo())

    def nodeinfo(self):
        (sys, host, rel, ver, mch) = os.uname()
        return [['system',  sys],
                ['host',    host],
                ['release', rel],
                ['version', ver],
                ['machine', mch]]

    def list_to_rangepairs(self,cmap):
            cmap.sort()
            pairs = []
            x = y = 0
            for i in range(0,len(cmap)):
                try:
                    if ((cmap[y+1] - cmap[i]) > 1):
                        pairs.append((cmap[x],cmap[y]))
                        x = y = i+1
                    else:
                        y = y + 1
                # if we go off the end, then just add x to y
                except IndexError:
                    pairs.append((cmap[x],cmap[y]))

            return pairs

    def format_pairs(self,pairs):
            if not pairs:
                return "no cpus"
            out = ""
            for f,s in pairs:
                if (f==s):
                    out += '%d'%f
                else:
                    out += '%d-%d'%(f,s)
                out += ','
            # trim trailing ','
            return out[:-1]

    def list_to_strrange(self,list):
        return self.format_pairs(self.list_to_rangepairs(list))

    def format_node_to_cpu(self, pinfo):
        str=''
        whitespace=''
        try:
            node_to_cpu=pinfo['node_to_cpu']
            for i in range(0, pinfo['nr_nodes']):
                str+='%snode%d:%s\n' % (whitespace,
                                        i, 
                                      self.list_to_strrange(node_to_cpu[i]))
                whitespace='%25s' % ''        
        except:
            str='none\n'
        return str[:-1];
    def format_node_to_memory(self, pinfo, key):
        str=''
        whitespace=''
        try:
            node_to_memory=pinfo[key]
            for i in range(0, pinfo['nr_nodes']):
                str+='%snode%d:%d\n' % (whitespace,
                                        i,
                                        node_to_memory[i] / 1024)
                whitespace='%25s' % ''
        except:
            str='none\n'
        return str[:-1];


    def physinfo(self):
        info = self.xc.physinfo()

        info['cpu_mhz'] = info['cpu_khz'] / 1000
        
        # physinfo is in KiB, need it in MiB
        info['total_memory'] = info['total_memory'] / 1024
        info['free_memory']  = info['free_memory'] / 1024
        info['node_to_cpu']  = self.format_node_to_cpu(info)
        info['node_to_memory'] = self.format_node_to_memory(info,
					'node_to_memory')
        info['node_to_dma32_mem'] = self.format_node_to_memory(info,
					'node_to_dma32_mem')

        ITEM_ORDER = ['nr_cpus',
                      'nr_nodes',
                      'cores_per_socket',
                      'threads_per_core',
                      'cpu_mhz',
                      'hw_caps',
                      'virt_caps',
                      'total_memory',
                      'free_memory',
                      'node_to_cpu',
                      'node_to_memory',
                      'node_to_dma32_mem'
                      ]

        return [[k, info[k]] for k in ITEM_ORDER]


    def pciinfo(self):
        from xen.xend.server.pciif import get_all_assigned_pci_devices
        assigned_devs = get_all_assigned_pci_devices()

        # Each element of dev_list is a PciDevice
        dev_list = PciUtil.find_all_assignable_devices()
 
        # Each element of devs_list is a list of PciDevice
        devs_list = PciUtil.check_FLR_capability(dev_list)
 
        devs_list = PciUtil.check_mmio_bar(devs_list)
 
        # Check if the devices have been assigned to guests.
        final_devs_list = []
        for dev_list in devs_list:
            available = True
            for d in dev_list:
                if d.name in assigned_devs:
                    available = False
                    break
            if available:
                final_devs_list = final_devs_list + [dev_list]

        pci_sxp_list = []
        for dev_list in final_devs_list:
            for d in dev_list:
                pci_sxp = ['dev', ['domain', '0x%04x' % d.domain],
                                  ['bus', '0x%02x' % d.bus],
                                  ['slot', '0x%02x' % d.slot],
                                  ['func', '0x%x' % d.func]]
                pci_sxp_list.append(pci_sxp)

        return pci_sxp_list
 

    def xenschedinfo(self):
        sched_id = self.xc.sched_id_get()
        if sched_id == xen.lowlevel.xc.XEN_SCHEDULER_SEDF:
            return 'sedf'
        elif sched_id == xen.lowlevel.xc.XEN_SCHEDULER_CREDIT:
            return 'credit'
        else:
            return 'unknown'

    def xeninfo(self):
        info = self.xc.xeninfo()
        info['xen_scheduler'] = self.xenschedinfo()

        ITEM_ORDER = ['xen_major',
                      'xen_minor',
                      'xen_extra',
                      'xen_caps',
                      'xen_scheduler',
                      'xen_pagesize',
                      'platform_params',
                      'xen_changeset',
                      'xen_commandline',
                      'cc_compiler',
                      'cc_compile_by',
                      'cc_compile_domain',
                      'cc_compile_date',
                      ]

        return [[k, info[k]] for k in ITEM_ORDER]

    def xendinfo(self):
        return [['xend_config_format', 4]]

    #
    # utilisation tracking
    #

    def get_vcpu_util(self, domid, vcpuid):
        cpu_loads = self.monitor.get_domain_vcpus_util()
        if domid in cpu_loads:
            return cpu_loads[domid].get(vcpuid, 0.0)
        return 0.0

    def get_vif_util(self, domid, vifid):
        vif_loads = self.monitor.get_domain_vifs_util()
        if domid in vif_loads:
            return vif_loads[domid].get(vifid, (0.0, 0.0))
        return (0.0, 0.0)

    def get_vif_stat(self, domid, vifid):
        vif_loads = self.monitor.get_domain_vifs_stat()
        if domid in vif_loads:
            return vif_loads[domid].get(vifid, (0.0, 0.0))
        return (0.0, 0.0)

    def get_vbd_util(self, domid, vbdid):
        vbd_loads = self.monitor.get_domain_vbds_util()
        if domid in vbd_loads:
            return vbd_loads[domid].get(vbdid, (0.0, 0.0))
        return (0.0, 0.0)

    # dictionary version of *info() functions to get rid of
    # SXPisms.
    def nodeinfo_dict(self):
        return dict(self.nodeinfo())
    def xendinfo_dict(self):
        return dict(self.xendinfo())
    def xeninfo_dict(self):
        return dict(self.xeninfo())
    def physinfo_dict(self):
        return dict(self.physinfo())
    def info_dict(self):
        return dict(self.info())

    # tmem
    def tmem_list(self, cli_id, use_long):
        pool_id = -1
        subop = TMEMC_LIST
        arg1 = 32768
        arg2 = use_long
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_thaw(self, cli_id):
        pool_id = -1
        subop = TMEMC_THAW
        arg1 = 0
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_freeze(self, cli_id):
        pool_id = -1
        subop = TMEMC_FREEZE
        arg1 = 0
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_flush(self, cli_id, pages):
        pool_id = -1
        subop = TMEMC_FLUSH
        arg1 = pages
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_destroy(self, cli_id):
        pool_id = -1
        subop = TMEMC_DESTROY
        arg1 = 0
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_set_weight(self, cli_id, arg1):
        pool_id = -1
        subop = TMEMC_SET_WEIGHT
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_set_cap(self, cli_id, arg1):
        pool_id = -1
        subop = TMEMC_SET_CAP
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_set_compress(self, cli_id, arg1):
        pool_id = -1
        subop = TMEMC_SET_COMPRESS
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_query_freeable_mb(self):
        pool_id = -1
        cli_id = -1
        subop = TMEMC_QUERY_FREEABLE_MB
        arg1 = 0
        arg2 = 0
        arg3 = 0
        buf = ''
        return self.xc.tmem_control(pool_id, subop, cli_id, arg1, arg2, arg3, buf)

    def tmem_shared_auth(self, cli_id, uuid_str, auth):
        return self.xc.tmem_auth(cli_id, uuid_str, auth)

def instance():
    global inst
    try:
        inst
    except:
        inst = XendNode()
        inst.save()
    return inst
