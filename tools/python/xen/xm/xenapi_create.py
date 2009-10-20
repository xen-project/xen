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
# Copyright (C) 2007 Tom Wilkie <tom.wilkie@gmail.com>
#============================================================================
"""Domain creation using new XenAPI
"""

from xen.xm.main import server, get_default_SR
from xml.dom.minidom import parse, getDOMImplementation
from xml.parsers.xmlproc import xmlproc, xmlval, xmldtd
from xen.xend import sxp
from xen.xend.XendAPIConstants import XEN_API_ON_NORMAL_EXIT, \
     XEN_API_ON_CRASH_BEHAVIOUR
from xen.xm.opts import OptionError
from xen.util import xsconstants
from xen.util.pci import pci_opts_list_from_sxp
from xen.util.path import SHAREDIR
import xen.util.xsm.xsm as security

import sys
import os
from os.path import join
import traceback
import re

def log(_, msg):
    #print "> " + msg
    pass

DEBUG = 0

def get_name_label(node):
    name_node = node.getElementsByTagName("name")[0]
    label_node = name_node.getElementsByTagName("label")[0]
    return " ".join([child.nodeValue for child in label_node.childNodes])

def get_name_description(node):
    name_node = node.getElementsByTagName("name")[0]
    description_node = name_node.getElementsByTagName("description")[0]
    return " ".join([child.nodeValue for child in description_node.childNodes])

def get_text_in_child_node(node, child):
    tag_node = node.getElementsByTagName(child)[0]
    return " ".join([child.nodeValue for child in tag_node.childNodes])

def get_child_node_attribute(node, child, attribute):
    tag_node = node.getElementsByTagName(child)[0]
    return tag_node.attributes[attribute].value

def get_child_nodes_as_dict(node, child_name,
                            key_attribute_name,
                            value_attribute_name):
    return dict([(child.attributes[key_attribute_name].value,
                  child.attributes[value_attribute_name].value)
                 for child in node.getElementsByTagName(child_name)])

def try_quietly(fn, *args):
    try:
        return fn(*args)
    except:
        return None

class xenapi_create:

    def __init__(self):
        self.DEFAULT_STORAGE_REPOSITORY = get_default_SR()

        self.dtd = join(SHAREDIR, "create.dtd")

    def create(self, filename=None, document=None, skipdtd=False):
        """
        Create a domain from an XML file or DOM tree
        """
        if skipdtd:
            print "Skipping DTD checks.  Dangerous!"
        
        if filename is not None:
            if not skipdtd:
                self.check_dtd(filename)
            document = parse(filename)
        elif document is not None:
            if not skipdtd:
                self.check_dom_against_dtd(document)

        self.check_doc(document)

        vdis = document.getElementsByTagName("vdi")
        vdi_refs_dict = self.create_vdis(vdis)

        networks = document.getElementsByTagName("network")
        network_refs_dict = self.create_networks(networks)
        
        try:    
            vms = document.getElementsByTagName("vm")
            return self.create_vms(vms, vdi_refs_dict, network_refs_dict)
        except Exception, exn:
            try_quietly(self.cleanup_vdis(vdi_refs_dict))
            raise exn

    # Methods to check xml file
    # try to use dtd to check where possible
    def check_dtd(self, file):
        """
        Check file against DTD.
        Use this if possible as it gives nice
        error messages
        """
        dtd = xmldtd.load_dtd(self.dtd)
        parser = xmlproc.XMLProcessor()
        parser.set_application(xmlval.ValidatingApp(dtd, parser))
        parser.dtd = dtd
        parser.ent = dtd
        parser.parse_resource(file)

    def check_dom_against_dtd(self, dom):
        """
        Check DOM again DTD.
        Doesn't give as nice error messages.
        (no location info)
        """
        dtd = xmldtd.load_dtd(self.dtd)
        app = xmlval.ValidatingApp(dtd, self)
        app.set_locator(self)
        self.dom2sax(dom, app)

    # Get errors back from ValidatingApp       
    def report_error(self, number, args=None):
        self.errors = xmlproc.errors.english
        try:
            msg = self.errors[number]
            if args != None:
                msg = msg % args
        except KeyError:
            msg = self.errors[4002] % number # Unknown err msg :-)
        print msg 
        sys.exit(-1)

    # Here for compatibility with ValidatingApp
    def get_line(self):
        return -1

    def get_column(self):
        return -1

    def dom2sax(self, dom, app):
        """
        Take a dom tree and tarverse it,
        issuing SAX calls to app.
        """
        for child in dom.childNodes:
            if child.nodeType == child.TEXT_NODE:
                data = child.nodeValue
                app.handle_data(data, 0, len(data))
            else:
                app.handle_start_tag(
                    child.nodeName,
                    self.attrs_to_dict(child.attributes))
                self.dom2sax(child, app)
                app.handle_end_tag(child.nodeName)

    def attrs_to_dict(self, attrs):
        return dict(attrs.items())     

    #
    # Checks which cannot be done with dtd
    #
    def check_doc(self, doc):
        vms = doc.getElementsByTagName("vm")
        self.check_vms(vms)

    def check_vms(self, vms):
        map(self.check_vm, vms)

    def check_vm(self, vm):
        vifs = vm.getElementsByTagName("vif")
        self.check_vifs(vifs)

    def check_vifs(self, vifs):
        map(self.check_vif, vifs)

    def check_vif(self, vif):
        pass

    # Cleanup methods here
    def cleanup_vdis(self, vdi_refs_dict):
        map(self.cleanup_vdi, vdi_refs_dict.values())

    def cleanup_vdi(self, vdi_ref):
        server.xenapi.VDI.destroy(vdi_ref)

    def cleanup_vms(self, vm_refs):
        map(self.cleanup_vm, vm_refs)

    def cleanup_vm(self, vm_ref):
        server.xenapi.VM.destroy(vm_ref)

    # Create methods here
    def create_vdis(self, vdis):
        log(DEBUG, "create_vdis")
        return dict(map(self.create_vdi, vdis))

    def create_vdi(self, vdi):
        log(DEBUG, "create_vdi")

        for ref, record in server.xenapi.VDI.get_all_records().items():
            location = record["other_config"]["location"]
            if vdi.attributes["src"].value != location:
                continue

            # Reuse the VDI because the location is same.
            key = vdi.attributes["name"].value
            return (key, ref)

        # Create a new VDI.
        vdi_record = {
            "name_label":       get_name_label(vdi),
            "name_description": get_name_description(vdi),
            "SR":               self.DEFAULT_STORAGE_REPOSITORY,  
            "virtual_size":     vdi.attributes["size"].value,
            "type":             vdi.attributes["type"].value,
            "sharable":         vdi.attributes["sharable"].value == "True",
            "read_only":        vdi.attributes["read_only"].value == "True",
            "other_config":     {"location":
                vdi.attributes["src"].value}
            }

        key = vdi.attributes["name"].value
        value = server.xenapi.VDI.create(vdi_record)
        
        return (key, value)

    def create_networks(self, networks):
        log(DEBUG, "create_networks")
        return dict(map(self.create_network, networks))

    def create_network(self, network):
        log(DEBUG, "create_network")

        network_record = {
            "name_label":       get_name_label(network),
            "name_description": get_name_description(network),
            "other_config":
                get_child_nodes_as_dict(network, "other_config",
                                        "key", "value"),
            "default_netmask":  network.attributes["default_netmask"].value,
            "default_gateway":  network.attributes["default_gateway"].value
            }

        key = network.attributes["name"].value
        value = server.xenapi.network.create(network_record)

        return (key, value)
        
    def create_vms(self, vms, vdis, networks):
        log(DEBUG, "create_vms")
        return map(lambda vm: self.create_vm(vm, vdis, networks), vms)

    def create_vm(self, vm, vdis, networks):
        log(DEBUG, "create_vm")

        vm_record = {
            "name_label":
                get_name_label(vm),
            "name_description":
                get_name_description(vm),
            "user_version":
                get_text_in_child_node(vm, "version"),
            "is_a_template":
                vm.attributes["is_a_template"].value == 'true',
            "auto_power_on":
                vm.attributes["auto_power_on"].value == 'true',
            "s3_integrity":
                vm.attributes["s3_integrity"].value,
            "superpages":
                vm.attributes["superpages"].value,
            "memory_static_max":
                get_child_node_attribute(vm, "memory", "static_max"),
            "memory_static_min":
                get_child_node_attribute(vm, "memory", "static_min"),
            "memory_dynamic_max":
                get_child_node_attribute(vm, "memory", "dynamic_max"),
            "memory_dynamic_min":
                get_child_node_attribute(vm, "memory", "dynamic_min"),
            "VCPUs_params":
                get_child_nodes_as_dict(vm, "vcpu_param", "key", "value"),
            "VCPUs_max":
                vm.attributes["vcpus_max"].value,
            "VCPUs_at_startup":
                vm.attributes["vcpus_at_startup"].value,
            "actions_after_shutdown":
                vm.attributes["actions_after_shutdown"].value,
            "actions_after_reboot":
                vm.attributes["actions_after_reboot"].value,
            "actions_after_crash":
                vm.attributes["actions_after_crash"].value,
            "platform":
                get_child_nodes_as_dict(vm, "platform", "key", "value"),
            "other_config":
                get_child_nodes_as_dict(vm, "other_config", "key", "value"),
            "PV_bootloader":
                "",
            "PV_kernel":
                "",
            "PV_ramdisk":
                "",
            "PV_args":
                "",
            "PV_bootloader_args":
                "",
            "HVM_boot_policy":
                "",
            "HVM_boot_params":
                {},
            "PCI_bus":
               ""
            }

        if vm.attributes.has_key("security_label"):
            vm_record.update({
                "security_label":
                    vm.attributes["security_label"].value
                })

        if len(vm.getElementsByTagName("pv")) > 0:
            vm_record.update({
                "PV_bootloader":
                    get_child_node_attribute(vm, "pv", "bootloader"),
                "PV_kernel":
                    get_child_node_attribute(vm, "pv", "kernel"),
                "PV_ramdisk":
                    get_child_node_attribute(vm, "pv", "ramdisk"),
                "PV_args":
                    get_child_node_attribute(vm, "pv", "args"),
                "PV_bootloader_args":
                    get_child_node_attribute(vm, "pv", "bootloader_args")
                })
        else:
            hvm = vm.getElementsByTagName("hvm")[0]
            vm_record.update({
                "HVM_boot_policy":
                    get_child_node_attribute(vm, "hvm", "boot_policy"),
                "HVM_boot_params":
                    get_child_nodes_as_dict(hvm, "boot_param", "key", "value")
                })
        try:
            vm_ref = server.xenapi.VM.create(vm_record)
        except:
            traceback.print_exc()
            sys.exit(-1)

        try:
            # Now create vbds

            vbds = vm.getElementsByTagName("vbd")

            self.create_vbds(vm_ref, vbds, vdis)

            # Now create vifs

            vifs = vm.getElementsByTagName("vif")

            self.create_vifs(vm_ref, vifs, networks)

            # Now create vtpms

            vtpms = vm.getElementsByTagName("vtpm")

            self.create_vtpms(vm_ref, vtpms)

            # Now create consoles

            consoles = vm.getElementsByTagName("console")

            self.create_consoles(vm_ref, consoles)

            # Now create pcis

            pcis = vm.getElementsByTagName("pci")

            self.create_pcis(vm_ref, pcis)

            # Now create scsis

            scsis = vm.getElementsByTagName("vscsi")

            self.create_scsis(vm_ref, scsis)

            return vm_ref
        except:
            server.xenapi.VM.destroy(vm_ref)
            raise
        
    def create_vbds(self, vm_ref, vbds, vdis):
        log(DEBUG, "create_vbds")
        return map(lambda vbd: self.create_vbd(vm_ref, vbd, vdis), vbds)

    def create_vbd(self, vm_ref, vbd, vdis):
        log(DEBUG, "create_vbd")

        vbd_record = {
            "VM":
                vm_ref,
            "VDI":
                vdis[vbd.attributes["vdi"].value],
            "device":
                vbd.attributes["device"].value,
            "bootable":
                vbd.attributes["bootable"].value == "1",
            "mode":
                vbd.attributes["mode"].value,
            "type":
                vbd.attributes["type"].value,
            "qos_algorithm_type":
                vbd.attributes["qos_algorithm_type"].value,
            "qos_algorithm_params":
                get_child_nodes_as_dict(vbd,
                  "qos_algorithm_param", "key", "value")
            }

        return server.xenapi.VBD.create(vbd_record)

    def create_vifs(self, vm_ref, vifs, networks):
        log(DEBUG, "create_vifs")
        return map(lambda vif: self.create_vif(vm_ref, vif, networks), vifs)

    def create_vif(self, vm_ref, vif, networks):
        log(DEBUG, "create_vif")

        if 'network' in vif.attributes.keys():
            network_name = vif.attributes['network'].value

            if network_name in networks.keys():
                network_uuid = networks[network_name]
            else:
                networks = dict([(record['name_label'], ref)
                                 for ref, record in
                                 server.xenapi.network.get_all_records().items()])
                if network_name in networks.keys():
                    network_uuid = networks[network_name]
                else:
                    raise OptionError("Network %s doesn't exist"
                                  % vif.attributes["network"].value)
        else:
            network_uuid = self._get_network_ref()

        vif_record = {
            "device":
                vif.attributes["device"].value,
            "network":
                network_uuid,
            "VM":
                vm_ref,
            "MAC":
                vif.attributes["mac"].value,
            "MTU":
                vif.attributes["mtu"].value,
            "qos_algorithm_type":
                vif.attributes["qos_algorithm_type"].value,
            "qos_algorithm_params":
                get_child_nodes_as_dict(vif,
                    "qos_algorithm_param", "key", "value"),
            "security_label":
                vif.attributes["security_label"].value
        }

        return server.xenapi.VIF.create(vif_record)

    _network_refs = []

    def _get_network_ref(self):
        try:
            return self._network_refs.pop(0)
        except IndexError:
            self._network_refs = server.xenapi.network.get_all()
            return self._network_refs.pop(0)

    def create_vtpms(self, vm_ref, vtpms):
        if len(vtpms) > 1:
            vtpms = [ vtpms[0] ]
        log(DEBUG, "create_vtpms")
        return map(lambda vtpm: self.create_vtpm(vm_ref, vtpm), vtpms)

    def create_vtpm(self, vm_ref, vtpm):
        vtpm_record = {
            "VM":
                vm_ref,
            "backend":
                vtpm.attributes["backend"].value
        }
        return server.xenapi.VTPM.create(vtpm_record)

    def create_consoles(self, vm_ref, consoles):
        log(DEBUG, "create_consoles")
        return map(lambda console: self.create_console(vm_ref, console),
                   consoles)

    def create_console(self, vm_ref, console):
        log(DEBUG, "create_consoles")

        console_record = {
            "VM":
                vm_ref,
            "protocol":
                console.attributes["protocol"].value,
            "other_config":
                get_child_nodes_as_dict(console,
                  "other_config", "key", "value")
            }

        return server.xenapi.console.create(console_record)

    def create_pcis(self, vm_ref, pcis):
        log(DEBUG, "create_pcis")
        return map(lambda pci: self.create_pci(vm_ref, pci), pcis)

    def create_pci(self, vm_ref, pci):
        log(DEBUG, "create_pci")

        domain = int(pci.attributes["domain"].value, 16)
        bus = int(pci.attributes["bus"].value, 16)
        slot = int(pci.attributes["slot"].value, 16)
        func = int(pci.attributes["func"].value, 16)
        name = "%04x:%02x:%02x.%01x" % (domain, bus, slot, func)

        target_ref = None
        for ppci_ref in server.xenapi.PPCI.get_all():
            if name == server.xenapi.PPCI.get_name(ppci_ref):
                target_ref = ppci_ref
                break
        if target_ref is None:
            log(DEBUG, "create_pci: pci device not found")
            return None

        dpci_record = {
            "VM":
                vm_ref,
            "PPCI":
                target_ref,
            "hotplug_slot":
                int(pci.attributes["vdevfn"].value, 16),
            "options":
                get_child_nodes_as_dict(pci,
                  "pci_opt", "key", "value"),
            "key":
                pci.attributes["key"].value
        }

        return server.xenapi.DPCI.create(dpci_record)

    def create_scsis(self, vm_ref, scsis):
        log(DEBUG, "create_scsis")
        return map(lambda scsi: self.create_scsi(vm_ref, scsi), scsis)

    def create_scsi(self, vm_ref, scsi):
        log(DEBUG, "create_scsi")

        target_ref = None
        for pscsi_ref in server.xenapi.PSCSI.get_all():
            if scsi.attributes["p-dev"].value == server.xenapi.PSCSI.get_physical_HCTL(pscsi_ref):
                target_ref = pscsi_ref
                break
        if target_ref is None:
            log(DEBUG, "create_scsi: scsi device not found")
            return None

        dscsi_record = {
            "VM":
                vm_ref,
            "PSCSI":
                target_ref,
            "virtual_HCTL":
                scsi.attributes["v-dev"].value
        }

        return server.xenapi.DSCSI.create(dscsi_record)

def get_child_by_name(exp, childname, default = None):
    try:
        return [child for child in sxp.children(exp)
                if child[0] == childname][0][1]
    except:
        return default

# Convert old sxp into new xml

class sxp2xml:

    def convert_sxp_to_xml(self, config, transient=False):
       
        devices = [child for child in sxp.children(config)
                   if len(child) > 0 and child[0] == "device"]
                   
        vbds_sxp = map(lambda x: x[1], [device for device in devices
                                        if device[1][0] in ("vbd", "tap", "tap2")])

        vifs_sxp = map(lambda x: x[1], [device for device in devices
                                        if device[1][0] == "vif"])

        vtpms_sxp = map(lambda x: x[1], [device for device in devices
                                         if device[1][0] == "vtpm"])

        vfbs_sxp = map(lambda x: x[1], [device for device in devices
                                        if device[1][0] == "vfb"])

        pcis_sxp = map(lambda x: x[1], [device for device in devices
                                        if device[1][0] == "pci"])

        scsis_sxp = map(lambda x: x[1], [device for device in devices
                                         if device[1][0] == "vscsi"])

        # Create XML Document
        
        impl = getDOMImplementation()

        document = impl.createDocument(None, "xm", None)

        # Lets make the VM tag..

        vm = document.createElement("vm")

        # Some string compatibility

        actions_after_shutdown \
            = get_child_by_name(config, "on_poweroff", "destroy")
        actions_after_reboot \
            = get_child_by_name(config, "on_reboot", "restart")
        actions_after_crash \
            = get_child_by_name(config, "on_crash", "restart")

        def conv_chk(val, vals):
            val.replace("-", "_")
            if val not in vals:
                raise "Invalid value: " + val
            else:
                return val

        actions_after_shutdown = conv_chk(actions_after_shutdown,\
                                          XEN_API_ON_NORMAL_EXIT)
        actions_after_reboot   = conv_chk(actions_after_reboot, \
                                          XEN_API_ON_NORMAL_EXIT)
        actions_after_crash    = conv_chk(actions_after_crash, \
                                          XEN_API_ON_CRASH_BEHAVIOUR)
        # Flesh out tag attributes            

        vm.attributes["is_a_template"] = "false"
        vm.attributes["auto_power_on"] = "false"
        vm.attributes["actions_after_shutdown"] \
            = actions_after_shutdown              
        vm.attributes["actions_after_reboot"] \
            = actions_after_reboot
        vm.attributes["actions_after_crash"] \
            = actions_after_crash
        vm.attributes["PCI_bus"] = ""

        vm.attributes["vcpus_max"] \
            = str(get_child_by_name(config, "vcpus", 1))
        vm.attributes["vcpus_at_startup"] \
            = str(get_child_by_name(config, "vcpus", 1))
        vm.attributes["s3_integrity"] \
            = str(get_child_by_name(config, "s3_integrity", 0))
        vm.attributes["superpages"] \
            = str(get_child_by_name(config, "superpages", 0))

        sec_data = get_child_by_name(config, "security")
        if sec_data:
            try :
                vm.attributes['security_label'] = \
                                    security.set_security_label(sec_data[0][1][1],sec_data[0][2][1])
            except Exception, e:
                raise "Invalid security data format: %s" % str(sec_data)

        # Make the name tag

        vm.appendChild(self.make_name_tag(
            get_child_by_name(config, "name"), document))

        # Make version tag

        version = document.createElement("version")
        version.appendChild(document.createTextNode("0"))
        vm.appendChild(version)
        
        # Make pv or hvm tag

        image = get_child_by_name(config, "image")

        if image[0] == "linux":
            pv = document.createElement("pv")
            pv.attributes["kernel"] \
                = get_child_by_name(image, "kernel", "")
            pv.attributes["bootloader"] \
                = get_child_by_name(config, "bootloader", "")
            pv.attributes["ramdisk"] \
                = get_child_by_name(image, "ramdisk", "")
            pv.attributes["args"] \
                = "root=" + get_child_by_name(image, "root", "") \
                + " " + get_child_by_name(image, "args", "")
            pv.attributes["bootloader_args"] \
                = get_child_by_name(config, "bootloader_args","")

            vm.appendChild(pv)
        elif image[0] == "hvm":
            hvm = document.createElement("hvm")
            hvm.attributes["boot_policy"] = "BIOS order"

            boot_order = document.createElement("boot_param")
            boot_order.attributes["key"] = "order"
            boot_order.attributes["value"] \
                = get_child_by_name(image, "boot", "abcd")
            hvm.appendChild

            vm.appendChild(hvm)

        # Make memory tag

        memory = document.createElement("memory")

        memory_str = str(int(
            get_child_by_name(config, "memory"))*1024*1024)

        memory.attributes["static_min"] = str(0)
        memory.attributes["static_max"] = memory_str
        memory.attributes["dynamic_min"] = memory_str
        memory.attributes["dynamic_max"] = memory_str

        if get_child_by_name(config, "maxmem"):
            memory.attributes["static_max"] = \
               str(int(get_child_by_name(config, "maxmem")*1024*1024))

        vm.appendChild(memory)

        # And now the vbds

        vbds = map(lambda vbd: self.extract_vbd(vbd, document), vbds_sxp)

        map(vm.appendChild, vbds)

        # And now the vifs

        vifs = map(lambda vif: self.extract_vif(vif, document), vifs_sxp)

        map(vm.appendChild, vifs)

        # And now the vTPMs

        vtpms = map(lambda vtpm: self.extract_vtpm(vtpm, document), vtpms_sxp)

        map(vm.appendChild, vtpms)

        # And now the pcis

        pcis = self.extract_pcis(pcis_sxp, document)

        map(vm.appendChild, pcis)

        # And now the scsis

        scsis = self.extract_scsis(scsis_sxp, document)

        map(vm.appendChild, scsis)

        # Last but not least the consoles...

        consoles = self.extract_consoles(image, document)

        map(vm.appendChild, consoles)

        vfbs = map(lambda vfb: self.extract_vfb(vfb, document), vfbs_sxp)

        map(vm.appendChild, vfbs)

        # Platform variables...

        platform = self.extract_platform(image, document)

        map(vm.appendChild, platform)

        # And now the vcpu_params

        vcpu_params = self.extract_vcpu_params(config, document)

        map(vm.appendChild, vcpu_params)

        # transient?

        if transient:
            other_config = document.createElement("other_config")
            other_config.attributes["key"] = "transient"
            other_config.attributes["value"] = "True"
            vm.appendChild(other_config)
        
        # Add it to doc_root

        document.documentElement.appendChild(vm)
        
        # We want to pull out vdis

        vdis = map(lambda vdb: self.extract_vdi(vdb, document), vbds_sxp)

        map(document.documentElement.appendChild, vdis)

        return document

    def make_name_tag(self, label_text, document):
        name = document.createElement("name")

        label = document.createElement("label")
        label.appendChild(document.createTextNode(str(label_text)))
        name.appendChild(label)

        description = document.createElement("description")
        description.appendChild(document.createTextNode(" "))
        name.appendChild(description)

        return name

    def extract_vbd(self, vbd_sxp, document):
        src = get_child_by_name(vbd_sxp, "uname")
        mode = get_child_by_name(vbd_sxp, "mode")
        name = str(src.__hash__())

        vbd = document.createElement("vbd")

        vbd.attributes["name"] = "vdb" + name
        vbd.attributes["vdi"] = "vdi" + name
        vbd.attributes["mode"] \
            = re.search("^w!{0,1}$", mode) and "RW" or "RO"
        vbd.attributes["device"] \
            = re.sub(":cdrom$", "", get_child_by_name(vbd_sxp, "dev"))
        vbd.attributes["bootable"] = "1"
        vbd.attributes["type"] \
            = re.search(":cdrom$", get_child_by_name(vbd_sxp, "dev")) \
              and "CD" or "disk"
        vbd.attributes["qos_algorithm_type"] = ""

        return vbd

    def extract_vdi(self, vbd_sxp, document):
        src = get_child_by_name(vbd_sxp, "uname")
        mode = get_child_by_name(vbd_sxp, "mode")
        name = "vdi" + str(src.__hash__())

        vdi = document.createElement("vdi")

        vdi.attributes["src"] = src
        vdi.attributes["read_only"] \
            = re.search("^w!{0,1}$", mode) and "False" or "True"
        vdi.attributes["size"] = '-1'
        vdi.attributes["type"] = "system"
        vdi.attributes["sharable"] \
            = re.search("^w!$", mode) and "True" or "False"
        vdi.attributes["name"] = name

        vdi.appendChild(self.make_name_tag(name, document))

        return vdi

    def extract_vif(self, vif_sxp, document):

        vif = document.createElement("vif")

        dev = get_child_by_name(vif_sxp, "vifname", None)

        if dev is None:
            dev = self.getFreshEthDevice()

        vif.attributes["name"] \
            = "vif" + str(dev.__hash__())
        vif.attributes["mac"] \
            = get_child_by_name(vif_sxp, "mac", "")               
        vif.attributes["mtu"] \
            = get_child_by_name(vif_sxp, "mtu", "")  
        vif.attributes["device"] = dev
        vif.attributes["qos_algorithm_type"] = ""

        policy = get_child_by_name(vif_sxp, "policy")
        label = get_child_by_name(vif_sxp, "label")

        vif.attributes["security_label"] = security.set_security_label(policy, label)

        if get_child_by_name(vif_sxp, "bridge") is not None:
            vif.attributes["network"] \
                = get_child_by_name(vif_sxp, "bridge")
        
        return vif

    def extract_vtpm(self, vtpm_sxp, document):

        vtpm = document.createElement("vtpm")

        vtpm.attributes["backend"] \
             = get_child_by_name(vtpm_sxp, "backend", "0")

        return vtpm

    def extract_vfb(self, vfb_sxp, document):

        vfb = document.createElement("console")
        vfb.attributes["protocol"] = "rfb"

        if get_child_by_name(vfb_sxp, "type", "") == "vnc":
            vfb.appendChild(self.mk_other_config(
                "type", "vnc",
                document))
            vfb.appendChild(self.mk_other_config(
                "vncunused", get_child_by_name(vfb_sxp, "vncunused", "1"),
                document))
            vfb.appendChild(self.mk_other_config(
                "vnclisten",
                get_child_by_name(vfb_sxp, "vnclisten", "127.0.0.1"),
                document))
            vfb.appendChild(self.mk_other_config(
                "vncdisplay", get_child_by_name(vfb_sxp, "vncdisplay", "0"),
                document))
            vfb.appendChild(self.mk_other_config(
                "vncpasswd", get_child_by_name(vfb_sxp, "vncpasswd", ""),
                document))

        if get_child_by_name(vfb_sxp, "type", "") == "sdl":
            vfb.appendChild(self.mk_other_config(
                "type", "sdl",
                document))
            vfb.appendChild(self.mk_other_config(
                "display", get_child_by_name(vfb_sxp, "display", ""),
                document))
            vfb.appendChild(self.mk_other_config(
                "xauthority",
                get_child_by_name(vfb_sxp, "xauthority", ""),
                document))
            vfb.appendChild(self.mk_other_config(
                "opengl", get_child_by_name(vfb_sxp, "opengl", "1"),
                document))

        return vfb

    def extract_pcis(self, pcis_sxp, document):

        pcis = []

        for pci_sxp in pcis_sxp:
            for dev_sxp in sxp.children(pci_sxp, "dev"):
                pci = document.createElement("pci")

                pci.attributes["domain"] \
                    = get_child_by_name(dev_sxp, "domain", "0")
                pci.attributes["bus"] \
                    = get_child_by_name(dev_sxp, "bus", "0")
                pci.attributes["slot"] \
                    = get_child_by_name(dev_sxp, "slot", "0")
                pci.attributes["func"] \
                    = get_child_by_name(dev_sxp, "func", "0")
                pci.attributes["vdevfn"] \
                    = get_child_by_name(dev_sxp, "vdevfn", "0")
                pci.attributes["key"] \
                    = get_child_by_name(dev_sxp, "key", "0")
                for opt in pci_opts_list_from_sxp(dev_sxp):
                    pci_opt = document.createElement("pci_opt")
                    pci_opt.attributes["key"] = opt[0]
                    pci_opt.attributes["value"] = opt[1]
                    pci.appendChild(pci_opt)

                pcis.append(pci)

        return pcis

    def extract_scsis(self, scsis_sxp, document):

        scsis = []

        for scsi_sxp in scsis_sxp:
            for dev_sxp in sxp.children(scsi_sxp, "dev"):
                scsi = document.createElement("vscsi")

                scsi.attributes["p-dev"] \
                    = get_child_by_name(dev_sxp, "p-dev")
                scsi.attributes["v-dev"] \
                    = get_child_by_name(dev_sxp, "v-dev")

                scsis.append(scsi)

        return scsis

    def mk_other_config(self, key, value, document):
        other_config = document.createElement("other_config")
        other_config.attributes["key"] = key
        other_config.attributes["value"] = value
        return other_config

    def extract_consoles(self, image, document):
        consoles = []

        if int(get_child_by_name(image, "nographic", "1")) == 1:
            return consoles
        
        if int(get_child_by_name(image, "vnc", "0")) == 1:
            console = document.createElement("console")
            console.attributes["protocol"] = "rfb"
            console.appendChild(self.mk_other_config(
                "type", "vnc",
                document))
            console.appendChild(self.mk_other_config(
                "vncunused", str(get_child_by_name(image, "vncunused", "1")),
                document))
            console.appendChild(self.mk_other_config(
                "vnclisten",
                get_child_by_name(image, "vnclisten", "127.0.0.1"),
                document))
            console.appendChild(self.mk_other_config(
                "vncdisplay", str(get_child_by_name(image, "vncdisplay", "0")),
                document))
            console.appendChild(self.mk_other_config(
                "vncpasswd", get_child_by_name(image, "vncpasswd", ""),
                document))
            consoles.append(console)          
        if int(get_child_by_name(image, "sdl", "0")) == 1:
            console = document.createElement("console")
            console.attributes["protocol"] = "rfb"
            console.appendChild(self.mk_other_config(
                "type", "sdl",
                document))
            console.appendChild(self.mk_other_config(
                "display", get_child_by_name(image, "display", ""),
                document))
            console.appendChild(self.mk_other_config(
                "xauthority", get_child_by_name(image, "xauthority", ""),
                document))
            console.appendChild(self.mk_other_config(
                "opengl", str(get_child_by_name(image, "opengl", "1")),
                document))
            consoles.append(console)
            
        return consoles


    def extract_platform(self, image, document):

        platform_keys = [
            'acpi',
            'apic',
            'boot',
            'device_model',
            'loader',
            'fda',
            'fdb',
            'keymap',
            'isa',
            'localtime',
            'monitor',
            'pae',
            'rtc_timeoffset',
            'serial',
            'soundhw',
            'stdvga',
            'usb',
            'usbdevice',
            'hpet',
            'timer_mode',
            'vpt_align',
            'viridian',
            'vhpt',
            'guest_os_type',
            'hap',
            'oos',
            'pci_msitranslate',
            'pci_power_mgmt',
            'xen_platform_pci',
            'tsc_native'
            'description',
            'nomigrate'
        ]

        platform_configs = []
        for key in platform_keys:
            value = get_child_by_name(image, key, None)
            if value is not None:
                platform = document.createElement("platform")
                platform.attributes["key"] = key
                platform.attributes["value"] = str(value)
                platform_configs.append(platform)
 
        return platform_configs

    def extract_vcpu_params(self, config, document):
        vcpu_params = []

        vcpu_param = document.createElement("vcpu_param")
        vcpu_param.attributes["key"] = "weight"
        vcpu_param.attributes["value"] \
            = str(get_child_by_name(config, "cpu_weight", 256))
        vcpu_params.append(vcpu_param)

        vcpu_param = document.createElement("vcpu_param")
        vcpu_param.attributes["key"] = "cap"
        vcpu_param.attributes["value"] \
            = str(get_child_by_name(config, "cpu_cap", 0))
        vcpu_params.append(vcpu_param)

        cpus = get_child_by_name(config, "cpus", [])
        if type(cpus) == list:
            vcpu = 0
            for cpu in cpus:
                if cpu:
                    vcpu_param = document.createElement("vcpu_param")
                    vcpu_param.attributes["key"] = "cpumap%i" % vcpu
                    vcpu_param.attributes["value"] = str(cpu)
                    vcpu_params.append(vcpu_param)
                vcpu = vcpu + 1
        else:
            for vcpu in range(0, int(get_child_by_name(config, "vcpus", 1))):
                vcpu_param = document.createElement("vcpu_param")
                vcpu_param.attributes["key"] = "cpumap%i" % vcpu
                vcpu_param.attributes["value"] = str(cpus)
                vcpu_params.append(vcpu_param)

        return vcpu_params
    
    _eths = -1

    def getFreshEthDevice(self):
        self._eths += 1
        return "eth%i" % self._eths
