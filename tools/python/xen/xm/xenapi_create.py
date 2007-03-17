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

from xen.xm.main import server
from xml.dom.minidom import parse, getDOMImplementation
from xml.dom.ext import PrettyPrint
from xml.parsers.xmlproc import xmlproc, xmlval, xmldtd
from xen.xend import sxp
from xen.xend.XendAPIConstants import XEN_API_ON_NORMAL_EXIT, \
     XEN_API_ON_CRASH_BEHAVIOUR


import sys
import os
import traceback

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
    return tag_node.nodeValue

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
        self.DEFAULT_STORAGE_REPOSITORY = [sr_ref
                  for sr_ref in server.xenapi.SR.get_all()
                  if server.xenapi.SR.get_type(sr_ref) == "local"][0]

        self.dtd = "/usr/lib/python/xen/xm/create.dtd"

    def create(self, filename=None, document=None):
        """
        Create a domain from an XML file or DOM tree
        """
        if filename is not None:
            self.check_dtd(file)
            document = parse(file)
        elif document is not None:
            self.check_dom_against_dtd(document)

        self.check_doc(document)

        vdis = document.getElementsByTagName("vdi")
        vdi_refs_dict = self.create_vdis(vdis)
        
        try:    
            vms = document.getElementsByTagName("vm")
            return self.create_vms(vms, vdi_refs_dict)
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
        """
        Check that the vif has
        either a bridge or network
        name but not both
        """
        if "bridge" in vif.attributes.keys() \
               and "network" in vif.attributes.keys():
            raise "You cannot specify both a bridge and\
                   a network name."

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

        vdi_record = {
            "name_label":       get_name_label(vdi),
            "name_description": get_name_description(vdi),
            "SR":               self.DEFAULT_STORAGE_REPOSITORY,  
            "virtual_size":     vdi.attributes["size"].value,
            "type":             vdi.attributes["type"].value,
            "shareable":        vdi.attributes["shareable"].value,
            "read_only":        vdi.attributes["read_only"].value,
            "other_config":     {"location":
                vdi.attributes["src"].value}
            }

        key = vdi.attributes["name"].value
        value = server.xenapi.VDI.create(vdi_record)
        
        return (key, value)

    def create_vms(self, vms, vdis):
        log(DEBUG, "create_vms")
        return map(lambda vm: self.create_vm(vm, vdis), vms)

    def create_vm(self, vm, vdis):
        log(DEBUG, "create_vm")

        vm_record = {
            "name_label":
                get_name_label(vm),
            "name_description":
                get_name_description(vm),
            "user_version":
                get_text_in_child_node(vm, "version"),
            "is_a_template":
                vm.attributes["is_a_template"].value,
            "auto_power_on":
                vm.attributes["auto_power_on"].value,
            "memory_static_max":
                get_child_node_attribute(vm, "memory", "static_max"),
            "memory_static_min":
                get_child_node_attribute(vm, "memory", "static_min"),
            "memory_dynamic_max":
                get_child_node_attribute(vm, "memory", "dynamic_max"),
            "memory_dynamic_min":
                get_child_node_attribute(vm, "memory", "dynamic_min"),
            "vcpus_params":
                get_child_nodes_as_dict(vm, "vcpu_param", "key", "value"),
            "vcpus_max":
                vm.attributes["vcpus_max"].value,
            "vcpus_at_startup":
                vm.attributes["vcpus_at_startup"].value,
            "actions_after_shutdown":
                vm.attributes["actions_after_shutdown"].value,
            "actions_after_reboot":
                vm.attributes["actions_after_reboot"].value,
            "actions_after_crash":
                vm.attributes["actions_after_crash"].value,
            "platform_std_VGA":
                vm.attributes["platform_std_VGA"].value,
            "platform_serial":
                vm.attributes["platform_serial"].value,
            "platform_localtime":
                vm.attributes["platform_localtime"].value,
            "platform_clock_offet":
                vm.attributes["platform_clock_offet"].value,
            "platform_enable_audio":
                vm.attributes["platform_enable_audio"].value,
            "PCI_bus":
                vm.attributes["platform_enable_audio"].value,
            "other_config":
                get_child_nodes_as_dict(vm, "other_config", "key", "value")
            }

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
                    get_child_nodes_as_dict(hvm, "boot_params", "key", "value")
                })
        try:
            vm_ref = server.xenapi.VM.create(vm_record)
        except:
            traceback.print_exc()
            sys.exit(-1)

        # Now create vbds

        vbds = vm.getElementsByTagName("vbd")

        self.create_vbds(vm_ref, vbds, vdis)

        # Now create vifs

        vifs = vm.getElementsByTagName("vif")

        self.create_vifs(vm_ref, vifs)

        return vm_ref
        
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
                vbd.attributes["bootable"].value,
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

    def create_vifs(self, vm_ref, vifs):
        log(DEBUG, "create_vifs")
        return map(lambda vif: self.create_vif(vm_ref, vif), vifs)

    def create_vif(self, vm_ref, vif):
        log(DEBUG, "create_vif")

        if "bridge" in vif.attributes.keys():
            raise "Not allowed to add by bridge just yet"
        elif "network" in vif.attributes.keys():
            network = [network_ref
                for network_ref in server.xenapi.network.get_all()
                if server.xenapi.network.get_name_label(network_ref)
                       == vif.attributes["network"].value][0]
        else:
            network = self._get_network_ref()

        vif_record = {
            "device":
                vif.attributes["device"].value,
            "network":
                network,
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
                    "qos_algorithm_param", "key", "value")
        }

        return server.xenapi.VIF.create(vif_record)

    _network_refs = []

    def _get_network_ref(self):
        try:
            return self._network_refs.pop(0)
        except IndexError:
            self._network_refs = server.xenapi.network.get_all()
            return self._network_refs.pop(0)

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
                                        if device[1][0] == "vbd"])

        vifs_sxp = map(lambda x: x[1], [device for device in devices
                                        if device[1][0] == "vif"])
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
        vm.attributes["platform_std_VGA"] = "false"
        vm.attributes["platform_serial"] = ""
        vm.attributes["platform_localtime"] = ""
        vm.attributes["platform_clock_offet"] = ""
        vm.attributes["platform_enable_audio"] = ""
        vm.attributes["PCI_bus"] = ""

        vm.attributes["vcpus_max"] \
            = str(get_child_by_name(config, "vcpus", 1))
        vm.attributes["vcpus_at_startup"] \
            = str(get_child_by_name(config, "vcpus", 1))

        # Make the name tag

        vm.appendChild(self.make_name_tag(
            get_child_by_name(config, "name"), document))

        # Make version tag

        version = document.createElement("version")
        version.appendChild(document.createTextNode("1.0"))
        vm.appendChild(version)
        
        # Make pv or hvm tag

        image = get_child_by_name(config, "image")

        if image[0] == "linux":
            pv = document.createElement("pv")
            pv.attributes["kernel"] \
                = get_child_by_name(image, "kernel", "")
            pv.attributes["bootloader"] = ""
            pv.attributes["ramdisk"] \
                = get_child_by_name(image, "ramdisk", "")
            pv.attributes["args"] \
                = "root=" + get_child_by_name(image, "root", "") \
                + " " + get_child_by_name(image, "args", "")
            pv.attributes["bootloader_args"] = ""

            vm.appendChild(pv)
        elif image[0] == "hvm":
            hvm = document.createElement("hvm")
            hvm.attributes["boot_policy"] = ""

            vm.appendChild(hvm)

        # Make memory tag

        memory = document.createElement("memory")

        memory_str = str(int(
            get_child_by_name(config, "memory"))*1024*1024)

        memory.attributes["static_min"] = memory_str
        memory.attributes["static_max"] = memory_str
        memory.attributes["dynamic_min"] = memory_str
        memory.attributes["dynamic_max"] = memory_str

        vm.appendChild(memory)

        # And now the vbds

        vbds = map(lambda vbd: self.extract_vbd(vbd, document), vbds_sxp)

        map(vm.appendChild, vbds)

        # And now the vifs

        vifs = map(lambda vif: self.extract_vif(vif, document), vifs_sxp)

        map(vm.appendChild, vifs)

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
        name = str(src.__hash__())

        vbd = document.createElement("vbd")

        vbd.attributes["name"] = "vdb" + name
        vbd.attributes["vdi"] = "vdi" + name
        vbd.attributes["mode"] \
            = get_child_by_name(vbd_sxp, "mode") != "w" \
              and "RO" or "RW"
        vbd.attributes["device"] \
            = get_child_by_name(vbd_sxp, "dev")
        vbd.attributes["bootable"] = "1"
        vbd.attributes["type"] = "disk"
        vbd.attributes["qos_algorithm_type"] = ""

        return vbd

    def extract_vdi(self, vbd_sxp, document):
        src = get_child_by_name(vbd_sxp, "uname")
        name = "vdi" + str(src.__hash__())
        path = src[src.find(":")+1:]

        vdi = document.createElement("vdi")

        vdi.attributes["src"] = src
        vdi.attributes["read_only"] \
            = (get_child_by_name(vbd_sxp, "mode") != "w") \
               and "true" or "false"
        vdi.attributes["size"] \
            = str(os.path.getsize(path))
        vdi.attributes["type"] = "system"
        vdi.attributes["shareable"] = "false"
        vdi.attributes["name"] = name

        vdi.appendChild(self.make_name_tag(name, document))

        return vdi

    def extract_vif(self, vif_sxp, document):

        vif = document.createElement("vif")

        dev = get_child_by_name(vif_sxp, "vifname", "eth0")

        vif.attributes["name"] \
            = "vif" + str(dev.__hash__())
        vif.attributes["mac"] \
            = get_child_by_name(vif_sxp, "mac", "")               
        vif.attributes["mtu"] \
            = get_child_by_name(vif_sxp, "mtu", "")  
        vif.attributes["device"] = dev
        vif.attributes["qos_algorithm_type"] = ""

        if get_child_by_name(vif_sxp, "bridge") is not None:
            vif.attributes["bridge"] \
                = get_child_by_name(vif_sxp, "bridge")
        
        return vif





