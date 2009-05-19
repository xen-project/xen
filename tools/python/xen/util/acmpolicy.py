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
# Copyright (C) 2006,2007 International Business Machines Corp.
# Author: Stefan Berger <stefanb@us.ibm.com>
#============================================================================

import os
import stat
import array
import struct
import shutil
import commands

# sha is deprecated as of python 2.6
try:
    from hashlib import sha1
except ImportError:
    # but hashlib was only added in python 2.5
    from sha import new as sha1

from xml.dom import minidom, Node
from xen.xend.XendLogging import log
from xen.util import xsconstants, bootloader, mkdir
from xen.util.xspolicy import XSPolicy
from xen.xend.XendError import SecurityError
import xen.util.xsm.acm.acm as security
from xen.util.xsm.xsm import XSMError
from xen.xend import XendOptions

ACM_POLICIES_DIR = security.policy_dir_prefix + "/"

# Constants needed for generating a binary policy from its XML
# representation
ACM_POLICY_VERSION = 4  # Latest one
ACM_CHWALL_VERSION = 1

ACM_STE_VERSION = 1

ACM_MAGIC = 0x001debc;

ACM_NULL_POLICY = 0
ACM_CHINESE_WALL_POLICY = 1
ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY = 2
ACM_POLICY_UNDEFINED = 15


ACM_LABEL_UNLABELED = "__UNLABELED__"
ACM_LABEL_UNLABELED_DISPLAY = "unlabeled"

"""
   Error codes reported in when trying to test for a new policy
   These error codes are reported in an array of tuples where
   each error code is followed by a parameter describing the error
   more closely, such as a domain id.
"""
ACM_EVTCHN_SHARING_VIOLATION = 0x100
ACM_GNTTAB_SHARING_VIOLATION = 0x101
ACM_DOMAIN_LOOKUP            = 0x102
ACM_CHWALL_CONFLICT          = 0x103
ACM_SSIDREF_IN_USE           = 0x104


DEFAULT_policy = \
"<?xml version=\"1.0\" ?>\n" +\
"<SecurityPolicyDefinition xmlns=\"http://www.ibm.com\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.ibm.com ../../security_policy.xsd\">\n" +\
"  <PolicyHeader>\n" +\
"    <PolicyName>DEFAULT</PolicyName>\n" +\
"    <Version>1.0</Version>\n" +\
"  </PolicyHeader>\n" +\
"  <SimpleTypeEnforcement>\n" +\
"    <SimpleTypeEnforcementTypes>\n" +\
"      <Type>SystemManagement</Type>\n" +\
"      <Type>__UNLABELED__</Type>\n" +\
"    </SimpleTypeEnforcementTypes>\n" +\
"  </SimpleTypeEnforcement>\n" +\
"  <ChineseWall>\n" +\
"    <ChineseWallTypes>\n" +\
"      <Type>SystemManagement</Type>\n" +\
"    </ChineseWallTypes>\n" +\
"  </ChineseWall>\n" +\
"  <SecurityLabelTemplate>\n" +\
"    <SubjectLabels bootstrap=\"SystemManagement\">\n" +\
"      <VirtualMachineLabel>\n" +\
"        <Name%s>SystemManagement</Name>\n" +\
"        <SimpleTypeEnforcementTypes>\n" +\
"          <Type>SystemManagement</Type>\n" +\
"          <Type>__UNLABELED__</Type>\n" +\
"        </SimpleTypeEnforcementTypes>\n" +\
"        <ChineseWallTypes>\n" +\
"          <Type/>\n" +\
"        </ChineseWallTypes>\n" +\
"      </VirtualMachineLabel>\n" +\
"      <VirtualMachineLabel>\n" +\
"        <Name>__UNLABELED__</Name>\n" +\
"        <SimpleTypeEnforcementTypes>\n" +\
"          <Type>__UNLABELED__</Type>\n" +\
"        </SimpleTypeEnforcementTypes>\n" +\
"        <ChineseWallTypes>\n" +\
"          <Type/>\n" +\
"        </ChineseWallTypes>\n" +\
"      </VirtualMachineLabel>\n" +\
"    </SubjectLabels>\n" +\
"    <ObjectLabels>\n" +\
"      <ResourceLabel>\n" +\
"        <Name>__UNLABELED__</Name>\n" +\
"        <SimpleTypeEnforcementTypes>\n" +\
"          <Type>__UNLABELED__</Type>\n" +\
"        </SimpleTypeEnforcementTypes>\n" +\
"      </ResourceLabel>\n" +\
"    </ObjectLabels>\n" +\
"  </SecurityLabelTemplate>\n" +\
"</SecurityPolicyDefinition>\n"

ACM_SCHEMA="""<?xml version="1.0" encoding="UTF-8"?>
<!-- Author: Ray Valdez, Reiner Sailer {rvaldez,sailer}@us.ibm.com -->
<!--         This file defines the schema, which is used to define -->
<!--         the security policy and the security labels in Xen.    -->

<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" targetNamespace="http://www.ibm.com" xmlns="http://www.ibm.com" elementFormDefault="qualified">
	<xsd:element name="SecurityPolicyDefinition">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element ref="PolicyHeader" minOccurs="1" maxOccurs="1"></xsd:element>
				<xsd:element ref="SimpleTypeEnforcement" minOccurs="0" maxOccurs="1"></xsd:element>
				<xsd:element ref="ChineseWall" minOccurs="0" maxOccurs="1"></xsd:element>
				<xsd:element ref="SecurityLabelTemplate" minOccurs="1" maxOccurs="1"></xsd:element>
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="PolicyHeader">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element name="PolicyName" minOccurs="1" maxOccurs="1" type="xsd:string"></xsd:element>
				<xsd:element name="PolicyUrl" minOccurs="0" maxOccurs="1" type="xsd:string"></xsd:element>
				<xsd:element name="Reference" type="xsd:string" minOccurs="0" maxOccurs="1" />
				<xsd:element name="Date" minOccurs="0" maxOccurs="1" type="xsd:string"></xsd:element>
				<xsd:element name="NameSpaceUrl" minOccurs="0" maxOccurs="1" type="xsd:string"></xsd:element>
				<xsd:element name="Version" minOccurs="1" maxOccurs="1" type="VersionFormat"/>
				<xsd:element ref="FromPolicy" minOccurs="0" maxOccurs="1"/>
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="ChineseWall">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element ref="ChineseWallTypes" minOccurs="1" maxOccurs="1" />
				<xsd:element ref="ConflictSets" minOccurs="0" maxOccurs="1" />
			</xsd:sequence>
			<xsd:attribute name="priority" type="PolicyOrder" use="optional"></xsd:attribute>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="SimpleTypeEnforcement">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element ref="SimpleTypeEnforcementTypes" />
			</xsd:sequence>
			<xsd:attribute name="priority" type="PolicyOrder" use="optional"></xsd:attribute>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="SecurityLabelTemplate">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element name="SubjectLabels" minOccurs="0" maxOccurs="1">
					<xsd:complexType>
						<xsd:sequence>
							<xsd:element ref="VirtualMachineLabel" minOccurs="1" maxOccurs="unbounded"></xsd:element>
						</xsd:sequence>
						<xsd:attribute name="bootstrap" type="xsd:string" use="required"></xsd:attribute>
					</xsd:complexType>
				</xsd:element>
				<xsd:element name="ObjectLabels" minOccurs="0" maxOccurs="1">
					<xsd:complexType>
						<xsd:sequence>
							<xsd:element ref="ResourceLabel" minOccurs="1" maxOccurs="unbounded"></xsd:element>
						</xsd:sequence>
					</xsd:complexType>
				</xsd:element>
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="ChineseWallTypes">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element maxOccurs="unbounded" minOccurs="1" ref="Type" />
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="ConflictSets">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element maxOccurs="unbounded" minOccurs="1" ref="Conflict" />
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="SimpleTypeEnforcementTypes">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element maxOccurs="unbounded" minOccurs="1" ref="Type" />
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="Conflict">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element maxOccurs="unbounded" minOccurs="1" ref="Type" />
			</xsd:sequence>
			<xsd:attribute name="name" type="xsd:string" use="required"></xsd:attribute>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="VirtualMachineLabel">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element name="Name" type="NameWithFrom"></xsd:element>
				<xsd:element ref="SimpleTypeEnforcementTypes" minOccurs="0" maxOccurs="1" />
				<xsd:element ref="ChineseWallTypes" minOccurs="0" maxOccurs="unbounded" />
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="ResourceLabel">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element name="Name" type="NameWithFrom"></xsd:element>
				<xsd:element name="SimpleTypeEnforcementTypes" type="SingleSimpleTypeEnforcementType" />
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:element name="Name" type="xsd:string" />
	<xsd:element name="Type" type="xsd:string" />
	<xsd:simpleType name="PolicyOrder">
		<xsd:restriction base="xsd:string">
			<xsd:enumeration value="PrimaryPolicyComponent"></xsd:enumeration>
		</xsd:restriction>
	</xsd:simpleType>
	<xsd:element name="FromPolicy">
		<xsd:complexType>
			<xsd:sequence>
				<xsd:element name="PolicyName" minOccurs="1" maxOccurs="1" type="xsd:string"/>
				<xsd:element name="Version" minOccurs="1" maxOccurs="1" type="VersionFormat"/>
			</xsd:sequence>
		</xsd:complexType>
	</xsd:element>
	<xsd:simpleType name="VersionFormat">
		<xsd:restriction base="xsd:string">
			<xsd:pattern value="[0-9]{1,8}.[0-9]{1,8}"></xsd:pattern>
		</xsd:restriction>
	</xsd:simpleType>
	<xsd:complexType name="NameWithFrom">
		<xsd:simpleContent>
			<xsd:extension base="xsd:string">
				<xsd:attribute name="from" type="xsd:string" use="optional"></xsd:attribute>
			</xsd:extension>
		</xsd:simpleContent>
	</xsd:complexType>
	<xsd:complexType name="SingleSimpleTypeEnforcementType">
		<xsd:sequence>
			<xsd:element maxOccurs="1" minOccurs="1" ref="Type" />
		</xsd:sequence>
	</xsd:complexType>
</xsd:schema>"""


def get_DEFAULT_policy(dom0label=""):
    fromnode = ""
    if dom0label != "":
        fromnode = " from=\"%s\"" % dom0label
    return DEFAULT_policy % fromnode

def initialize():
    xoptions = XendOptions.instance()
    basedir = xoptions.get_xend_security_path()
    policiesdir = basedir + "/policies"
    mkdir.parents(policiesdir, stat.S_IRWXU)

    instdir = security.install_policy_dir_prefix
    DEF_policy_file = "DEFAULT-security_policy.xml"

    #Install default policy.
    f = open(policiesdir + "/" + DEF_policy_file, 'w')
    if f:
        f.write(get_DEFAULT_policy())
        f.close()
    else:
        log.error("Could not write the default policy's file.")
    defpol = ACMPolicy(xml=get_DEFAULT_policy())
    defpol.compile()


class ACMPolicy(XSPolicy):
    """
     ACMPolicy class. Implements methods for getting information from
     the XML representation of the policy as well as compilation and
     loading of a policy into the HV.
    """

    def __init__(self, name=None, dom=None, ref=None, xml=None):
        if name:
            self.name = name
            try:
                self.dom = minidom.parse(self.path_from_policy_name(name))
            except Exception, e:
                raise SecurityError(-xsconstants.XSERR_XML_PROCESSING,
                                    str(e))
        elif dom:
            self.dom = dom
            self.name = self.get_name()
        elif xml:
            try:
                self.dom = minidom.parseString(xml)
            except Exception, e:
                raise SecurityError(-xsconstants.XSERR_XML_PROCESSING,
                                    str(e))
            self.name = self.get_name()
        rc = self.validate()
        if rc != xsconstants.XSERR_SUCCESS:
            raise SecurityError(rc)
        if ref:
            from xen.xend.XendXSPolicy import XendACMPolicy
            self.xendacmpolicy = XendACMPolicy(self, {}, ref)
        else:
            self.xendacmpolicy = None
        XSPolicy.__init__(self, name=self.name, ref=ref)

    def get_dom(self):
        return self.dom

    def get_name(self):
        return self.policy_dom_get_hdr_item("PolicyName")

    def get_type(self):
        return xsconstants.XS_POLICY_ACM

    def get_type_name(self):
        return xsconstants.ACM_POLICY_ID

    def __str__(self):
        return self.get_name()


    def validate(self):
        """
            validate against the policy's schema Does not fail if the
            libxml2 python lib is not installed
        """
        rc = xsconstants.XSERR_SUCCESS
        try:
            import libxml2
        except Exception, e:
            log.warn("Libxml2 python-wrapper is not installed on the system.")
            return xsconstants.XSERR_SUCCESS
        try:
            parserctxt = libxml2.schemaNewMemParserCtxt(ACM_SCHEMA,
                                                        len(ACM_SCHEMA))
            schemaparser = parserctxt.schemaParse()
            valid = schemaparser.schemaNewValidCtxt()
            doc = libxml2.parseDoc(self.toxml())
            if doc.schemaValidateDoc(valid) != 0:
                rc = -xsconstants.XSERR_BAD_XML
        except Exception, e:
            log.warn("Problem with the schema: %s" % str(e))
            rc = -xsconstants.XSERR_GENERAL_FAILURE
        if rc != xsconstants.XSERR_SUCCESS:
            log.warn("XML did not validate against schema")
        if rc == xsconstants.XSERR_SUCCESS:
            rc = self.__validate_name_and_labels()
        return rc

    def __validate_name_and_labels(self):
        """ no ':' allowed in the policy name and the labels """
        if ':' in self.get_name():
            return -xsconstants.XSERR_BAD_POLICY_NAME
        for s in self.policy_get_resourcelabel_names():
            if ':' in s:
                return -xsconstants.XSERR_BAD_LABEL
        for s in self.policy_get_virtualmachinelabel_names():
            if ':' in s:
                return -xsconstants.XSERR_BAD_LABEL
        return xsconstants.XSERR_SUCCESS


    def is_default_policy(self):
        """
           Determine whether this is the default policy
        """
        default = ['SystemManagement', ACM_LABEL_UNLABELED ]
        if self.policy_get_virtualmachinelabel_names() == default and \
           self.policy_get_bootstrap_vmlabel() == default[0] and \
           self.policy_get_stetypes_types() == default and \
           self.policy_get_stes_of_vmlabel(default[0]) == default and \
           self.policy_get_stes_of_vmlabel(default[1]) == [default[1]] and \
           self.policy_get_resourcelabel_names() == [default[1]] and \
           self.policy_get_chwall_types() == [ default[0] ] and \
           self.get_name() == "DEFAULT":
            return True
        return False

    def update(self, xml_new):
        """
            Update the policy with the new XML. The hypervisor decides
            whether the new policy can be applied.
        """
        rc = -xsconstants.XSERR_XML_PROCESSING
        errors = ""
        acmpol_old = self
        try:
            acmpol_new = ACMPolicy(xml=xml_new)
        except Exception:
            return -xsconstants.XSERR_XML_PROCESSING, errors

        vmlabel_map = acmpol_new.policy_get_vmlabel_translation_map()

        # An update requires version information in the current
        # and new policy. The version number of the current policy
        # must be the same as what is in the FromPolicy/Version node
        # in the new one and the current policy's name must be the
        # same as in FromPolicy/PolicyName
        # The default policy when it is set skips this step.
        if not acmpol_new.is_default_policy() and \
           not acmpol_old.is_default_policy():
            irc = self.__do_update_version_check(acmpol_new)
            if irc != xsconstants.XSERR_SUCCESS:
                return irc, errors

        if self.isloaded():
            newvmnames = \
                 acmpol_new.policy_get_virtualmachinelabel_names_sorted()
            oldvmnames = \
                 acmpol_old.policy_get_virtualmachinelabel_names_sorted()
            del_array = ""
            chg_array = ""

            for o in oldvmnames:
                if o not in newvmnames:
                    old_idx = oldvmnames.index(o)
                    if vmlabel_map.has_key(o):
                        #not a deletion, but a renaming
                        new = vmlabel_map[o]
                        new_idx = newvmnames.index(new)
                        chg_array += struct.pack("ii", old_idx, new_idx)
                    else:
                        del_array += struct.pack("i", old_idx)
            for v in newvmnames:
                if v in oldvmnames:
                    old_idx = oldvmnames.index(v)
                    new_idx = newvmnames.index(v)
                    if old_idx != new_idx:
                        chg_array += struct.pack("ii", old_idx, new_idx)

            # VM labels indicated in the 'from' attribute of a VM or
            # resource node but that did not exist in the old policy
            # are considered bad labels.
            bad_renamings = set(vmlabel_map.keys()) - set(oldvmnames)
            if len(bad_renamings) > 0:
                log.error("Bad VM label renamings: %s" %
                          list(bad_renamings))
                return -xsconstants.XSERR_BAD_LABEL, errors

            reslabel_map = acmpol_new.policy_get_reslabel_translation_map()
            oldresnames  = acmpol_old.policy_get_resourcelabel_names()
            bad_renamings = set(reslabel_map.keys()) - set(oldresnames)
            if len(bad_renamings) > 0:
                log.error("Bad resource label renamings: %s" %
                          list(bad_renamings))
                return -xsconstants.XSERR_BAD_LABEL, errors

            #Get binary and map from the new policy
            rc, pol_map, bin_pol = acmpol_new.policy_create_map_and_bin()
            if rc != xsconstants.XSERR_SUCCESS:
                log.error("Could not build the map and binary policy.")
                return rc, errors

            #Need to do / check the following:
            # - relabel all resources where there is a 'from' field in
            #   the policy and mark those as unlabeled where the label
            #   does not appear in the new policy anymore
            # - relabel all VMs where there is a 'from' field in the
            #   policy and mark those as unlabeled where the label
            #   does not appear in the new policy anymore; no running
            #   or paused VM may be unlabeled through this
            # - check that under the new labeling conditions the VMs
            #   still have access to their resources as before. Unlabeled
            #   resources are inaccessible. If this check fails, the
            #   update failed.
            # - Attempt changes in the hypervisor; if this step fails,
            #   roll back the relabeling of resources and VMs
            # - Commit the relabeling of resources


            rc, errors = security.change_acm_policy(bin_pol,
                                        del_array, chg_array,
                                        vmlabel_map, reslabel_map,
                                        self, acmpol_new,
                                        acmpol_new.is_default_policy())

            if rc == 0:
                # Replace the old DOM with the new one and save it
                self.dom = acmpol_new.dom
                self.compile()
                log.info("ACM policy update was successful")
        else:
            #Not loaded in HV
            self.dom = acmpol_new.dom
            rc = self.compile()
        return rc, errors

    def force_default_policy(klass, policy_ref):
        """
           Force the installation of the DEFAULT policy if for
           example no XML of the current policy is available and
           the update path with comparisons of old and new policy
           cannot be taken.
           This only succeeds if only Domain-0 is running or
           all guest have the same ssidref as Domain-0.
        """
        errors = ""

        acmpol_new = ACMPolicy(xml = get_DEFAULT_policy(), ref=policy_ref)

        from xen.lowlevel import acm
        dom0_ssidref = acm.getssid(0)
        del_array = ""
        chg_array = struct.pack("ii",
                                dom0_ssidref['ssidref'] & 0xffff,
                                0x1)

        rc, pol_map, bin_pol = acmpol_new.policy_create_map_and_bin()
        if rc != xsconstants.XSERR_SUCCESS:
            return rc, errors, acmpol_new
        rc, errors = security.hv_chg_policy(bin_pol, del_array, chg_array)
        return rc, errors, acmpol_new

    force_default_policy = classmethod(force_default_policy)

    def get_reset_policy_xml(klass):
        dom0_label = security.get_ssid(0)[1]
        return get_DEFAULT_policy(dom0_label)

    get_reset_policy_xml = classmethod(get_reset_policy_xml)

    def __do_update_version_check(self, acmpol_new):
        acmpol_old = self

        now_vers    = acmpol_old.policy_dom_get_hdr_item("Version")
        now_name    = acmpol_old.policy_dom_get_hdr_item("PolicyName")
        req_oldvers = acmpol_new.policy_dom_get_frompol_item("Version")
        req_oldname = acmpol_new.policy_dom_get_frompol_item("PolicyName")

        if now_vers == "" or \
           now_vers != req_oldvers or \
           now_name != req_oldname:
            log.info("Policy rejected: %s != %s or %s != %s" % \
                     (now_vers,req_oldvers,now_name,req_oldname))
            return -xsconstants.XSERR_VERSION_PREVENTS_UPDATE

        if not self.isVersionUpdate(acmpol_new):
            log.info("Policy rejected since new version is not an update.")
            return -xsconstants.XSERR_VERSION_PREVENTS_UPDATE

        return xsconstants.XSERR_SUCCESS


    def compareVersions(self, v1, v2):
        """
            Compare two policy versions given their tuples of major and
            minor.
            Return '0' if versions are equal, '>0' if v1 > v2 and
            '<' if v1 < v2
        """
        rc = v1[0] - v2[0]
        if rc == 0:
            rc = v1[1] - v2[1]
        return rc

    def getVersionTuple(self, item="Version"):
        v_str = self.policy_dom_get_hdr_item(item)
        return self.__convVersionToTuple(v_str)

    def get_version(self):
        return self.policy_dom_get_hdr_item("Version")

    def isVersionUpdate(self, polnew):
        if self.compareVersions(polnew.getVersionTuple(),
                                self.getVersionTuple()) > 0:
            return True
        return False

    def __convVersionToTuple(self, v_str):
        """ Convert a version string, formatted according to the scheme
            "%d.%d" into a tuple of (major, minor). Return (0,0) if the
            string is empty.
        """
        major = 0
        minor = 0
        if v_str != "":
            tmp = v_str.split(".")
            major = int(tmp[0])
            if len(tmp) > 1:
                minor = int(tmp[1])
        return (major, minor)

    def get_policies_path(self):
        xoptions = XendOptions.instance()
        basedir = xoptions.get_xend_security_path()
        return basedir + "/policies/"

    def policy_path(self, name):
        prefix = self.get_policies_path()
        path = prefix + name.replace('.','/')
        _path = path.split("/")
        del _path[-1]
        mkdir.parents("/".join(_path), stat.S_IRWXU)
        return path

    def path_from_policy_name(self, name):
        return self.policy_path(name) + "-security_policy.xml"

    #
    # Functions interacting with the bootloader
    #
    def vmlabel_to_ssidref(self, vm_label):
        """ Convert a VMlabel into an ssidref given the current
            policy
            Return xsconstants.INVALID_SSIDREF if conversion failed.
        """
        ssidref = xsconstants.INVALID_SSIDREF
        names = self.policy_get_virtualmachinelabel_names_sorted()
        try:
            vmidx = names.index(vm_label)
            ssidref = (vmidx << 16) | vmidx
        except:
            pass
        return ssidref

    def set_vm_bootlabel(self, vm_label, remove=False):
        parms="<>"
        if vm_label != "":
            ssidref = self.vmlabel_to_ssidref(vm_label)
            if ssidref == xsconstants.INVALID_SSIDREF:
                return -xsconstants.XSERR_BAD_LABEL
            parms = "0x%08x:%s:%s:%s" % \
                        (ssidref, xsconstants.ACM_POLICY_ID, \
                         self.get_name(),vm_label)
        else:
            ssidref = 0 #Identifier for removal

        if remove == True:
            parms = "<>"

        try:
            def_title = bootloader.get_default_title()
            bootloader.set_kernel_attval(def_title, "ssidref", parms)
        except:
            return -xsconstants.XSERR_GENERAL_FAILURE
        return ssidref

    #
    # Utility functions related to the policy's files
    #
    def get_filename(self, postfix, prefix=None, dotted=False):
        """
           Create the filename for the policy. The prefix is prepended
           to the path. If dotted is True, then a policy name like
           'a.b.c' will remain as is, otherwise it will become 'a/b/c'
        """
        if prefix == None:
            prefix = self.get_policies_path()
        name = self.get_name()
        if name:
            p = name.split(".")
            path = ""
            if dotted:
                sep = "."
            else:
                sep = "/"
            if len(p) > 1:
                path = sep.join(p[0:len(p)-1])
            if prefix != "" or path != "":
                allpath = prefix + path + sep + p[-1] + postfix
            else:
                allpath = p[-1] + postfix
            return allpath
        return None

    def __readfile(self, name):
        cont = ""
        filename = self.get_filename(name)
        f = open(filename, "r")
        if f:
            cont = f.read()
            f.close()
        return cont

    def get_map(self):
        return self.__readfile(".map")

    def get_bin(self):
        return self.__readfile(".bin")

    def copy_policy_file(self, suffix, destdir):
        spolfile = self.get_filename(suffix)
        dpolfile = destdir + "/" + self.get_filename(suffix,"",dotted=True)
        try:
            shutil.copyfile(spolfile, dpolfile)
        except Exception, e:
            log.error("Could not copy policy file %s to %s: %s" %
                      (spolfile, dpolfile, str(e)))
            return -xsconstants.XSERR_FILE_ERROR
        return xsconstants.XSERR_SUCCESS

    #
    # DOM-related functions
    #

    def policy_dom_get(self, parent, key, createit=False):
        for node in parent.childNodes:
            if node.nodeType == Node.ELEMENT_NODE:
                if node.nodeName == key:
                    return node
        if createit:
            self.dom_create_node(parent, key)
            return self.policy_dom_get(parent, key)

    def dom_create_node(self, parent, newname, value=" "):
        xml = "<a><"+newname+">"+ value +"</"+newname+"></a>"
        frag = minidom.parseString(xml)
        frag.childNodes[0].nodeType = Node.DOCUMENT_FRAGMENT_NODE
        parent.appendChild(frag.childNodes[0])
        return frag.childNodes[0]

    def dom_get_node(self, path, createit=False):
        node = None
        parts = path.split("/")
        doc = self.get_dom()
        if len(parts) > 0:
            node = self.policy_dom_get(doc.documentElement, parts[0])
            if node:
                i = 1
                while i < len(parts):
                    _node = self.policy_dom_get(node, parts[i], createit)
                    if not _node:
                        if not createit:
                            break
                        else:
                            self.dom_create_node(node, parts[i])
                            _node = self.policy_dom_get(node, parts[i])
                    node = _node
                    i += 1
        return node

    #
    # Header-related functions
    #
    def policy_dom_get_header_subnode(self, nodename):
        node = self.dom_get_node("PolicyHeader/%s" % nodename)
        return node

    def policy_dom_get_hdr_item(self, name, default=""):
        node = self.policy_dom_get_header_subnode(name)
        if node and len(node.childNodes) > 0:
            return node.childNodes[0].nodeValue
        return default

    def policy_dom_get_frompol_item(self, name, default="", createit=False):
        node = self.dom_get_node("PolicyHeader/FromPolicy",createit)
        if node:
            node = self.policy_dom_get(node, name, createit)
            if node and len(node.childNodes) > 0:
                return node.childNodes[0].nodeValue
        return default

    def get_header_fields_map(self):
        header = {
          'policyname'   : self.policy_dom_get_hdr_item("PolicyName"),
          'policyurl'    : self.policy_dom_get_hdr_item("PolicyUrl"),
          'reference'    : self.policy_dom_get_hdr_item("Reference"),
          'date'         : self.policy_dom_get_hdr_item("Date"),
          'namespaceurl' : self.policy_dom_get_hdr_item("NameSpaceUrl"),
          'version'      : self.policy_dom_get_hdr_item("Version")
        }
        return header

    def set_frompolicy_name(self, name):
        """ For tools to adapt the header of the policy """
        node = self.dom_get_node("PolicyHeader/FromPolicy/PolicyName",
                                 createit=True)
        node.childNodes[0].nodeValue = name

    def set_frompolicy_version(self, version):
        """ For tools to adapt the header of the policy """
        node = self.dom_get_node("PolicyHeader/FromPolicy/Version",
                                 createit=True)
        node.childNodes[0].nodeValue = version

    def set_policy_name(self, name):
        """ For tools to adapt the header of the policy """
        node = self.dom_get_node("PolicyHeader/PolicyName")
        node.childNodes[0].nodeValue = name

    def set_policy_version(self, version):
        """ For tools to adapt the header of the policy """
        node = self.dom_get_node("PolicyHeader/Version")
        node.childNodes[0].nodeValue = version

    def update_frompolicy(self, curpol):
        self.set_frompolicy_name(curpol.policy_dom_get_hdr_item("PolicyName"))
        version = curpol.policy_dom_get_hdr_item("Version")
        self.set_frompolicy_version(version)
        (maj, minor) = self.__convVersionToTuple(version)
        self.set_policy_version("%s.%s" % (maj, minor+1))

    #
    # Get all types that are part of a node
    #

    def policy_get_types(self, node):
        strings = []
        i = 0
        while i < len(node.childNodes):
            if node.childNodes[i].nodeName == "Type" and \
               len(node.childNodes[i].childNodes) > 0:
                strings.append(node.childNodes[i].childNodes[0].nodeValue)
            i += 1
        return strings

    #
    # Simple Type Enforcement-related functions
    #

    def policy_get_stetypes_node(self):
        node = self.dom_get_node("SimpleTypeEnforcement/SimpleTypeEnforcementTypes")
        return node

    def policy_get_stetypes_types(self):
        strings = []
        node = self.policy_get_stetypes_node()
        if node:
            strings = self.policy_get_types(node)
        return strings

    #
    # Chinese Wall Type-related functions
    #

    def policy_get_chwall_types(self):
        strings = []
        node = self.dom_get_node("ChineseWall/ChineseWallTypes")
        if node:
            strings = self.policy_get_types(node)
        return strings

    def policy_get_chwall_cfses(self):
        cfs = []
        node = self.dom_get_node("ChineseWall/ConflictSets")
        if node:
            i = 0
            while i < len(node.childNodes):
                _cfs = {}
                if node.childNodes[i].nodeName == "Conflict":
                    _cfs['name']  = node.childNodes[i].getAttribute('name')
                    _cfs['chws'] = self.policy_get_types(node.childNodes[i])
                    cfs.append(_cfs)
                i += 1
        return cfs

    def policy_get_chwall_cfses_names_sorted(self):
        """
           Return the list of all conflict set names in alphabetical
           order.
        """
        cfs_names = []
        node = self.dom_get_node("ChineseWall/ConflictSets")
        if node:
            i = 0
            while i < len(node.childNodes):
                if node.childNodes[i].nodeName == "Conflict":
                    n  = node.childNodes[i].getAttribute('name')
                    #it better have a name!
                    if n:
                        cfs_names.append(n)
                i += 1
        cfs_names.sort()
        return cfs_names

    #
    # Subject Label-related functions
    #

    def policy_get_bootstrap_vmlabel(self):
        node = self.dom_get_node("SecurityLabelTemplate/SubjectLabels")
        if node:
            vmlabel = node.getAttribute("bootstrap")
        return vmlabel

    # Get the names of all virtual machine labels; returns an array
    def policy_get_virtualmachinelabel_names(self):
        strings = []
        node = self.dom_get_node("SecurityLabelTemplate/SubjectLabels")
        if node:
            i = 0
            while i < len(node.childNodes):
                if node.childNodes[i].nodeName == "VirtualMachineLabel":
                    name = self.policy_dom_get(node.childNodes[i], "Name")
                    if len(name.childNodes) > 0:
                        strings.append(name.childNodes[0].nodeValue)
                i += 1
        return strings

    def policy_sort_virtualmachinelabel_names(self, vmnames):
        bootstrap = self.policy_get_bootstrap_vmlabel()
        if bootstrap not in vmnames:
            raise SecurityError(-xsconstants.XSERR_POLICY_INCONSISTENT)
        vmnames.remove(bootstrap)
        vmnames.sort()
        vmnames.insert(0, bootstrap)
        if ACM_LABEL_UNLABELED in vmnames:
            vmnames.remove(ACM_LABEL_UNLABELED)
            vmnames.insert(0, ACM_LABEL_UNLABELED)
        return vmnames

    def policy_get_virtualmachinelabel_names_sorted(self):
        """ Get a sorted list of VMlabel names. The bootstrap VM's
            label will be the first one in that list, followed
            by an alphabetically sorted list of VM label names """
        vmnames = self.policy_get_virtualmachinelabel_names()
        res = self.policy_sort_virtualmachinelabel_names(vmnames)
        if res[0] != ACM_LABEL_UNLABELED:
            res.insert(0, ACM_LABEL_UNLABELED)
        return res

    def policy_get_virtualmachinelabels(self):
        """ Get a list of all virtual machine labels in this policy """
        res = []
        node = self.dom_get_node("SecurityLabelTemplate/SubjectLabels")
        if node:
            i = 0
            while i < len(node.childNodes):
                if node.childNodes[i].nodeName == "VirtualMachineLabel":
                    name = self.policy_dom_get(node.childNodes[i], "Name")
                    if len(name.childNodes) > 0:
                        _res = {}
                        _res['type'] = xsconstants.ACM_LABEL_VM
                        _res['name'] = name.childNodes[0].nodeValue
                        stes = self.policy_dom_get(node.childNodes[i],
                                                 "SimpleTypeEnforcementTypes")
                        if stes:
                           _res['stes'] = self.policy_get_types(stes)
                        else:
                            _res['stes'] = []
                        chws = self.policy_dom_get(node.childNodes[i],
                                                   "ChineseWallTypes")
                        if chws:
                            _res['chws'] = self.policy_get_types(chws)
                        else:
                            _res['chws'] = []
                        res.append(_res)
                i += 1
        return res

    def policy_get_stes_of_vmlabel(self, vmlabel):
        """ Get a list of all STEs of a given VMlabel """
        return self.__policy_get_stes_of_labeltype(vmlabel,
                                        "/SubjectLabels", "VirtualMachineLabel")

    def policy_get_stes_of_resource(self, reslabel):
        """ Get a list of all resources of a given VMlabel """
        return self.__policy_get_stes_of_labeltype(reslabel,
                                        "/ObjectLabels", "ResourceLabel")

    def __policy_get_stes_of_labeltype(self, label, path, labeltype):
        node = self.dom_get_node("SecurityLabelTemplate" + path)
        if node:
            i = 0
            while i < len(node.childNodes):
                if node.childNodes[i].nodeName == labeltype:
                    name = self.policy_dom_get(node.childNodes[i], "Name")
                    if len(name.childNodes) > 0 and \
                       name.childNodes[0].nodeValue == label:
                        stes = self.policy_dom_get(node.childNodes[i],
                                            "SimpleTypeEnforcementTypes")
                        if not stes:
                            return []
                        return self.policy_get_types(stes)
                i += 1
        return []

    def policy_check_vmlabel_against_reslabels(self, vmlabel, resources):
        """
           Check whether the given vmlabel is compatible with the given
           resource labels. Do this by getting all the STEs of the
           vmlabel and the STEs of the resources. Any STE type of the
           VM label must match an STE type of the resource.
        """
        vm_stes = self.policy_get_stes_of_vmlabel(vmlabel)
        if len(vm_stes) == 0:
            return False
        for res in resources:
            res_stes = self.policy_get_stes_of_resource(res)
            if len(res_stes) == 0 or \
               len( set(res_stes).intersection( set(vm_stes) ) ) == 0:
                return False
        return True

    def __policy_get_label_translation_map(self, path, labeltype):
        res = {}
        node = self.dom_get_node("SecurityLabelTemplate/" + path)
        if node:
            i = 0
            while i < len(node.childNodes):
                if node.childNodes[i].nodeName == labeltype:
                    name = self.policy_dom_get(node.childNodes[i], "Name")
                    from_name = name.getAttribute("from")
                    if from_name and len(name.childNodes) > 0:
                        res.update({from_name : name.childNodes[0].nodeValue})
                i += 1
        return res

    def policy_get_vmlabel_translation_map(self):
        """
            Get a dictionary of virtual machine mappings from their
            old VMlabel name to the new VMlabel name.
        """
        return self.__policy_get_label_translation_map("SubjectLabels",
                                                       "VirtualMachineLabel")

    def policy_get_reslabel_translation_map(self):
        """
            Get a dictionary of resource mappings from their
            old resource label name to the new resource label name.
        """
        return self.__policy_get_label_translation_map("ObjectLabels",
                                                       "ResourceLabel")

    #
    # Object Label-related functions
    #
    def policy_get_resourcelabel_names(self):
        """
            Get the names of all resource labels in an array but
            only those that actually have types
        """
        strings = []
        node = self.dom_get_node("SecurityLabelTemplate/ObjectLabels")
        if node:
            i = 0
            while i < len(node.childNodes):
                if node.childNodes[i].nodeName == "ResourceLabel":
                    name = self.policy_dom_get(node.childNodes[i], "Name")
                    stes = self.policy_dom_get(node.childNodes[i],
                                          "SimpleTypeEnforcementTypes")
                    if stes and len(name.childNodes) > 0:
                        strings.append(name.childNodes[0].nodeValue)
                i += 1
        return strings

    def policy_get_resourcelabels(self):
        """
           Get all information about all resource labels of this policy.
        """
        res = []
        node = self.dom_get_node("SecurityLabelTemplate/ObjectLabels")
        if node:
            i = 0
            while i < len(node.childNodes):
                if node.childNodes[i].nodeName == "ResourceLabel":
                    name = self.policy_dom_get(node.childNodes[i], "Name")
                    if len(name.childNodes) > 0:
                        _res = {}
                        _res['type'] = xsconstants.ACM_LABEL_RES
                        _res['name'] = name.childNodes[0].nodeValue
                        stes = self.policy_dom_get(node.childNodes[i],
                                                   "SimpleTypeEnforcementTypes")
                        if stes:
                            _res['stes'] = self.policy_get_types(stes)
                        else:
                            _res['stes'] = []
                        _res['chws'] = []
                        res.append(_res)
                i += 1
        return res


    def policy_find_reslabels_with_stetype(self, stetype):
        """
           Find those resource labels that hold a given STE type.
        """
        res = []
        reslabels = self.policy_get_resourcelabels()
        for resl in reslabels:
            if stetype in resl['stes']:
                res.append(resl['name'])
        return res


    def toxml(self):
        dom = self.get_dom()
        if dom:
            return dom.toxml()
        return None

    def hash(self):
        """ Calculate a SHA1 hash of the XML policy """
        return sha1(self.toxml())

    def save(self):
        ### Save the XML policy into a file ###
        rc = -xsconstants.XSERR_FILE_ERROR
        name = self.get_name()
        if name:
            path = self.path_from_policy_name(name)
            if path:
                f = open(path, 'w')
                if f:
                    try:
                        try:
                            f.write(self.toxml())
                            rc = 0
                        except:
                            pass
                    finally:
                        f.close()
        return rc

    def __write_to_file(self, suffix, data):
        #write the data into a file with the given suffix
        f = open(self.get_filename(suffix),"w")
        if f:
            try:
                try:
                    f.write(data)
                except Exception, e:
                    log.error("Error writing file: %s" % str(e))
                    return -xsconstants.XSERR_FILE_ERROR
            finally:
                f.close()
        else:
            return -xsconstants.XSERR_FILE_ERROR
        return xsconstants.XSERR_SUCCESS


    def compile(self):
        rc = self.save()
        if rc == 0:
            rc, mapfile, bin_pol = self.policy_create_map_and_bin()

            if rc == 0:
                try:
                    security.mapfile_lock()

                    rc = self.__write_to_file(".map", mapfile)
                    if rc != 0:
                        log.error("Error writing map file")

                finally:
                    security.mapfile_unlock()

            if rc == 0:
                rc = self.__write_to_file(".bin", bin_pol)
                if rc != 0:
                    log.error("Error writing binary policy file")
        return rc

    def loadintohv(self):
        """
            load this policy into the hypervisor
            if successful,the policy's flags will indicate that the
            policy is the one loaded into the hypervisor
        """
        if not self.isloaded():
            (ret, output) = commands.getstatusoutput(
                                   security.xensec_tool +
                                   " loadpolicy " +
                                   self.get_filename(".bin"))
            if ret != 0:
                return -xsconstants.XSERR_POLICY_LOAD_FAILED
        return xsconstants.XSERR_SUCCESS

    def isloaded(self):
        """
            Determine whether this policy is the active one.
        """
        if self.get_name() == security.get_active_policy_name():
            return True
        return False

    def destroy(self):
        """
            Destroy the policy including its binary, mapping and
            XML files.
            This only works if the policy is not the one that's loaded
        """
        if self.isloaded():
            return -xsconstants.XSERR_POLICY_LOADED
        files = [ self.get_filename(".map",""),
                  self.get_filename(".bin","") ]
        for f in files:
            try:
                os.unlink(f)
            except:
                pass
        if self.xendacmpolicy:
            self.xendacmpolicy.destroy()
        XSPolicy.destroy(self)
        return xsconstants.XSERR_SUCCESS

    def policy_get_domain_label(self, domid):
        """
           Given a domain's ID, retrieve the label it has using
           its ssidref for reverse calculation.
        """
        try:
            mgmt_dom = security.get_ssid(domid)
        except:
            return ""
        return self.policy_get_domain_label_by_ssidref(int(mgmt_dom[3]))

    def policy_get_domain_label_by_ssidref(self, ssidref):
        """ Given an ssidref, find the corresponding VM label """
        chwall_ref = ssidref & 0xffff
        try:
            allvmtypes = self.policy_get_virtualmachinelabel_names_sorted()
        except:
            return None
        return allvmtypes[chwall_ref]

    def policy_get_domain_label_formatted(self, domid):
        label = self.policy_get_domain_label(domid)
        if label == "":
            label = ACM_LABEL_UNLABELED
        return "%s:%s:%s" % (xsconstants.ACM_POLICY_ID, self.get_name(), label)

    def policy_get_domain_label_by_ssidref_formatted(self, ssidref):
        label = self.policy_get_domain_label_by_ssidref(ssidref)
        if label == "":
            return ""
        return "%s:%s:%s" % (xsconstants.ACM_POLICY_ID, self.get_name(), label)

    def policy_create_map_and_bin(self):
        """
            Create the policy's map and binary files -- compile the policy.
        """
        def roundup8(len):
            return ((len + 7) & ~7)

        rc = xsconstants.XSERR_SUCCESS
        mapfile = ""
        primpolcode = ACM_POLICY_UNDEFINED
        secpolcode  = ACM_POLICY_UNDEFINED
        unknown_ste = set()
        unknown_chw = set()
        unlabeled_ste = "__NULL_LABEL__"
        unlabeled_chw = "__NULL_LABEL__"

        rc = self.validate()
        if rc:
            return rc, "", ""

        stes = self.policy_get_stetypes_types()
        if stes:
            stes.sort()

        chws = self.policy_get_chwall_types()
        if chws:
            chws.sort()

        vms = self.policy_get_virtualmachinelabels()
        bootstrap = self.policy_get_bootstrap_vmlabel()

        vmlabels = self.policy_get_virtualmachinelabel_names_sorted()
        if bootstrap not in vmlabels:
            log.error("Bootstrap label '%s' not found among VM labels '%s'." \
                      % (bootstrap, vmlabels))
            return -xsconstants.XSERR_POLICY_INCONSISTENT, "", ""

        vms_with_chws = []
        chws_by_vm = { ACM_LABEL_UNLABELED : [] }
        for v in vms:
            if v.has_key("chws"):
                vms_with_chws.append(v["name"])
                chws_by_vm[v["name"]] = v["chws"]


        if bootstrap in vms_with_chws:
            vms_with_chws.remove(bootstrap)
            vms_with_chws.sort()
            vms_with_chws.insert(0, bootstrap)
        else:
            vms_with_chws.sort()

        if ACM_LABEL_UNLABELED in vms_with_chws:
            unlabeled_chw = ACM_LABEL_UNLABELED
            vms_with_chws.remove(ACM_LABEL_UNLABELED) ; # @1

        vms_with_stes = []
        stes_by_vm = { ACM_LABEL_UNLABELED : [] }
        for v in vms:
            if v.has_key("stes"):
                vms_with_stes.append(v["name"])
                stes_by_vm[v["name"]] = v["stes"]

        if bootstrap in vms_with_stes:
            vms_with_stes.remove(bootstrap)
            vms_with_stes.sort()
            vms_with_stes.insert(0, bootstrap)
        else:
            vms_with_stes.sort()

        if ACM_LABEL_UNLABELED in vms_with_stes:
            unlabeled_ste = ACM_LABEL_UNLABELED
            vms_with_stes.remove(ACM_LABEL_UNLABELED) ; # @2

        resnames = self.policy_get_resourcelabel_names()
        resnames.sort()
        stes_by_res = {}
        res = self.policy_get_resourcelabels()
        for r in res:
            if r.has_key("stes"):
                stes_by_res[r["name"]] = r["stes"]

        if ACM_LABEL_UNLABELED in resnames:
            resnames.remove(ACM_LABEL_UNLABELED)

        # check for duplicate labels
        if len(vmlabels) != len(set(vmlabels)) or \
           len(resnames) != len(set(resnames)) or \
           len(stes)     != len(set(stes))     or \
           len(chws)     != len(set(chws)):
            return -xsconstants.XSERR_POLICY_HAS_DUPLICATES, "", ""

        max_chw_ssids = 1 + len(vms_with_chws)
        max_chw_types = 1 + len(vms_with_chws)
        max_ste_ssids = 1 + len(vms_with_stes) + len(resnames)
        max_ste_types = 1 + len(vms_with_stes) + len(resnames)

        mapfile  = "POLICYREFERENCENAME    %s\n" % self.get_name()
        mapfile += "MAGIC                  %08x\n" % ACM_MAGIC
        mapfile += "POLICFILE              %s\n" % \
            self.path_from_policy_name(self.get_name())
        mapfile += "BINARYFILE             %s\n" % self.get_filename(".bin")
        mapfile += "MAX-CHWALL-TYPES       %08x\n" % len(chws)
        mapfile += "MAX-CHWALL-SSIDS       %08x\n" % max_chw_ssids
        mapfile += "MAX-CHWALL-LABELS      %08x\n" % max_chw_ssids
        mapfile += "MAX-STE-TYPES          %08x\n" % len(stes)
        mapfile += "MAX-STE-SSIDS          %08x\n" % max_ste_ssids
        mapfile += "MAX-STE-LABELS         %08x\n" % max_ste_ssids
        mapfile += "\n"

        if chws:
            mapfile += \
                 "PRIMARY                CHWALL\n"
            primpolcode = ACM_CHINESE_WALL_POLICY
            if stes:
                mapfile += \
                     "SECONDARY              STE\n"
            else:
                mapfile += \
                     "SECONDARY             NULL\n"
            secpolcode = ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY
        else:
            if stes:
                mapfile += \
                     "PRIMARY                STE\n"
                primpolcode = ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY
            mapfile += \
                     "SECONDARY             NULL\n"

        mapfile += "\n"

        if len(vms_with_chws) > 0:
            mapfile += \
                 "LABEL->SSID ANY CHWALL %-20s %x\n" % \
                 (unlabeled_chw, 0)
            i = 0
            for v in vms_with_chws:
                mapfile += \
                 "LABEL->SSID VM  CHWALL %-20s %x\n" % \
                  (v, i+1)
                i += 1
            mapfile += "\n"

        if len(vms_with_stes) > 0 or len(resnames) > 0:
            mapfile += \
                 "LABEL->SSID ANY STE    %-20s %08x\n" % \
                 (unlabeled_ste, 0)
            i = 0
            for v in vms_with_stes:
                mapfile += \
                 "LABEL->SSID VM  STE    %-20s %x\n" % (v, i+1)
                i += 1
            j = 0
            for r in resnames:
                mapfile += \
                 "LABEL->SSID RES STE    %-20s %x\n" % (r, j+i+1)
                j += 1
            mapfile += "\n"

        if vms_with_chws:
            mapfile += \
                 "SSID->TYPE CHWALL      %08x\n" % 0
            i = 1
            for v in vms_with_chws:
                mapfile += \
                 "SSID->TYPE CHWALL      %08x" % i
                for c in chws_by_vm[v]:
                    mapfile += " %s" % c
                mapfile += "\n"
                i += 1
            mapfile += "\n"

        if len(vms_with_stes) > 0 or len(resnames) > 0:
            mapfile += \
                 "SSID->TYPE STE         %08x\n" % 0
            i = 1
            for v in vms_with_stes:
                mapfile += \
                 "SSID->TYPE STE         %08x" % i
                for s in stes_by_vm[v]:
                    mapfile += " %s" % s
                mapfile += "\n"
                i += 1

            for r in resnames:
                mapfile += \
                 "SSID->TYPE STE         %08x" % i
                for s in stes_by_res[r]:
                    mapfile += " %s" % s
                mapfile += "\n"
                i += 1
            mapfile += "\n"

        if chws:
            i = 0
            while i < len(chws):
                mapfile += \
                 "TYPE CHWALL            %-20s %d\n" % (chws[i], i)
                i += 1
            mapfile += "\n"
        if stes:
            i = 0
            while i < len(stes):
                mapfile += \
                 "TYPE STE               %-20s %d\n" % (stes[i], i)
                i += 1
            mapfile += "\n"

        mapfile += "\n"

        # Build header with policy name
        length = roundup8(4 + len(self.get_name()) + 1)
        polname = self.get_name();
        pr_bin = struct.pack("!i", len(polname)+1)
        pr_bin += polname;
        while len(pr_bin) < length:
             pr_bin += "\x00"

        # Build chinese wall part
        vms_with_chws.insert(0, ACM_LABEL_UNLABELED)

        cfses_names = self.policy_get_chwall_cfses_names_sorted()
        cfses = self.policy_get_chwall_cfses()

        chwformat = "!iiiiiiiii"
        max_chw_cfs = len(cfses)
        chw_ssid_offset = struct.calcsize(chwformat)
        chw_confset_offset = chw_ssid_offset + \
                             2 * len(chws) * max_chw_types
        chw_running_types_offset = 0
        chw_conf_agg_offset = 0

        chw_bin = struct.pack(chwformat,
                              ACM_CHWALL_VERSION,
                              ACM_CHINESE_WALL_POLICY,
                              len(chws),
                              max_chw_ssids,
                              max_chw_cfs,
                              chw_ssid_offset,
                              chw_confset_offset,
                              chw_running_types_offset,
                              chw_conf_agg_offset)
        chw_bin_body = ""

        # VMs that are listed and their chinese walls
        for v in vms_with_chws:
            for c in chws:
                unknown_chw |= (set(chws_by_vm[v]) - set(chws))
                if c in chws_by_vm[v]:
                    chw_bin_body += struct.pack("!h",1)
                else:
                    chw_bin_body += struct.pack("!h",0)

        # Conflict sets -- they need to be processed in alphabetical order
        for cn in cfses_names:
            if cn == "" or cn is None:
                return -xsconstants.XSERR_BAD_CONFLICTSET, "", ""
            i = 0
            while i < len(cfses):
                if cfses[i]['name'] == cn:
                    conf = cfses[i]['chws']
                    break
                i += 1
            for c in chws:
                if c in conf:
                    chw_bin_body += struct.pack("!h",1)
                else:
                    chw_bin_body += struct.pack("!h",0)
            del cfses[i]

        if len(cfses) != 0:
            return -xsconstants.XSERR_BAD_CONFLICTSET, "", ""

        chw_bin += chw_bin_body

        while len(chw_bin) < roundup8(len(chw_bin)):
            chw_bin += "\x00"

        # Build STE part
        vms_with_stes.insert(0, ACM_LABEL_UNLABELED) # Took out in @2

        steformat="!iiiii"
        ste_bin = struct.pack(steformat,
                              ACM_STE_VERSION,
                              ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY,
                              len(stes),
                              max_ste_types,
                              struct.calcsize(steformat))
        ste_bin_body = ""
        if stes:
            # VMs that are listed and their STE types
            for v in vms_with_stes:
                unknown_ste |= (set(stes_by_vm[v]) - set(stes))
                for s in stes:
                    if s in stes_by_vm[v]:
                        ste_bin_body += struct.pack("!h",1)
                    else:
                        ste_bin_body += struct.pack("!h",0)
            for r in resnames:
                unknown_ste |= (set(stes_by_res[r]) - set(stes))
                for s in stes:
                    if s in stes_by_res[r]:
                        ste_bin_body += struct.pack("!h",1)
                    else:
                        ste_bin_body += struct.pack("!h",0)

        ste_bin += ste_bin_body;

        while len(ste_bin) < roundup8(len(ste_bin)):
            ste_bin += "\x00"

        #Write binary header:
        headerformat="!iiiiiiiiii20s"
        totallen_bin = struct.calcsize(headerformat) + \
                       len(pr_bin) + len(chw_bin) + len(ste_bin)
        polref_offset = struct.calcsize(headerformat)
        primpoloffset = polref_offset + len(pr_bin)
        if primpolcode == ACM_CHINESE_WALL_POLICY:
            secpoloffset = primpoloffset + len(chw_bin)
        elif primpolcode == ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY:
            secpoloffset = primpoloffset + len(ste_bin)
        else:
            secpoloffset = primpoloffset

        (major, minor) = self.getVersionTuple()
        hdr_bin = struct.pack(headerformat,
                              ACM_MAGIC,
                              ACM_POLICY_VERSION,
                              totallen_bin,
                              polref_offset,
                              primpolcode,
                              primpoloffset,
                              secpolcode,
                              secpoloffset,
                              major, minor,
                              self.hash().digest())

        all_bin = array.array('B')
        for s in [ hdr_bin, pr_bin, chw_bin, ste_bin ]:
            for c in s:
                all_bin.append(ord(c))

        log.info("Compiled policy: rc = %s" % hex(rc))
        if len(unknown_ste) > 0:
            log.info("The following STEs in VM/res labels were unknown:" \
                     " %s" % list(unknown_ste))
            rc = -xsconstants.XSERR_BAD_LABEL
        if len(unknown_chw) > 0:
            log.info("The following Ch. Wall types in labels were unknown:" \
                     " %s" % list(unknown_chw))
            rc = -xsconstants.XSERR_BAD_LABEL
        return rc, mapfile, all_bin.tostring()

    def validate_enforced_policy_hash(self):
        """ verify that the policy hash embedded in the binary policy
            that is currently enforce matches the one of the XML policy.
        """
        if self.hash().digest() != self.get_enforced_policy_hash():
            raise Exception('Policy hashes do not match')

    def get_enforced_policy_hash(self):
        binpol = self.get_enforced_binary()
        headerformat="!iiiiiiiiii20s"
        res = struct.unpack(headerformat, binpol[:60])
        if len(res) >= 11:
            return res[10]
        return None

    def get_enforced_binary(self):
        rc, binpol = security.hv_get_policy()
        if rc != 0:
            raise SecurityError(-xsconstants.XSERR_HV_OP_FAILED)
        return binpol

    get_enforced_binary = classmethod(get_enforced_binary)
