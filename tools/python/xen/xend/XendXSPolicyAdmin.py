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
import shutil

from xml.dom import minidom, Node

from xen.xend.XendLogging import log
from xen.xend import uuid
from xen.util import xsconstants, bootloader
import xen.util.xsm.acm.acm as security
from xen.util.xspolicy import XSPolicy
from xen.util.acmpolicy import ACMPolicy, initialize
from xen.xend.XendError import SecurityError


class XSPolicyAdmin:
    """ The class that handles the managed policies in the system.
        Handles adding and removing managed policies. All managed
        policies are handled using a reference (UUID) which is
        assigned to the policy by this class.
    """

    def __init__(self, maxpolicies):
        """ Create a management class for managing the system's
            policies.

            @param maxpolicies: The max. number of policies allowed
                                on the system (currently '1')
        """
        self.maxpolicies = maxpolicies
        self.policies = {}
        self.xsobjs = {}
        bootloader.init()

        if security.on() == xsconstants.XS_POLICY_ACM:
            self.__acm_init()

    def __acm_init(self):
        act_pol_name = self.get_hv_loaded_policy_name()
        initialize()

        ref = uuid.createString()
        try:
            self.xsobjs[ref] = ACMPolicy(name=act_pol_name, ref=ref)
            self.policies[ref] = (act_pol_name, xsconstants.ACM_POLICY_ID)
            self.xsobjs[ref].validate_enforced_policy_hash()
        except Exception, e:
            log.error("Could not find XML representation of policy '%s': "
                      "%s" % (act_pol_name,e))
            rc, errors, acmpol_def = ACMPolicy.force_default_policy(ref)
            if rc == xsconstants.XSERR_SUCCESS:
                self.xsobjs[ref] = acmpol_def
                self.policies[ref] = (acmpol_def.get_name(),
                                      xsconstants.ACM_POLICY_ID)
                log.info("Switched to DEFAULT policy.")

        log.debug("XSPolicyAdmin: Known policies: %s" % self.policies)


    def isXSEnabled(self):
        """ Check whether 'security' is enabled on this system.
        """
        rc = 0
        if security.on() == xsconstants.XS_POLICY_ACM:
            rc |= xsconstants.XS_POLICY_ACM
	else:
            rc |= xsconstants.XS_POLICY_FLASK
        return rc

    def add_acmpolicy_to_system(self, xmltext, flags, overwrite):
        """ Add an ACM policy's xml representation to the system. The
            policy will automatically be compiled
         flags:
          XS_INST_BOOT : make policy the one to boot the system with
                         by default; if there's a policy already installed,
                         refuse to install this policy unless its one with
                         the same name
          XS_INST_LOAD : load the policy immediately; if this does not work
                         refuse to install this policy
         overwrite:
          If any policy is installed and this is False, refuse to install
          this policy
          If flags is True, then any existing policy will be removed from
          the system and the new one will be installed
        """
        from xen.xend import XendDomain
        domains = XendDomain.instance()
        try:
            domains.domains_lock.acquire()
            return self.__add_acmpolicy_to_system(xmltext, flags, overwrite)
        finally:
            domains.domains_lock.release()

    def __add_acmpolicy_to_system(self, xmltext, flags, overwrite):
        errors = ""
        if security.on() != xsconstants.XS_POLICY_ACM:
            raise SecurityError(-xsconstants.XSERR_POLICY_TYPE_UNSUPPORTED)
        loadedpol = self.get_loaded_policy()
        if loadedpol:
            # This is meant as an update to a currently loaded policy
            if flags & xsconstants.XS_INST_LOAD == 0:
                raise SecurityError(-xsconstants.XSERR_POLICY_LOADED)

            # Remember old flags, so they can be restored if update fails
            old_flags = self.get_policy_flags(loadedpol)

            # Remove policy from bootloader in case of new name of policy
            self.rm_bootpolicy()

            rc, errors = loadedpol.update(xmltext)
            if rc == 0:
                irc = self.activate_xspolicy(loadedpol, flags)
                # policy is loaded; if setting the boot flag fails it's ok.
            else:
                old_flags = old_flags & xsconstants.XS_INST_BOOT
                log.info("OLD FLAGS TO RESTORE: %s" % str(old_flags))
                if old_flags != 0:
                    self.activate_xspolicy(loadedpol, xsconstants.XS_INST_BOOT)

            return (loadedpol, rc, errors)

        try:
            dom = minidom.parseString(xmltext.encode("utf-8"))
        except:
            raise SecurityError(-xsconstants.XSERR_BAD_XML)

        ref = uuid.createString()

        acmpol = ACMPolicy(dom=dom, ref=ref)

        #First some basic tests that do not modify anything:

        if flags & xsconstants.XS_INST_BOOT and not overwrite:
            filename = acmpol.get_filename(".bin","",dotted=True)
            if bootloader.get_default_policy != None and \
               not bootloader.loads_default_policy(filename):
                raise SecurityError(-xsconstants.XSERR_BOOTPOLICY_INSTALLED)

        if not overwrite and len(self.policies) >= self.maxpolicies:
            raise SecurityError(-xsconstants.XSERR_BOOTPOLICY_INSTALLED)

        if overwrite:
            #This should only give one key since only one policy is
            #allowed.
            keys = self.policies.keys()
            for k in keys:
                self.rm_bootpolicy()
                rc = self.rm_policy_from_system(k, force=overwrite)
                if rc != xsconstants.XSERR_SUCCESS:
                    raise SecurityError(rc)

        rc = acmpol.compile()
        if rc != 0:
            raise SecurityError(rc)

        if flags & xsconstants.XS_INST_LOAD:
            rc = acmpol.loadintohv()
            if rc != 0:
                raise SecurityError(rc)

        if flags & xsconstants.XS_INST_BOOT:
            rc = self.make_boot_policy(acmpol)
            if rc != 0:
                # If it cannot be installed due to unsupported
                # bootloader, let it be ok.
                pass

        if dom:
            new_entry = { ref : tuple([acmpol.get_name(),
                                       xsconstants.ACM_POLICY_ID]) }
            self.policies.update(new_entry)
            self.xsobjs[ref]  = acmpol
        return (acmpol, xsconstants.XSERR_SUCCESS, errors)


    def reset_acmpolicy(self):
        """
           Attempt to reset the system's policy by udating it with
           the DEFAULT policy.
        """
        from xen.xend import XendDomain
        domains = XendDomain.instance()
        try:
            domains.domains_lock.acquire()
            xml = ACMPolicy.get_reset_policy_xml()
            flags = xsconstants.XS_INST_BOOT | xsconstants.XS_INST_LOAD
            return self.__add_acmpolicy_to_system(xml, flags, True)
        finally:
            domains.domains_lock.release()


    def make_boot_policy(self, acmpol):
        if acmpol.is_default_policy():
            return xsconstants.XSERR_SUCCESS
        rc = acmpol.copy_policy_file(".bin","/boot")
        if rc != xsconstants.XSERR_SUCCESS:
            return rc

        try:
            filename = acmpol.get_filename(".bin","",dotted=True)
            if bootloader.set_default_boot_policy(filename) != True:
                return xsconstants.XSERR_BOOTPOLICY_INSTALL_ERROR
        except:
            return xsconstants.XSERR_FILE_ERROR
        return xsconstants.XSERR_SUCCESS

    def activate_xspolicy(self, xspol, flags):
        from xen.xend import XendDomain
        domains = XendDomain.instance()
        try:
            domains.domains_lock.acquire()
            return self.__activate_xspolicy(xspol, flags)
        finally:
            domains.domains_lock.release()

    def __activate_xspolicy(self, xspol, flags):
        rc = xsconstants.XSERR_SUCCESS
        if flags & xsconstants.XS_INST_LOAD:
            rc = xspol.loadintohv()
        if rc == xsconstants.XSERR_SUCCESS and \
           flags & xsconstants.XS_INST_BOOT:
            rc = self.make_boot_policy(xspol)
        if rc == xsconstants.XSERR_SUCCESS:
            rc = flags
        return rc

    def rm_policy_from_system(self, ref, force=False):
        if self.policies.has_key(ref):
            acmpol = self.xsobjs[ref]
            rc = acmpol.destroy()
            if rc == xsconstants.XSERR_SUCCESS or force:
                del self.policies[ref]
                del self.xsobjs[ref]
                rc = xsconstants.XSERR_SUCCESS
            return rc

    def rm_bootpolicy(self):
        """ Remove any (ACM) boot policy from the grub configuration file
        """
        rc = 0
        title = bootloader.get_default_title()
        if title != None:
            polnames = []
            for (k, v) in self.xsobjs.items():
                polnames.append(v.get_filename(".bin","",dotted=True))
            bootloader.rm_policy_from_boottitle(title, polnames)
        else:
            rc = -xsconstants.XSERR_NO_DEFAULT_BOOT_TITLE
        return rc

    def get_policy_flags(self, acmpol):
        """ Get the currently active flags of a policy, i.e., whether the
            system is using this policy as its boot policy for the default
            boot title.
        """
        flags = 0

        filename = acmpol.get_filename(".bin","", dotted=True)
        if bootloader.loads_default_policy(filename) or \
           acmpol.is_default_policy():
            flags |= xsconstants.XS_INST_BOOT

        if acmpol.isloaded():
            flags |= xsconstants.XS_INST_LOAD
        return flags

    def get_policies(self):
        """ Get all managed policies. """
        return self.xsobjs.values()

    def get_policies_refs(self):
        """ Get all managed policies' references. """
        return self.xsobjs.keys()

    def has_ref(self, ref):
        """ Check whether there is a policy with the given reference """
        return self.xsobjs.has_key(ref)

    def policy_from_ref(self, ref):
        """ Get the policy's object given its reference """
        if ref in self.xsobjs.keys():
            return self.xsobjs[ref]
        return None

    def ref_from_polname(self, polname):
        """ Get the reference of the policy given its name """
        ref = None
        for (k, v) in self.xsobjs.items():
            if v.get_name() == polname:
                ref = k
                break
        return ref

    def lock_policy(self, ref):
        """ get exclusive access to a policy """
        self.xsobjs[ref].grab_lock()

    def unlock_policy(self, ref):
        """ release exclusive access to a policy """
        self.xsobjs[ref].unlock()

    def get_loaded_policy(self):
        for pol in self.xsobjs.values():
            if pol.isloaded():
                return pol
        return None

    def get_hv_loaded_policy_name(self):
        return security.get_active_policy_name()

    def get_policy_by_name(self, name):
        for pol in self.xsobjs.values():
            if pol.get_name() == name:
                return pol
        return None

    def get_domain0_bootlabel(self):
        """ Get the domain0 bootlabel from the default boot title """
        title = ""
        def_title = bootloader.get_default_title()
        line = bootloader.get_kernel_val(def_title, "ssidref")
        if line:
            parms = line.split(":",1)
            if len(parms) > 1:
                title = parms[1]
        return title

    def set_domain0_bootlabel(self, xspol, label):
        """ Set the domain-0 bootlabel under the given policy. If the
            current policy is the default policy, it will remove it. """
        rm_entry = (xspol.get_name() == "DEFAULT")
        return xspol.set_vm_bootlabel(label, rm_entry)

    def rm_domain0_bootlabel(self):
        """ Remove the domain-0 bootlabel from the default boot title """
        def_title = bootloader.get_default_title()
        return bootloader.set_kernel_attval(def_title, "ssidref", None)

    def ssidref_to_vmlabel(self, ssidref):
        """ Given an ssidref, return the vmlabel under the current policy """
        vmlabel = ""
        pol = self.get_loaded_policy()
        if pol:
            vmlabel = pol.policy_get_domain_label_by_ssidref_formatted(ssidref)
        return vmlabel

    def get_stes_of_vmlabel(self, vmlabel_xapi):
        """ Get the list of STEs given a VM label in XenAPI format """
        stes = []
        loadedpol = self.get_loaded_policy()
        if loadedpol:
            tmp = vmlabel_xapi.split(":")
            if len(tmp) != 3:
                return []
            stes = loadedpol.policy_get_stes_of_vmlabel(tmp[2])
        return stes

    def get_enforced_binary(self, xstype):
        res = None
        if xstype == xsconstants.XS_POLICY_ACM:
            res = ACMPolicy.get_enforced_binary()
        return res

poladmin = None

def XSPolicyAdminInstance(maxpolicies=1):
    global poladmin
    if poladmin == None:
        poladmin = XSPolicyAdmin(maxpolicies)
    return poladmin
