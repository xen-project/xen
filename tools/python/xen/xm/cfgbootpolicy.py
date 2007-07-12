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
# Copyright (C) 2006 International Business Machines Corp.
# Author: Reiner Sailer <sailer@us.ibm.com>
# Contributions: Stefan Berger <stefanb@us.ibm.com>
#============================================================================
"""Configuring a security policy into the boot configuration
"""

import sys
import traceback
import tempfile
import os, stat
import shutil
import string
import re
from xen.util.security import err
from xen.util.security import policy_dir_prefix, xen_title_re
from xen.util.security import boot_filename, altboot_filename
from xen.util.security import any_title_re, xen_kernel_re, any_module_re
from xen.util.security import empty_line_re, binary_name_re, policy_name_re
from xen.util import xsconstants
from xen.xm.opts import OptionError
from xen.xm import main as xm_main
from xen.xm.main import server
from xen.util.acmpolicy import ACMPolicy

def help():
    return """
    Adds a 'module' line to the Xen grub configuration file entry
    so that Xen boots with a specific access control policy. If
    boot-title is not given, then this script tries to determine
    it by looking for a title starting with \"XEN\". If there are
    multiple entries matching, then it must be called with the unique
    beginning of the title's name.\n"""

def strip_title(line):
    """
    strips whitespace left and right and cuts 'title'
    """
    s_title = string.strip(line)
    pos = string.index(s_title, "title")
    if pos >= 0:
        return s_title[pos+6:]
    else:
        return s_title


def insert_policy(boot_file, alt_boot_file, user_title, policy_name):
    """
    inserts policy binary file as last line of the grub entry
    matching the user_title or default title
    """
    if user_title:
        #replace "(" by "\(" and ")" by "\)" for matching
        user_title = string.replace(user_title, "(", "\(")
        user_title = string.replace(user_title, ")", "\)")
        user_title_re = re.compile("\s*title\s+.*%s" \
                                   % user_title, re.IGNORECASE)
    else:
        user_title_re = xen_title_re

    within_xen_title = 0
    within_xen_entry = 0
    insert_at_end_of_entry = 0
    path_prefix = ''
    this_title = ''
    extended_titles = []
    (tmp_fd, tmp_grub) = tempfile.mkstemp()
    #First check whether menu.lst exists
    if not os.path.isfile(boot_file):
        #take alternate boot file (grub.conf) instead
        boot_file = alt_boot_file
    #follow symlink since menue.lst might be linked to grub.conf
    if stat.S_ISLNK(os.lstat(boot_file)[stat.ST_MODE]):
        new_name = os.readlink(boot_file)
        if new_name[0] == "/":
            boot_file = new_name
        else:
            path = boot_file.split('/')
            path[len(path)-1] = new_name
            boot_file = '/'.join(path)
        if not os.path.exists(boot_file):
            err("Boot file \'%s\' not found." % boot_file)
    grub_fd = open(boot_file)
    for line in grub_fd:
        if user_title_re.match(line):
            this_title = strip_title(line)
            within_xen_title = 1
        elif within_xen_title and xen_kernel_re.match(line):
            insert_at_end_of_entry = 1
            #use prefix from xen.gz path for policy
            path_prefix = line.split()[1]
            idx = path_prefix.rfind('/')
            if idx >= 0:
                path_prefix = path_prefix[0:idx+1]
            else:
                path_prefix = ''
        elif any_module_re.match(line) and insert_at_end_of_entry:
            if binary_name_re.match(line):
                #delete existing policy module line
                line=''
        elif any_title_re.match(line):
            within_xen_title = 0

        if (empty_line_re.match(line) or any_title_re.match(line)) and \
            insert_at_end_of_entry:
            #newline or new title: we insert the policy module line here
            os.write(tmp_fd, "\tmodule " + path_prefix + policy_name + ".bin\n")
            extended_titles.append(this_title)
            insert_at_end_of_entry = 0
        #write the line that was read (except potential existing policy entry)
        os.write(tmp_fd, line)

    if insert_at_end_of_entry:
        #last entry, no empty line at end of file
        os.write(tmp_fd, "\tmodule " + path_prefix + policy_name + ".bin\n")
        extended_titles.append(this_title)

    #if more than one entry was changed, abort
    if len(extended_titles) > 1:
        err("Following boot entries matched: %s. \nPlease specify "
            "unique part of the boot title." % extended_titles)
    if len(extended_titles) == 0:
        err("Boot entry not found. Please specify unique part "
            "of the boot title.")

    #temp file might be destroyed when closing it, first copy it
    shutil.move(boot_file, boot_file+"_save")
    shutil.copyfile(tmp_grub, boot_file)
    os.close(tmp_fd)
    #sometimes the temp file does not disappear
    try:
        os.remove(tmp_grub)
    except:
        pass
    return extended_titles[0]

def cfgbootpolicy_xapi(policy, user_title=None):
    xstype = int(server.xenapi.XSPolicy.get_xstype())
    if xstype & xsconstants.XS_POLICY_ACM == 0:
        raise OptionError("ACM policy not supported on system.")
    if user_title:
        raise OptionError("Only the default title is supported with Xen-API.")

    policystate = server.xenapi.XSPolicy.get_xspolicy()
    if int(policystate['type']) == 0:
        print "No policy is installed."
        return

    if int(policystate['type']) != xsconstants.XS_POLICY_ACM:
        print "Unknown policy type '%s'." % policystate['type']
        return
    else:
        xml = policystate['repr']
        xs_ref = policystate['xs_ref']
        if not xml:
            OptionError("No policy installed on system?")
        acmpol = ACMPolicy(xml=xml)
        if acmpol.get_name() != policy:
            OptionError("Policy installed on system '%s' does not match the "
                        "request policy '%s'" % (acmpol.get_name(), policy))
        flags = int(policystate['flags']) | xsconstants.XS_INST_BOOT
        rc = int(server.xenapi.XSPolicy.activate_xspolicy(xs_ref, flags))
        if rc == flags:
            print "Successfully enabled the policy for having the system" \
                  " booted with."
        else:
            print "An error occurred during the operation: %s" % \
                  xsconstants.xserr2string(rc)


def main(argv):
    user_kver = None
    user_title = None
    if len(argv) == 2:
        policy = argv[1]
    elif len(argv) == 3:
        policy = argv[1]
        user_title = argv[2]
    else:
        raise OptionError('Invalid number of arguments')
    
    if not policy_name_re.match(policy):
        raise OptionError("Illegal policy name: '%s'" % policy)

    if xm_main.serverType == xm_main.SERVER_XEN_API:
        cfgbootpolicy_xapi(policy)
    else:
        policy_file = '/'.join([policy_dir_prefix] + policy.split('.'))
        src_binary_policy_file = policy_file + ".bin"
        #check if .bin exists or if policy file exists
        if not os.path.isfile(src_binary_policy_file):
            if not os.path.isfile(policy_file + "-security_policy.xml"):
                raise OptionError("Unknown policy '%s'" % policy)
            else:
                err_msg = "Cannot find binary file for policy '%s'." % policy
                err_msg += " Please use makepolicy to create binary file."
                raise OptionError(err_msg)
    
        dst_binary_policy_file = "/boot/" + policy + ".bin"
        shutil.copyfile(src_binary_policy_file, dst_binary_policy_file)
    
        entryname = insert_policy(boot_filename, altboot_filename,
                                  user_title, policy)
        print "Boot entry '%s' extended and \'%s\' copied to /boot" \
              % (entryname, policy + ".bin")

if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception, e:
        sys.stderr.write('Error: ' + str(e) + '\n')    
        sys.exit(-1)
