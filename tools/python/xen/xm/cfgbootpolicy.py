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
#============================================================================
"""Configuring a security policy into the boot configuration
"""

import sys
import traceback
import tempfile
import os, stat
import re
import commands
import shutil
import string
from xen.util.security import ACMError, err
from xen.util.security import policy_dir_prefix, boot_filename, xen_title_re
from xen.util.security import any_title_re, xen_kernel_re, kernel_ver_re, any_module_re
from xen.util.security import empty_line_re, binary_name_re, policy_name_re


def usage():
    print "\nUsage: xm cfgbootpolicy <policy> [<kernelversion>]\n"
    print "  Adds a 'module' line to the Xen grub.conf entry"
    print "  so that xen boots into a specific access control"
    print "  policy. If kernelversion is not given, then this"
    print "  script tries to determine it by looking for a grub"
    print "  entry with a line kernel xen.* If there are multiple"
    print "  Xen entries, then it must be called with an explicit"
    print "  version (it will fail otherwise).\n"
    err("Usage")



def determine_kernelversion(user_specified):
    within_xen_title = 0
    within_xen_entry = 0
    version_list = []
    guess_version = None

    grub_fd = open(boot_filename)
    for line in grub_fd:
        if xen_title_re.match(line):
            within_xen_title = 1
        elif within_xen_title and xen_kernel_re.match(line):
            within_xen_entry = 1
        elif within_xen_title and within_xen_entry and kernel_ver_re.match(line):
            for i in line.split():
                if (i.find("vmlinuz-") >= 0):
                    # skip start until "vmlinuz-"
                    guess_version = i[i.find("vmlinuz-") + len("vmlinuz-"):]
                    if user_specified:
                        if (guess_version == user_specified):
                            version_list.append(guess_version)
                    else:
                        version_list.append(guess_version)
        elif len(line.split()) > 0:
            if line.split()[0] == "title":
                within_xen_title = 0
                within_xen_entry = 0
    if len(version_list) > 1:
        err("Cannot decide between entries for kernels: " + version_list)
    elif len(version_list) == 0:
        err("Cannot find a boot entry candidate (please create a Xen boot entry first).")
    else:
        return version_list[0]



def insert_policy(boot_file, kernel_version, policy_name):
    """
    inserts policy binary file as last line of the grub entry
    matching the kernel_version version
    """
    within_xen_title = 0
    within_xen_entry = 0
    insert_at_end_of_entry = 0
    path_prefix = ''
    done = False
    (tmp_fd, tmp_grub) = tempfile.mkstemp()
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
            err("Boot file \'" + boot_file + "\' not found.")
    grub_fd = open(boot_file)
    for line in grub_fd:
        if xen_title_re.match(line):
            within_xen_title = 1
        elif within_xen_title and xen_kernel_re.match(line):
            within_xen_entry = 1
        elif within_xen_title and within_xen_entry and kernel_ver_re.match(line):
            for i in line.split():
                if (i.find("vmlinuz-") >= 0):
                    if  kernel_version == i[i.find("vmlinuz-") + len("vmlinuz-"):]:
                        insert_at_end_of_entry = 1
                        path_prefix = i[0:i.find("vmlinuz-")]
        elif any_module_re.match(line) and insert_at_end_of_entry:
            if binary_name_re.match(line):
                #delete existing policy module line
                line=''
        elif any_title_re.match(line):
            within_xen_title = 0
            within_xen_entry = 0

        if (empty_line_re.match(line) or any_title_re.match(line)) and insert_at_end_of_entry:
            #newline or new title: we insert the policy module line here
            os.write(tmp_fd, "\tmodule " + path_prefix + policy_name + ".bin\n")
            insert_at_end_of_entry = 0
        #write the line that was read (except potential existing policy entry)
        os.write(tmp_fd, line)

    if insert_at_end_of_entry:
        #last entry, no empty line at end of file
        os.write(tmp_fd, "\tmodule " + path_prefix + policy_name + ".bin\n")

    #temp file might be destroyed when closing it, first copy ...
    shutil.move(boot_file, boot_file+"_save")
    shutil.copyfile(tmp_grub, boot_file)
    os.close(tmp_fd)
    #temp file did not disappear on my system ...
    try:
        os.remove(tmp_grub)
    except:
        pass



def main(argv):
    try:
        user_kver = None
        policy = None
        if len(argv) == 2:
            policy = argv[1]
        elif len(argv) == 3:
            policy = argv[1]
            user_kver = argv[2]
        else:
            usage()

        if not policy_name_re.match(policy):
            err("Illegal policy name \'" + policy + "\'")

        policy_file = policy_dir_prefix + "/" + string.join(string.split(policy, "."), "/")
        src_binary_policy_file = policy_file + ".bin"
        #check if .bin exists or if policy file exists
        if not os.path.isfile(src_binary_policy_file):
            if not os.path.isfile(policy_file + "-security_policy.xml"):
                err("Unknown policy \'" + policy +"\'")
            else:
                err("Cannot find binary file for policy \'" + policy +
                    "\'. Please use makepolicy to create binary file.")
        dst_binary_policy_file = "/boot/" + policy + ".bin"
        shutil.copyfile(src_binary_policy_file, dst_binary_policy_file)

        kernel_version = determine_kernelversion(user_kver)
        insert_policy(boot_filename, kernel_version, policy)
        print "Boot entry created and \'%s\' copied to /boot" % (policy + ".bin")

    except ACMError:
        pass
    except:
        traceback.print_exc(limit=1)



if __name__ == '__main__':
    main(sys.argv)

