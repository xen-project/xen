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
# Author: Bryan D. Payne <bdpayne@us.ibm.com>
#============================================================================

"""Remove a label from a domain configuration file or a resoruce.
"""
import sys, os, re
import string
import traceback
#from xml.marshal import generic
from xen.util import security

def usage():
    print "\nUsage: xm rmlabel dom <configfile>"
    print "       xm rmlabel res <resource>\n"
    print "  This program removes an acm_label entry from the 'configfile'"
    print "  for a domain or from the global resource label file for a"
    print "  resource. If the label does not exist for the given domain or"
    print "  resource, then rmlabel fails.\n"


def rm_resource_label(resource):
    """Removes a resource label from the global resource label file.
    """
    try:
        # read in the resource file
        file = security.res_label_filename
        if os.path.isfile(file):
            fd = open(file, "rb")
#            access_control = generic.load(fd)
            fd.close()
        else:
            security.err("Resource file not found, cannot remove label!")

        # remove the entry and update file
        if access_control.has_key(resource):
            del access_control[resource]
            fd = open(file, "wb")
#            generic.dump(access_control, fd)
            fd.close()
        else:
            security.err("Label does not exist in resource label file.")

    except security.ACMError:
        pass
    except:
        traceback.print_exc(limit=1)


def rm_domain_label(configfile):
    try:
        # open the domain config file
        fd = None
        file = None
        if configfile[0] == '/':
            fd = open(configfile, "rb")
        else:
            for prefix in [".", "/etc/xen"]:
                file = prefix + "/" + configfile
                if os.path.isfile(file):
                    fd = open(file, "rb")
                    break
        if not fd:
            security.err("Configuration file '"+configfile+"' not found.")

        # read in the domain config file, removing label
        ac_entry_re = re.compile("^access_control\s*=.*", re.IGNORECASE)
        ac_exit_re = re.compile(".*'\].*")
        file_contents = ""
        comment = 0
        removed = 0
        for line in fd.readlines():
            if ac_entry_re.match(line):
                comment = 1
            if comment:
                removed = 1
                line = "#"+line
            if comment and ac_exit_re.match(line):
                comment = 0
            file_contents = file_contents + line
        fd.close()

        # send error message if we didn't find anything to remove
        if not removed:
            security.err("Label does not exist in domain configuration file.")

        # write the data back out to the file
        fd = open(file, "wb")
        fd.writelines(file_contents)
        fd.close()

    except security.ACMError:
        pass
    except:
        traceback.print_exc(limit=1)


def main (argv):
    try:
        if len(argv) != 3:
            usage()
            return

        if argv[1].lower() == "dom":
            configfile = argv[2]
            rm_domain_label(configfile)
        elif argv[1].lower() == "res":
            resource = argv[2]
            rm_resource_label(resource)
        else:
            usage()

    except security.ACMError:
        traceback.print_exc(limit=1)


if __name__ == '__main__':
    main(sys.argv)


