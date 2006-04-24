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

"""Labeling a domain configuration file.
"""
import sys, os
import traceback


from xen.util.security import ACMError, err, active_policy, label2ssidref, on, access_control_re


def usage():
    print "\nUsage: xm addlabel <configfile> <label> [<policy>]\n"
    print "  This program adds an acm_label entry into the 'configfile'."
    print "  It derives the policy from the running hypervisor if it"
    print "  is not given (optional parameter). If the configfile is"
    print "  already labeled, then addlabel fails.\n"
    err("Usage")


def main(argv):
    try:
        policyref = None
        if len(argv) not in [3,4]:
            usage()
        configfile = argv[1]
        label = argv[2]

        if len(argv) == 4:
            policyref = argv[3]
        elif on():
            policyref = active_policy
        else:
            err("No active policy. Policy must be specified in command line.")

        #sanity checks: make sure this label can be instantiated later on
        ssidref = label2ssidref(label, policyref)

        new_label = "access_control = ['policy=%s,label=%s']\n" % (policyref, label)
        if not os.path.isfile(configfile):
            err("Configuration file \'" + configfile + "\' not found.")
        config_fd = open(configfile, "ra+")
        for line in config_fd:
            if not access_control_re.match(line):
                continue
            config_fd.close()
            err("Config file \'" + configfile + "\' is already labeled.")
        config_fd.write(new_label)
        config_fd.close()

    except ACMError:
        pass
    except:
        traceback.print_exc(limit=1)


if __name__ == '__main__':
    main(sys.argv)


