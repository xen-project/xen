"""
 XenMemory.py - grep memory from domU

 This module can handle the /proc/xen/balloon as well as the sysfs
 memory interface.

 Copyright (C) flonatel GmbH & Co. KG, 2009
 Author: Andreas Florath

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; under version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
"""

import os

from Test import *

class XenMemory:

    def __init__(self, console):
        self.console = console
        self.sysfs_mem_dir = "/sys/devices/system/xen_memory/xen_memory0"

        try:
            res = self.console.runCmd("ls " + self.sysfs_mem_dir)
            self.use_sysfs = res['return'] == 0
        except ConsoleError, e:
            FAIL(str(e))
        

    def get_mem_from_domU_sysfs(self):
        try:
            run = self.console.runCmd(
                "cat " + os.path.join(self.sysfs_mem_dir, "info/current_kb"))
        except ConsoleError, e:
            FAIL(str(e))

        return int(run["output"]) / 1024
    
    def get_mem_from_domU_balloon(self):
        try:
            run = self.console.runCmd("cat /proc/xen/balloon | grep Current");
        except ConsoleError, e:
            FAIL(str(e))

        match = re.match("^Current allocation:\s+(\d+)\skB", run["output"])
        if not match:
            FAIL("Invalid domU meminfo line")
   
        return int(match.group(1)) / 1024

    # Prefer sysfs interface
    def get_mem_from_domU(self):
        if self.use_sysfs:
            return self.get_mem_from_domU_sysfs()
        else:
            return self.get_mem_from_domU_balloon()

