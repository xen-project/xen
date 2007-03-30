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
# Copyright (c) 2006-2007 Xensource Inc.
#============================================================================


class XendPIFMetrics:
    """PIF Metrics."""
    
    def __init__(self, uuid):
        self.uuid = uuid

    def set_PIF(self, pif):
        self.pif = pif

    def get_io_read_kbs(self):
        return self._get_stat(0)
    
    def get_io_write_kbs(self):
        return self._get_stat(1)

    def _get_stat(self, n):
        from xen.xend.XendNode import instance as xennode
        pifname = self.pif.device
        pifs_util = xennode().monitor.get_pifs_util()
        if pifname in pifs_util:
            return pifs_util[pifname][n]
        return 0.0

    def get_last_updated(self):
        import xen.xend.XendAPI as XendAPI
        return XendAPI.now()

    def get_record(self):
        return {'uuid'         : self.uuid,
                'io_read_kbs'  : self.get_io_read_kbs(),
                'io_write_kbs' : self.get_io_write_kbs(),
                'last_updated' : self.get_last_updated(),
                }
