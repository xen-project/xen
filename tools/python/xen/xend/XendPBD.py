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
# Copyright (c) 2007 Xensource Inc.
#============================================================================


import uuid
from XendLogging import log


attr_inst = ['uuid',
             'host',
             'SR',
             'device_config']
attr_ro = attr_inst + ['currently_attached']


_all = {}


def get(ref):
    return _all[ref]


def get_all():
    return _all.values()


def get_all_refs():
    return _all.keys()


def get_by_SR(sr_ref):
    return [k for (k, v) in _all.items() if v.get_SR() == sr_ref]


class XendPBD:
    """Physical block devices."""
    
    def __init__(self, record):
        if 'uuid' not in record:
            record['uuid'] = uuid.createString()

        import XendAPI
        for v in attr_inst:
            setattr(self, v, record[v])
        self.currently_attached = True
        _all[record['uuid']] = self


    def destroy(self):
        if self.uuid in _all:
            del _all[self.uuid]


    def get_record(self):
        import XendAPI
        result = {}
        for v in attr_ro:
            result[v] = getattr(self, v)
        return result


for v in attr_ro:
    def f(v_):
        setattr(XendPBD, 'get_' + v_, lambda s: getattr(s, v_))
    f(v)
