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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd
#============================================================================

import xen.lowlevel.xc

from xen.xend.XendLogging import log


xc = xen.lowlevel.xc.new()


class EventChannel:
    """An event channel between domains.
    """

    def __init__(self, dom1, dom2, port1, port2):
        self.dom1 = dom1
        self.dom2 = dom2
        self.port1 = port1
        self.port2 = port2


    def close(self):
        """Close the event channel.  Nothrow guarantee.
        """
        def evtchn_close(dom, port):
            try:
                xc.evtchn_close(dom=dom, port=port)
            except Exception:
                log.exception("Exception closing event channel %d, %d.", dom,
                              port)
            
        evtchn_close(self.dom1, self.port1)
        evtchn_close(self.dom2, self.port2)


    def sxpr(self):
        return ['event-channel',
                ['dom1',  self.dom1  ],
                ['port1', self.port1 ],
                ['dom2',  self.dom2  ],
                ['port2', self.port2 ]
                ]


    def __repr__(self):
        return ("<EventChannel dom1:%d:%d dom2:%d:%d>"
                % (self.dom1, self.port1, self.dom2, self.port2))


def eventChannel(dom1, dom2, port1 = 0, port2 = 0):
    """Create an event channel between domains.
        
    @return EventChannel (None on error)
    """
    v = xc.evtchn_bind_interdomain(dom1=dom1, dom2=dom2,
                                   port1=port1, port2=port2)
    if v and v.get('port1'):
        return EventChannel(dom1, dom2, v['port1'], v['port2'])
    else:
        return None
