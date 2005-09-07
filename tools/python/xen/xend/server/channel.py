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
#============================================================================

import threading
import select

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()
from xen.lowlevel import xu

from xen.xend.XendLogging import log

DEBUG = 0

RESPONSE_TIMEOUT = 20.0

class EventChannel(dict):
    """An event channel between domains.
    """

    def interdomain(cls, dom1, dom2, port1=0, port2=0):
        """Create an event channel between domains.
        
        @return EventChannel (None on error)
        """
        v = xc.evtchn_bind_interdomain(dom1=dom1, dom2=dom2,
                                       port1=port1, port2=port2)
        if v:
            v = cls(dom1, dom2, v)
        return v

    interdomain = classmethod(interdomain)

    def restoreFromDB(cls, db, dom1, dom2, port1=0, port2=0):
        """Create an event channel using db info if available.
        Inverse to saveToDB().

        @param db db
        @param dom1
        @param dom2
        @param port1
        @param port2
        """
        try:
            dom1  = int(db['dom1'].getData())
        except: pass
        try:
            dom2  = int(db['dom2'].getData())
        except: pass
        try:
            port1 = int(db['port1'].getData())
        except: pass
        try:
            port2 = int(db['port2'].getData())
        except: pass
        evtchn = cls.interdomain(dom1, dom2, port1=port1, port2=port2)
        return evtchn

    restoreFromDB = classmethod(restoreFromDB)

    def __init__(self, dom1, dom2, d):
        d['dom1'] = dom1
        d['dom2'] = dom2
        self.update(d)
        self.dom1 = dom1
        self.dom2 = dom2
        self.port1 = d.get('port1')
        self.port2 = d.get('port2')

    def close(self):
        """Close the event channel.
        """
        def evtchn_close(dom, port):
            try:
                xc.evtchn_close(dom=dom, port=port)
            except Exception, ex:
                pass
            
        if DEBUG:
            print 'EventChannel>close>', self
        evtchn_close(self.dom1, self.port1)
        evtchn_close(self.dom2, self.port2)

    def saveToDB(self, db, save=False):
        """Save the event channel to the db so it can be restored later,
        using restoreFromDB() on the class.

        @param db db
        """
        db['dom1']  = str(self.dom1)
        db['dom2']  = str(self.dom2)
        db['port1'] = str(self.port1)
        db['port2'] = str(self.port2)
        db.saveDB(save=save)

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

def eventChannel(dom1, dom2, port1=0, port2=0):
    """Create an event channel between domains.
        
    @return EventChannel (None on error)
    """
    return EventChannel.interdomain(dom1, dom2, port1=port1, port2=port2)

def eventChannelClose(evtchn):
    """Close an event channel.
    """
    if not evtchn: return
    evtchn.close()
