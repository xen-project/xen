# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

from xen.xend import sxp
from xen.xend import EventServer
from SrvDir import SrvDir

class SrvEventDir(SrvDir):
    """Event directory.
    """

    def __init__(self):
        SrvDir.__init__(self)
        self.eserver = EventServer.instance()

    def op_inject(self, op, req):
        eventstring = req.args.get('event')
        pin = sxp.Parser()
        pin.input(eventstring)
        pin.input_eof()
        sxpr = pin.get_val()
        self.eserver.inject(sxp.name(sxpr), sxpr)
        if req.use_sxp:
            sxp.name(sxpr)
        else:
            return '<code>' + eventstring + '</code>'
        
    def render_POST(self, req):
        return self.perform(req)

    def form(self, req):
        action = req.prePathURL()
        req.write('<form method="post" action="%s" enctype="multipart/form-data">'
                  % action)
        req.write('<button type="submit" name="op" value="inject">Inject</button>')
        req.write('Event <input type="text" name="event" size="40"><br>')
        req.write('</form>')
        req.write('<form method="post" action="%s" enctype="multipart/form-data">'
                  % action)
        req.write('<button type="submit" name="op" value="inject">Inject</button>')
        req.write('Event file<input type="file" name="event"><br>')
        req.write('</form>')
