"""Xend interface to the vifctl script.
"""
import os
import os.path
import sys

VIFCTL = '/etc/xen/xend/vifctl'

def init():
    """Call 'vifctl init'. Called when xend starts.
    """
    os.system(VIFCTL + ' init ')

def vifctl_args(vif, mac=None, bridge=None, ipaddr=[]):
    """Construct the argument list for vifctl.
    """
    args = ['vif=%s' % vif]
    if mac:
        args.append('mac=%s' % mac)
    if bridge:
        args.append('bridge=%s' % bridge)
    for ip in ipaddr:
        args.append('ipaddr=%s' % ip)
    return ' '.join(args)
    
def up(vif, **kwds):
    """Call 'vifctl up' for a vif. Called when a vif is created.
    """
    args = vifctl_args(vif, **kwds)
    os.system(VIFCTL + ' up ' + args)

def down(vif, **kwds):
    """Call 'vifctl down' for a vif. Called when a vif is destroyed.
    """
    args = vifctl_args(vif, **kwds)
    os.system(VIFCTL + ' down ' + args)
