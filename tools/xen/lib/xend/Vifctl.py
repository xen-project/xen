import os
import os.path
import sys

VIFCTL = '/etc/xen/xend/vifctl'

def init():
    os.system(VIFCTL + ' init ')

def up(vif, mac=None, bridge=None, ipaddr=[]):
    args = ['vif=%s' % vif]
    if mac:
        args.append('mac=%s' % mac)
    if bridge:
        args.append('bridge=%s' % bridge)
    if ipaddr:
        args.append('ipaddr=%s' % ','.join(ipaddr))
    os.system(VIFCTL + ' up ' + ' '.join(args))

def down(vif, mac=None, bridge=None, ipaddr=[]):
    args = ['vif=%s' % vif]
    if mac:
        args.append('mac=%s' % mac)
    if bridge:
        args.append('bridge=%s' % bridge)
    if ipaddr:
        args.append('ipaddr=%s' % ','.join(ipaddr))
    os.system(VIFCTL + ' down ' + ' '.join(args))
