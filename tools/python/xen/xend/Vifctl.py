"""Xend interface to networking control scripts.
"""
import os
import os.path
import sys
import xen.util.process

from xen.xend import XendRoot
xroot = XendRoot.instance()

"""Where network control scripts live."""
SCRIPT_DIR = xroot.network_script_dir

def network(op, script=None, bridge=None, antispoof=None):
    """Call a network control script.
    Xend calls this with op 'start' when it starts.

    @param op:        operation (start, stop, status)
    @param script:    network script name
    @param bridge:    xen bridge
    @param antispoof: whether to enable IP antispoofing rules
    """
    if op not in ['start', 'stop', 'status']:
        raise ValueError('Invalid operation:' + op)
    if script is None:
        script = xroot.get_network_script()
    if bridge is None:
        bridge = xroot.get_vif_bridge()
    if antispoof is None:
        antispoof = xroot.get_vif_antispoof()
    script = os.path.join(SCRIPT_DIR, script)
    args = [op]
    args.append("bridge='%s'" % bridge)
    if antispoof:
        args.append("antispoof=yes")
    else:
        args.append("antispoof=no")
    args = ' '.join(args)
    xen.util.process.system(script + ' ' + args)

def set_vif_name(vif_old, vif_new):
    if vif_old == vif_new:
        vif = vif_new
        return vif
    if os.system("ip link show %s" % vif_old) == 0:
        os.system("ip link set %s down" % vif_old)
        os.system("ip link set %s name %s" % (vif_old, vif_new))
        os.system("ip link set %s up" % vif_new)
    if os.system("ip link show %s" % vif_new) == 0:
        vif = vif_new
    else:
        vif = vif_old
    return vif

def vifctl(op, vif=None, script=None, domain=None, mac=None, bridge=None, ipaddr=[]):
    """Call a vif control script.
    Xend calls this when bringing vifs up or down.

    @param op:     vif operation (up, down)
    @param vif:    vif name
    @param script: name of control script
    @param domain: name of domain the vif is on
    @param mac:    vif MAC address
    @param bridge: bridge to add the vif to
    @param ipaddr: list of ipaddrs the vif may use
    """
    if op not in ['up', 'down']:
        raise ValueError('Invalid operation:' + op)
    if script is None:
        script = xroot.get_vif_script()
    if bridge is None:
        bridge = xroot.get_vif_bridge()
    script = os.path.join(SCRIPT_DIR, script)
    args = [op]
    args.append("vif='%s'" % vif)
    args.append("domain='%s'" % domain)
    args.append("mac='%s'" % mac)
    if bridge:
        args.append("bridge='%s'" % bridge)
    if ipaddr:
        ips = ' '.join(ipaddr)
        args.append("ip='%s'" % ips)
    args = ' '.join(args)
    os.system(script + ' ' + args)

