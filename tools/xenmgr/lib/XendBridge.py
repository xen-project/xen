"""Bridge control utilities.
"""
import os
import os.path
import re
import sys

from xenmgr import XendRoot
xroot = XendRoot.instance()

os.defpath = os.defpath + ':/sbin:/usr/sbin:/usr/local/sbin'
CMD_IFCONFIG = 'ifconfig'
CMD_ROUTE    = 'route'
CMD_BRCTL    = 'brctl'
CMD_IPTABLES = "iptables"

DEFAULT_BRIDGE = 'nbe-br'
DEFAULT_INTERFACE = 'eth0'

opts = None

class Opts:

    def __init__(self, defaults):
        for (k, v) in defaults.items():
            setattr(self, k, v)
        pass

def cmd(p, s):
    """Print and execute command 'p' with args 's'.
    """
    global opts
    c = p + ' ' + s
    if opts.verbose: print c
    if not opts.dryrun:
        os.system(c)

def default_bridge():
    return xroot.get_config_value('bridge', DEFAULT_BRIDGE)

def default_interface():
    return xroot.get_config_value('interface', DEFAULT_INTERFACE)

def vif_dev(dom, vif):
    """Return the name of the network interface for vif on domain dom.
    """
    return "vif%d.%d" % (dom, vif)

def vif_bridge_add(dom, vif, bridge=None):
    """Add the network interface for vif on dom to a bridge.
    """
    if not bridge: bridge = default_bridge()
    d = { 'bridge': bridge, 'vif': vif_dev(dom, vif) }
    cmd(CMD_BRCTL, 'addif %(bridge)s %(vif)s' % d)
    return bridge

def vif_bridge_rem(dom, vif, bridge=None):
    """Remove the network interface for vif on dom from a bridge.
    """
    if not bridge: bridge = default_bridge()
    print 'vif_bridge_rem>', dom, vif, bridge
    d = { 'bridge': bridge, 'vif': vif_dev(dom, vif) }
    cmd(CMD_BRCTL, 'delif %(bridge)s %(vif)s' % d)

def vif_restrict_addr(dom, vif, addr, delete=0):
    d = { 'vif': vif_dev(dom, vif), 'addr': addr}
    if delete:
        d['flag'] = '-D'
    else:
        d['flag' = '-A'
    cmd(CMD_IPTABLES, '-P FORWARD DROP')
    cmd(CMD_IPTABLES, '%(flag)s FORWARD -m physdev --physdev-in %(vif)s -s %(addr)s -j ACCEPT' % d)
    cmd(CMD_IPTABLES, '%(flag)s FORWARD -m physdev --physdev-out %(vif)s -d %(addr)s -j ACCEPT' % d)

def bridge_create(bridge=None, **kwd):
    """Create a bridge.
    Defaults hello time to 0, forward delay to 0 and stp off.
    """
    if not bridge: bridge = default_bridge()
    cmd(CMD_BRCTL, 'addbr %s' % bridge)
    if kwd.get('hello', None) is None:
        kwd['hello'] = 0
    if kwd.get('fd', None) is None:
        kwd['fd'] = 0
    if kwd.get('stp', None) is None:
        kwd['stp'] = 'off'
    bridge_set(bridge, **kwd)

def bridge_set(bridge, hello=None, fd=None, stp=None):
    """Set bridge parameters.
    """
    if hello is not None:
        cmd(CMD_BRCTL, 'sethello %s %d' % (bridge, hello))
    if fd is not None:
        cmd(CMD_BRCTL, 'setfd %s %d' % (bridge, fd))
    if stp is not None:
        cmd(CMD_BRCTL, 'stp %s %s' % (bridge, stp))

def bridge_del(bridge=None):
    """Delete a bridge.
    """
    if not bridge: bridge = default_bridge()
    cmd(CMD_BRCTL, 'delbr %s' % bridge)

def routes():
    """Return a list of the routes.
    """
    fin = os.popen(CMD_ROUTE + ' -n', 'r')
    routes = []
    for x in fin:
        if x.startswith('Kernel'): continue
        if x.startswith('Destination'): continue
        x = x.strip()
        y = x.split()
        z = { 'destination': y[0],
              'gateway'    : y[1],
              'mask'       : y[2],
              'flags'      : y[3],
              'metric'     : y[4],
              'ref'        : y[5],
              'use'        : y[6],
              'interface'  : y[7] }
        routes.append(z)
    return routes

def ifconfig(interface):
    """Return the ip config for an interface,
    """
    fin = os.popen(CMD_IFCONFIG + ' %s' % interface, 'r')
    inetre = re.compile('\s*inet\s*addr:(?P<address>\S*)\s*Bcast:(?P<broadcast>\S*)\s*Mask:(?P<mask>\S*)')
    info = None
    for x in fin:
        m = inetre.match(x)
        if not m: continue
        info = m.groupdict()
        info['interface'] = interface
        break
    return info

def reconfigure(interface=None, bridge=None):
    """Reconfigure an interface to be attached to a bridge, and give the bridge
    the IP address etc. from interface. Move the default route to the interface
    to the bridge.

    If opts.create is true, creates the bridge.
    """
    global opts
    if not interface: interface = default_interface()
    if not bridge: bridge = default_bridge()
    intf_info = ifconfig(interface)
    if not intf_info:
        print 'Interface not found:', interface
        return
    if opts.create:
        bridge_create(bridge)
    #bridge_info = ifconfig(bridge)
    #if not bridge_info:
    #    print 'Bridge not found:', bridge
    #    return
    route_info = routes()
    intf_info['bridge'] = bridge
    intf_info['gateway'] = None
    for r in route_info:
        if (r['destination'] == '0.0.0.0' and
            'G' in r['flags'] and
            r['interface'] == interface):
            intf_info['gateway'] = r['gateway']
    if not intf_info['gateway']:
        print 'Gateway not found: ', interface
        return
    cmd(CMD_IFCONFIG,
        '%(bridge)s %(address)s netmask %(mask)s broadcast %(broadcast)s up'
        % intf_info)
    cmd(CMD_ROUTE,
        'add default gateway %(gateway)s dev %(bridge)s'
        % intf_info)
    cmd(CMD_BRCTL, 'addif %(bridge)s %(interface)s' % intf_info)
    cmd(CMD_IFCONFIG, '%(interface)s 0.0.0.0' % intf_info)

defaults = {
    'interface': default_interface(),
    'bridge'   : default_bridge(),
    'verbose'  : 1,
    'dryrun'   : 0,
    'create'   : 0,
    }

opts = Opts(defaults)

def set_opts(val):
    global opts
    opts = val
    return opts
