# XL Network Configuration

## Syntax Overview

This document specifies the xl config file format vif configuration
option.  It has the following form:

        vif = [ '<vifspec>', '<vifspec>', ... ]

where each vifspec is in this form:
    
        [<key>=<value>|<flag>,]

For example:

        'mac=00:16:3E:74:3d:76,model=rtl8139,bridge=xenbr0'
        'mac=00:16:3E:74:34:32'
        '' # The empty string

These might be specified in the domain config file like this:

        vif = [ 'mac=00:16:3E:74:34:32', 'mac=00:16:3e:5f:48:e4,bridge=xenbr1' ]

More formally, the string is a series of comma-separated keyword/value
pairs. All keywords are optional.

Each device has a `DEVID` which is its index within the vif list, starting from 0.

## Keywords

### mac

If specified then this option specifies the MAC address inside the
guest of this VIF device. The value is a 48-bit number represented as
six groups of two hexadecimal digits, separated by colons (:).

The default if this keyword is not specified is to be automatically
generate a MAC address inside the space assigned to Xen's
[Organizationally Unique Identifier][oui] (00:16:3e).

If you are choosing a MAC address then it is strongly recommend to
follow one of the following strategies:

  * Generate a random sequence of 6 byte, set the locally administered
    bit (bit 2 of the first byte) and clear the multicast bit (bit 1
    of the first byte). In other words the first byte should have the
    bit pattern xxxxxx10 (where x is a randomly generated bit) and the
    remaining 5 bytes are randomly generated See
    [http://en.wikipedia.org/wiki/MAC_address] for more details the
    structure of a MAC address.
  * Allocate an address from within the space defined by your
    organization's OUI (if you have one) following your organization's
    procedures for doing so.
  * Allocate an address from within the space defined by Xen's OUI
    (00:16:3e). Taking care not to clash with other users of the
    physical network segment where this VIF will reside.

If you have an OUI for your own use then that is the preferred
strategy. Otherwise in general you should prefer to generate a random
MAC and set the locally administered bit since this allows for more
bits of randomness than using the Xen OUI.

### bridge

Specifies the name of the network bridge which this VIF should be
added to. The default is `xenbr0`. The bridge must be configured using
your distribution's network configuration tools. See the [wiki][net]
for guidance and examples.

### type

This keyword is valid for HVM guests only.

Specifies the type of device to valid values are:

  * `ioemu` (default) -- this device will be provided as an emulate
    device to the guest and also as a paravirtualised device which the
    guest may choose to use instead if it has suitable drivers
    available.
  * `vif` -- this device will be provided as a paravirtualised device
    only.

### model

This keyword is valid for HVM guest devices with `type=ioemu` only.

Specifies the type device to emulated for this guest. Valid values
are:

  * `rtl8139` (default) -- Realtek RTL8139
  * `e1000` -- Intel E1000 
  * in principal any device supported by your device model

### vifname

This keyword is valid for HVM guest devices with `type=ioemu` only.

Specifies the backend device name for an emulated device. The default
is `tapDOMID.DEVID` where `DOMID` is the guest domain ID and `DEVID`
is the device number.

### script

Specifies the hotplug script to run to configure this device (e.g. to
add it to the relevant bridge). Defaults to
`XEN_SCRIPT_DIR/vif-bridge` but can be set to any script. Some example
scripts are installed in `XEN_SCRIPT_DIR`.

### ip

Specifies the IP address for the device, the default is not to
specify an IP address.

What, if any, effect this has depends on the hotplug script which is
configured. A typically behaviour (exhibited by the example hotplug
scripts) if set might be to configure firewall rules to allow only the
specified IP address to be used by the guest (blocking all others).

### backend

Specifies the backend domain which this device should attach to. This
defaults to domain 0. Specifying another domain requires setting up a
driver domain which is outside the scope of this document.

[oui]: http://en.wikipedia.org/wiki/Organizationally_Unique_Identifier
[net]: http://wiki.xen.org/xenwiki/HostConfiguration/Networking
