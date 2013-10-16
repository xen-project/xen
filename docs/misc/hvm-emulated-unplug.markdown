#Xen HVM emulated device unplug protocol

The protocol covers three basic things:

 * Disconnecting emulated devices.
 * Getting log messages out of the drivers and into dom0.
 * Allowing dom0 to block the loading of specific drivers.  This is
   intended as a backwards-compatibility thing: if we discover a bug
   in some old version of the drivers, then rather than working around
   it in Xen, we have the option of just making those drivers fall
   back to emulated mode.

The current protocol works like this (from the point of view of
drivers):

1. When the drivers first come up, they check whether the unplug logic
   is available by reading a two-byte magic number from IO port `0x10`.
   These should be `0x49d2`.  If the magic number doesn't match, the
   drivers don't do anything.

2. The drivers read a one-byte protocol version from IO port `0x12`.  If
   this is 0, skip to 6.

3. The drivers write a two-byte product number to IO port `0x12`.  At
   the moment, the only drivers using this protocol are our
   closed-source ones, which use product number 1.

4. The drivers write a four-byte build number to IO port `0x10`.

5. The drivers check the magic number by reading two bytes from `0x10`
   again.  If it's changed from `0x49d2` to `0xd249`, the drivers are
   blacklisted and should not load.

6. The drivers write a two-byte bitmask of devices to unplug to IO
   port `0x10`.  The defined fields are:

  * `1` -- All IDE disks (not including CD drives)
  * `2` -- All emulated NICs
  * `4` -- All IDE disks except for the primary master (not including CD
	   drives)

   The relevant emulated devices then disappear from the relevant
   buses.  For most guest operating systems, you want to do this
   before device enumeration happens.

Once the drivers have checked the magic number, they can send log
messages to qemu which will be logged to wherever qemu's logs go
(`/var/log/xen/qemu-dm.log` on normal Xen, dom0 syslog on XenServer).
These messages are written to IO port `0x12` a byte at a time, and are
terminated by newlines.  There's a fairly aggressive rate limiter on
these messages, so they shouldn't be used for anything even vaguely
high-volume, but they're rather useful for debugging and support.

It is still permitted for a driver to use this logging feature if it
is blacklisted, but *ONLY* if it has checked the magic number and found
it to be `0x49d2` or `0xd249`.

This isn't exactly a pretty protocol, but it does solve the problem.

The blacklist is, from qemu's point of view, handled mostly through
xenstore.  A driver version is considered to be blacklisted if
`/mh/driver-blacklist/{product_name}/{build_number}` exists and is
readable, where `{build_number}` is the build number from step 4 as a
decimal number.  `{product_name}` is a string corresponding to the
product number in step 3.

The master registry of product names and numbers is in
xen/include/public/hvm/pvdrivers.h.

NOTE: The IO ports implementing the unplug protocol are implemented
as part of the Xen Platform PCI Device, so if that device is not
present in the system then this protocol will not work.
