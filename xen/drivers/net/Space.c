/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Holds initial configuration information for devices.
 *
 * Version:	@(#)Space.c	1.0.7	08/12/93
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald J. Becker, <becker@scyld.com>
 */
#include <xeno/config.h>
#include <xeno/netdevice.h>

/*
 * KAF (23/7/02): All the probe shit is gone from here -- each network
 * driver should probe as part of its setup, and dynamically append
 * to dev_base when it finds a NIC.
 */

/*
 * The @dev_base list is protected by @dev_base_lock and the rtln
 * semaphore.
 *
 * Pure readers hold dev_base_lock for reading.
 *
 * Writers must hold the rtnl semaphore while they loop through the
 * dev_base list, and hold dev_base_lock for writing when they do the
 * actual updates.  This allows pure readers to access the list even
 * while a writer is preparing to update it.
 *
 * To put it another way, dev_base_lock is held for writing only to
 * protect against pure readers; the rtnl semaphore provides the
 * protection against other writers.
 *
 * See, for example usages, register_netdevice() and
 * unregister_netdevice(), which must be called with the rtnl
 * semaphore held.
 */
struct net_device *dev_base = NULL;
rwlock_t dev_base_lock = RW_LOCK_UNLOCKED;

