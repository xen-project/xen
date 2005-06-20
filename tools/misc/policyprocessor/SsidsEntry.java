/**
 * (C) Copyright IBM Corp. 2005
 *
 * $Id: SsidsEntry.java,v 1.2 2005/06/17 20:02:40 rvaldez Exp $
 *
 * Author: Ray Valdez
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * SsidsEntry Class.  
 * <p>
 *
 * Holds ssid information.
 *
 * <p>
 *
 *
 */
public class SsidsEntry 
 {
  int id;	/* used for partition and vlan */
  int bus;	/* used for slots */
  int slot;
  int ste = 0xffffffff;
  int chw = 0xffffffff;
 }
