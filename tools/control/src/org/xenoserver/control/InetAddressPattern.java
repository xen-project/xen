package org.xenoserver.control;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class InetAddressPattern
{
  InetAddress base;
  boolean addDom;

  static InetAddressPattern parse (String t)
  {
    InetAddressPattern result = new InetAddressPattern ();
    char[] ca = t.toCharArray ();
    int len = ca.length;

    try {
      if (len == 0) {
	result.base = null;
	result.addDom = false;
      } else if (ca[len - 1] == '+') {
	result.base = InetAddress.getByName(t.substring(0, len - 1));
	result.addDom = true;
      } else {
	result.base = InetAddress.getByName(t);
	result.addDom = false;
      }
    } catch (UnknownHostException uhe) {
      result.base = null;
      result.addDom = false;
    }

    return result;
  }

  public String resolve (int domain_id) {
    byte b[] = base.getAddress ();
    if (addDom) {
      if (((int)b[3]) + domain_id > 255) {
	if (((int)b[2]) + domain_id > 255) {
	  if (((int)b[1]) + domain_id > 255) {
	    b[0] ++;
	  }
	  b[1] ++;
	}
	b[2] ++;
      }
      b[3] += domain_id;
    }
    return "" + 
      (b[0] + (b[0] < 0 ? 256 : 0)) + "." + 
      (b[1] + (b[1] < 0 ? 256 : 0)) + "." + 
      (b[2] + (b[2] < 0 ? 256 : 0)) + "." + 
      (b[3] + (b[3] < 0 ? 256 : 0));
  }

  public String toString () {
    return "[" + base + (addDom ? "+dom_id" : "") + "]";
  }
}
