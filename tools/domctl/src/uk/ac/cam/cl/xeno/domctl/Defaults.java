package uk.ac.cam.cl.xeno.domctl;

import java.net.InetAddress;
import java.io.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;

public class Defaults
{
  String domainName;

  int domainSizeKB;
  String domainImage;
  String domainInitRD;
  int domainVIFs;

  String rootDevice;

  String NWIP;
  String NWGW;
  String NWMask;
  String NWHost;

  String NWNFSServer;
  String NWNFSRoot;

  int MaxDomainNumber = Integer.MAX_VALUE;

  String XIToolsDir;

  /***********************************************************************/

  public Defaults ()
  {
    File f = Settings.getDefaultsFile ();

    try
      {
	XMLReader xr = new org.apache.crimson.parser.XMLReaderImpl();
	Handler handler = new Handler ();
	xr.setContentHandler (handler);
	xr.setErrorHandler (handler);
	xr.parse (new InputSource(new FileReader (f)));
      }
    catch (Exception e) 
      {
	System.err.println ("Could not read defaults file " + f +
			    "\nException: " + e);
	e.printStackTrace();
	System.exit(1);
      }
  }

  public void describe () {
    System.out.println ("Domain defaults:");
    System.out.println ("   name            " + domainName);
    System.out.println ("   size            " + domainSizeKB);
    System.out.println ("   vifs            " + domainVIFs);
    System.out.println ("   domainImage     " + domainImage);
    System.out.println ("   domainInitRD    " + domainInitRD);
    System.out.println ("   rootDevice      " + rootDevice);
    System.out.println ("   NWIP            " + NWIP);
    System.out.println ("   NWGW            " + NWGW);
    System.out.println ("   NWMask          " + NWMask);
    System.out.println ("   MaxDomainNumber " + MaxDomainNumber);
    System.out.println ("   NWNFSServer     " + NWNFSServer);
    System.out.println ("   NWNFSRoot       " + NWNFSRoot);
    System.out.println ("   XIToolsDir      " + XIToolsDir);
  }

  /***********************************************************************/

  class Handler extends DefaultHandler
  {
    boolean inDomctlDefaults;
    String lastName;

    public void startDocument ()
    {
    }

    public void endDocument ()
    {
    }

    public void startElement (String uri, String name,
			      String qname, Attributes atts)
    {
      if (qname.equals ("domctl_defaults")) {
	inDomctlDefaults = true;
      } else {
	lastName = qname;
      }
    }

    public void endElement (String uri, String name, String qname)
    {
      lastName = "";
      if (qname.equals ("domctl_defaults")) {
	inDomctlDefaults = false;
      }
    }
    
    public void characters (char ch[], int start, int length)
    {
      String s = new String (ch, start, length);
      if (lastName != null)
	{
	  if (lastName.equals ("domain_size_kb")) {
	    domainSizeKB = Integer.parseInt (s);
	  } else if (lastName.equals ("domain_image")) {
	    domainImage = s;
	  } else if (lastName.equals ("domain_name")) {
	    domainName = s;
	  } else if (lastName.equals ("domain_init_rd")) {
	    domainInitRD = s;
	  } else if (lastName.equals ("domain_vifs")) {
	    domainVIFs = Integer.parseInt (s);
	  } else if (lastName.equals ("root_device")) {
	    rootDevice = s;
	  } else if (lastName.equals ("nw_ip")) {
	    NWIP = expandDefault (s, Settings.LOCAL_IP);
	  } else if (lastName.equals ("nw_gw")) {
	    NWGW = expandDefault (s, Settings.LOCAL_GW);
	  } else if (lastName.equals ("nw_mask")) {
	    NWMask = expandDefault (s, Settings.LOCAL_MASK);
	  } else if (lastName.equals ("nw_host")) {
	    NWHost = s;
	  } else if (lastName.equals ("nw_nfs_server")) {
	    NWNFSServer = s;
	  } else if (lastName.equals ("nw_nfs_root")) {
	    NWNFSRoot = s;
	  } else if (lastName.equals ("max_domain_number")) {
	    MaxDomainNumber = Integer.parseInt(s);
	  } else if (lastName.equals ("xi_tools_dir")) {
	    XIToolsDir = s;
	  }
	}
    }
  }

  public String expandDefault (String supplied, String self)
  {
    if (supplied.startsWith ("=")) {
      if (supplied.length() > 1) {
	return self + supplied.substring (1, supplied.length());
      } else {
	return self;
      }
    } else {
      return supplied;
    }
  }
}
