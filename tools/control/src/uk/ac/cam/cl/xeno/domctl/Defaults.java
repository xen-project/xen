package uk.ac.cam.cl.xeno.domctl;

import java.net.InetAddress;
import java.io.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;

/* these values are used in xenctl & domctl, so they need to be public */

public class Defaults
{
  public String domainName;

  public int domainSizeKB;
  public String domainImage;
  public String domainInitRD;
  public int domainVIFs;

  public String rootDevice;

  public String NWIP;
  public String NWGW;
  public String NWMask;
  public String NWHost;

  public String NWNFSServer;
  public String NWNFSRoot;

  int MaxDomainNumber = Integer.MAX_VALUE;
  String args = "";

  public String XIToolsDir = "";

  /***********************************************************************/

  public Defaults ()
  {
    File f = Settings.getDefaultsFile ();

    if (f == null)
    {
      return;
    }

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
	return;
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
    System.out.println ("   args            " + args);
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
	    NWIP = expandDefault (s, runCommand(XIToolsDir+Settings.XI_HELPER+" ip").trim());
	  } else if (lastName.equals ("nw_gw")) {
	    NWGW = expandDefault (s, runCommand(XIToolsDir+Settings.XI_HELPER+" route").trim());
	  } else if (lastName.equals ("nw_mask")) {
	    NWMask = expandDefault (s, runCommand(XIToolsDir+Settings.XI_HELPER+" mask").trim());
	  } else if (lastName.equals ("nw_host")) {
	    NWHost = s;
	  } else if (lastName.equals ("nw_nfs_server")) {
	    NWNFSServer = s;
	  } else if (lastName.equals ("nw_nfs_root")) {
	    NWNFSRoot = s;
	  } else if (lastName.equals ("args")) {
	    args = s;
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

  
  public String
    runCommand (String command)
  {
    Runtime runtime = Runtime.getRuntime();
    String outline;
    StringBuffer output = new StringBuffer();

    try
    {
      Process process = runtime.exec(command);
      BufferedReader in = new BufferedReader(
                         new InputStreamReader(process.getInputStream()));

      outline = in.readLine();
      while (outline != null)
      {
        output.append("\n" + outline);
        outline = in.readLine();
      }
    }
    catch (IOException e)
    {
      return e.toString();
    }

    return output.toString();
  }


}
