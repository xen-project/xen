package uk.ac.cam.cl.xeno.domctl;

import java.io.*;
import java.net.*;

public class CommandNew extends Command
{
  public int doCommand(Defaults d, String args[])
  {
    Runtime r = Runtime.getRuntime ();
    String name = getStringParameter(args, 'n', d.domainName);
    int size = getIntParameter(args, 'k', d.domainSizeKB);
    String image = getStringParameter(args, 'i', d.domainImage);
    String initrd = getStringParameter (args, 'r', d.domainInitRD);
    int vifs = getIntParameter(args, 'v', d.domainVIFs);
    String bargs = getStringParameter (args, 'a', "") + " ";
    String root_dev = getStringParameter (args, 'd', d.rootDevice);
    String nfs_root_path = getStringParameter (args, 'f', d.NWNFSRoot);
    String nw_ip = getStringParameter (args, '4', d.NWIP);
    String nw_gw = getStringParameter (args, 'g', d.NWGW);
    String nw_mask = getStringParameter (args, 'm', d.NWMask);
    String nw_nfs_server = getStringParameter (args, 's', d.NWNFSServer);
    String nw_host = getStringParameter (args, 'h', d.NWHost);
    String domain_ip = "";
    int rc = 0;
    int domain_id = -1;
    DataInputStream dis;
    int idx;
    int i;

    d.describe ();

    try
      {
	/* Some initial sanity checks */
	if (root_dev.equals ("/dev/nfs") && (vifs == 0)) {
	  return reportError ("Cannot use NFS root without VIFs configured");
	}

	/* Create a new empty domain */
	Process create_p;
	String create_cmdarray[] = new String[3];
	int create_rc;
	create_cmdarray[0] = d.XIToolsDir + "xi_create";
	create_cmdarray[1] = "" + size;
	create_cmdarray[2] = name;
	if (Settings.TEST) {
	  reportCommand (create_cmdarray);
	  domain_id=1;
	  create_rc=0;
	} else {
	  create_p = r.exec (create_cmdarray);
	  dis = new DataInputStream (new BufferedInputStream (create_p.getInputStream ()));
	  domain_id = Integer.parseInt (dis.readLine ());
	  create_rc = create_p.waitFor ();
	}

	if (create_rc != 0) {
	  return reportXIError ("Failed to create domain", create_cmdarray);
	} else if (domain_id > d.MaxDomainNumber) {
	  return reportError ("Cannot configure more than " + 
			      d.MaxDomainNumber + " domains");
	}

	/* Set up boot parameters to pass to xi_build. */
	if (root_dev.equals ("/dev/nfs")) {
	  if (vifs == 0) {
	    return reportError ("Cannot use NFS root without VIFs configured");
	  }
	  if (nfs_root_path == null) {
	    return reportError ("No NFS root specified");
	  }
	  if (nw_nfs_server == null) {
	    return reportError ("No NFS server specified");
	  }
	  bargs = (bargs + 
		   "root=/dev/nfs " +
		   "nfsroot=" + StringPattern.parse(nfs_root_path).resolve(domain_id) +
		   " ");
	} else {
	  bargs = (bargs + 
		   "root=" + StringPattern.parse(root_dev).resolve(domain_id) +
		   " ");

	}
	
	if (vifs > 0) {
	  domain_ip = InetAddressPattern.parse(nw_ip).resolve(domain_id);
	  if (nw_host == null) {
	    try {
	      nw_host = InetAddress.getByName(domain_ip).getHostName();
	    } catch (UnknownHostException uhe) {
	      nw_host = "" + nw_ip;
	    }
	    
	  }
	  bargs = ("ip=" + domain_ip +
		   ":" + ((nw_nfs_server == null) ? "" : (InetAddressPattern.parse(nw_nfs_server).resolve(domain_id))) +
		   ":" + ((nw_gw == null) ? "" : (InetAddressPattern.parse(nw_gw).resolve(domain_id))) + 
		   ":" + ((nw_mask == null) ? "" : InetAddressPattern.parse(nw_mask).resolve(domain_id)) +
		   ":" + ((nw_host == null) ? "" : nw_host) + 
		   ":eth0:off " + bargs);
	}
	
	/* Build the domain */
	Process build_p;
	String build_cmdarray[] = new String[6];
	int build_rc;
	idx = 0;
	for (i = 0; i < build_cmdarray.length; i ++) 
	  build_cmdarray[i] = "";
	build_cmdarray[idx ++] = d.XIToolsDir + "xi_build";
	build_cmdarray[idx ++] = "" + domain_id;
	build_cmdarray[idx ++] = "" + image;
	build_cmdarray[idx ++] = "" + vifs;
	if (initrd != null) build_cmdarray[idx ++] = "initrd=" + initrd;
	build_cmdarray[idx ++] = "" + bargs;
	System.out.println ("Build args: " + bargs);
	if (Settings.TEST) {
	  reportCommand (build_cmdarray);
	  build_rc = 0;
	} else {
	  build_p = r.exec (build_cmdarray);
	  build_rc = build_p.waitFor ();
	}

	if (build_rc != 0) {
	  return reportXIError ("Failed to build domain", build_cmdarray);
	}


	/* Set up the first VIF if necessary */
	if (vifs > 0) {
	  Process vifinit_p;
	  String vifinit_cmdarray[] = new String[4];
	  int vifinit_rc;
	  vifinit_cmdarray[0] = d.XIToolsDir + "xi_vifinit";
	  vifinit_cmdarray[1] = "" + domain_id;
	  vifinit_cmdarray[2] = "0";
	  vifinit_cmdarray[3] = domain_ip;
	  if (Settings.TEST) {
	    reportCommand (vifinit_cmdarray);
	    vifinit_rc = 0;
	  } else {
	    vifinit_p = r.exec (vifinit_cmdarray);
	    vifinit_rc = vifinit_p.waitFor ();
	  }
	  
	  if (vifinit_rc != 0) {
	    return reportXIError ("Failed to initialise VIF 0", vifinit_cmdarray);
	  }
	}
      }
    catch (Exception e) 
      {
	System.err.println ("Could not create new domain (" + e + ")");
	e.printStackTrace ();
	rc = -1;
      }

    if (rc == 0) {
      System.out.println ("Created domain " + domain_id);
    }

    return rc;
  }

  public String getName()
  {
    return "new";
  }

  public String getUsage()
  {
    return "[-n<domain_name>] [-k<size>] [-i<image>] [-v<num_vifs>] [-r<initrd>] [-d<root_device>] [-f<nfs_root>] [-s<nfs_boot_server>] [-4<ipv4_boot_address>] [-g<ipv4_boot_gateway>] [-m<ipv4_boot_netmask>] [-h<hostname>] [-a<args>]";
  }

  public String getHelpText()
  {
    return
      "Create a new domain.  Note that most of the parameters will assume\n" +
      "default values: it should not be necessary to specify them all. See\n" +
      "domctl.xml for the current default settings.\n" +
      "\n" +
      "General command line options:\n" +
      "  -n  Domain name                              domain_name\n" +
      "  -k  Domain size (kb)                         domain_size_kb\n" +
      "  -i  Domain image name                        domain_image\n" +
      "  -v  Number of VIFs                           domain_vifs\n" +
      "  -r  InitRD (if required)                     domain_init_rd\n" +
      "  -d  Root device (e.g /dev/nfs, /dev/hda3)    root_device\n" +
      "  -a  Additional boot parameters\n" +
      "\n" +
      "Networking options:\n" +
      "  -f  NFS root (if /dev/nfs specified)         nw_nfs_root\n" +
      "  -s  NFS server                               nw_nfs_server\n" +
      "  -4  Domain IPv4 address                      nw_ip\n" +
      "  -g  Domain gateway                           nw_gw\n" +
      "  -m  Domain net mask                          nw_mask\n" +
      "  -h  Domain hostname                          nw_host\n" +
      "\n" +
      "Parameters to -d, -f, -4, -g, -h can be specified as patterns into\n" +
      "which the allocated domain ID will be incorporated.  e.g.  for\n" +
      "domain 1 patterns would expand as follows:\n" +
      "\n" +
      "  /dev/hda+       /dev/hda1\n" +
      "  /dev/hda7+      /dev/hda8\n" +
      "  128.232.8.50+   128.232.8.51\n" +
      "\n" +
      "Additionally, patterns for -4 -g -m can include an = which is\n" + 
      "expanded to the corresponding setting from the calling domain.\n";
  }
}
