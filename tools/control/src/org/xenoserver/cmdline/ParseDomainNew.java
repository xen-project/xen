package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandDomainNew;
import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

public class ParseDomainNew extends CommandParser {

  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    String name = getStringParameter(args, 'n', d.domainName);
    int size = getIntParameter(args, 'k', d.domainSizeKB);
    String image = getStringParameter(args, 'i', d.domainImage);
    String initrd = getStringParameter (args, 'r', d.domainInitRD);
    int vifs = getIntParameter(args, 'v', d.domainVIFs);
    String bargs = getStringParameter (args, 'a', d.args) + " ";
    String root_dev = getStringParameter (args, 'd', d.rootDevice);
    String nfs_root_path = getStringParameter (args, 'f', d.nwNFSRoot);
    String nw_ip = getStringParameter (args, '4', d.nwIP);
    String nw_gw = getStringParameter (args, 'g', d.nwGateway);
    String nw_mask = getStringParameter (args, 'm', d.nwMask);
    String nw_nfs_server = getStringParameter (args, 's', d.nwNFSServer);
    String nw_host = getStringParameter (args, 'h', d.nwHost);

    d.describe();

    CommandDomainNew c = new CommandDomainNew(d, name, size, image, initrd, vifs,
                                  bargs, root_dev, nfs_root_path,
                                  nw_ip, nw_gw, nw_mask, nw_nfs_server, nw_host);
    c.execute();
    String[] output = c.output();
    for ( int i = 0; i < output.length; i++ )
      System.out.println( output[i] ); 
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
