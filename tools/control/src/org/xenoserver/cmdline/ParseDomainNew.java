package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandDomainNew;
import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandPhysicalGrant;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Mode;
import org.xenoserver.control.StringPattern;

public class ParseDomainNew extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        String name = getStringParameter(args, 'n', d.domainName);
        int size = getIntParameter(args, 'k', d.domainSizeKB);
        String image = getStringParameter(args, 'i', d.domainImage);
        String initrd = getStringParameter(args, 'r', d.domainInitRD);
        int vifs = getIntParameter(args, 'v', d.domainVIFs);
        String bargs = getStringParameter(args, 'a', d.args);
        String root_dev = getStringParameter(args, 'd', d.rootDevice);
        String root_args = getStringParameter(args, 't', d.rootArgs);
        String usr_dev = getStringParameter(args, 'u', d.usrDevice);
        String nfs_root_path = getStringParameter(args, 'f', d.nwNFSRoot);
        String nw_ip = getStringParameter(args, '4', d.nwIP);
        String nw_gw = getStringParameter(args, 'g', d.nwGateway);
        String nw_mask = getStringParameter(args, 'm', d.nwMask);
        String nw_nfs_server = getStringParameter(args, 's', d.nwNFSServer);
        String nw_host = getStringParameter(args, 'h', d.nwHost);
	int subst = getIntParameter(args, 'x', -1);

        d.describe();

        CommandDomainNew c =
            new CommandDomainNew(
                d,
                name,
                size,
                image,
                initrd,
                vifs,
                bargs,
                root_dev,
                root_args,
                nfs_root_path,
                nw_ip,
                nw_gw,
                nw_mask,
                nw_nfs_server,
                nw_host,
                usr_dev,
		subst);
        c.execute();
        String[] output = c.output();
        for (int i = 0; i < output.length; i++) {
            System.out.println(output[i]);
        }
        
        if (root_dev.startsWith("/dev/sda") || root_dev.startsWith("/dev/hda")) {
            String real_root = StringPattern.parse(root_dev).resolve(c.domain_id());
            String device = real_root.substring(real_root.indexOf('/',1)+1);
            CommandPhysicalGrant cg = new CommandPhysicalGrant(d,c.domain_id(),device,Mode.READ_WRITE,false,subst);
            String output2 = cg.execute();
            if ( output2 != null ) {
                System.out.println(output2);
            }
        }
        
        if (usr_dev != null && ((usr_dev.startsWith("/dev/sda")) || usr_dev.startsWith("/dev/hda"))) {
            String real_usr = StringPattern.parse(usr_dev).resolve(c.domain_id());
            String device = real_usr.substring(real_usr.indexOf('/',1)+1);
            CommandPhysicalGrant cg = new CommandPhysicalGrant(d,c.domain_id(),device,Mode.READ_ONLY,false,subst);
            String output2 = cg.execute();
            if ( output2 != null ) {
                System.out.println(output2);
            }
        }
    }

    public String getName() {
        return "new";
    }

    public String getUsage() {
        return "[-n<domain_name>] [-k<size>] [-i<image>] [-v<num_vifs>] [-r<initrd>] [-d<root_device>] [-t<root_mount_args>] [-u<usr_device>] [-f<nfs_root>] [-s<nfs_boot_server>] [-4<ipv4_boot_address>] [-g<ipv4_boot_gateway>] [-m<ipv4_boot_netmask>] [-h<hostname>] [-a<args>] [-x<subst>]";
    }

    public String getHelpText() {
        return "Create a new domain.  Note that most of the parameters will assume\n"
            + "default values: it should not be necessary to specify them all. See\n"
            + "xenctl.xml for the current default settings.\n"
            + "\n"
            + "General command line options:\n"
            + "  -n  Domain name                              domain_name\n"
            + "  -k  Domain size (kb)                         domain_size_kb\n"
            + "  -i  Domain image name                        domain_image\n"
            + "  -v  Number of VIFs                           domain_vifs\n"
            + "  -r  InitRD (if required)                     domain_init_rd\n"
            + "  -d  Root device (e.g /dev/nfs, /dev/hda3)    root_device\n"
            + "  -t  Root mount args (e.g ro)                 root_args\n"
            + "  -u  Usr dev/path (e.g /dev/hda3, server:path)usr_device\n"
            + "  -a  Additional boot parameters               args\n"
            + "  -x  Number to substitute for + if not domain id\n"
            + "\n"
            + "Networking options:\n"
            + "  -f  NFS root (if /dev/nfs specified)         nw_nfs_root\n"
            + "  -s  NFS server                               nw_nfs_server\n"
            + "  -4  Domain IPv4 address                      nw_ip\n"
            + "  -g  Domain gateway                           nw_gw\n"
            + "  -m  Domain net mask                          nw_mask\n"
            + "  -h  Domain hostname                          nw_host\n"
            + "\n"
            + "Parameters to -d, -f, -4, -g, -h can be specified as patterns into\n"
            + "which the allocated domain ID will be incorporated.  e.g.  for\n"
            + "domain 1 patterns would expand as follows:\n"
            + "\n"
            + "  /dev/hda+       /dev/hda1\n"
            + "  /dev/hda7+      /dev/hda8\n"
            + "  128.232.8.50+   128.232.8.51\n"
            + "\n"
            + "Additionally, patterns for -4 -g -m can include an = which is\n"
            + "expanded to the corresponding setting from the calling domain.\n";
    }
}
