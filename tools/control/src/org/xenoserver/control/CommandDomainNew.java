package org.xenoserver.control;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.NumberFormatException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.zip.GZIPInputStream;

/**
 * Creates a new domain. As this command returns a multi-line result,
 * call output() to get an array of strings.
 */
public class CommandDomainNew extends Command {
    /** Defaults instance in use. */
    private Defaults d;
    /** Name of new domain. */
    private String name;
    /** Memory size for new domain. */
    private int size;
    /** Kernel image */
    private String image;
    /** Initial ramdisk */
    private String initrd;
    /** Num of virtual interfaces */
    private int vifs;
    /** Boot arguments */
    private String bargs;
    /** Root device */
    private String root_dev;
    /** Usr device */
    private String usr_dev;
    /** NFS root path */
    private String nfs_root_path;
    /** IP address */
    private String nw_ip;
    /** Gateway */
    private String nw_gw;
    /** netmask */
    private String nw_mask;
    /** NFS server */
    private String nw_nfs_server;
    /** Hostname */
    private String nw_host;
    /** Output from domain creation */
    private String[] output;
    /** Domain ID created. */
    private int domain_id;

    /**
     * @return Output from domain creation.
     */
    public String[] output() {
        return output;
    }
    
    /**
     * @return The domain id this command created.
     */
    public int domain_id() {
        return domain_id;
    }

    /**
     * Constructor for CommandDomainNew.
     * @param d Defaults object to use.
     * @param name Name for the domain.
     * @param size Memory size for the domain.
     * @param image Image to boot domain from.
     * @param initrd Initrd to boot domain with.
     * @param vifs Number of virtual interfaces for the domain.
     * @param bargs Boot arguments for the domain.
     * @param root_dev Root device for the domain.
     * @param nfs_root_path NFS root to be used by the domain.
     * @param nw_ip IP address pattern to use for the domain's interfaces.
     * @param nw_gw Gateway to configure the domain for.
     * @param nw_mask Network mask to configure the domain for.
     * @param nw_nfs_server NFS server to be used by the domain.
     * @param nw_host Hostname to be used by the domain.
     */
    public CommandDomainNew(
        Defaults d,
        String name,
        int size,
        String image,
        String initrd,
        int vifs,
        String bargs,
        String root_dev,
        String nfs_root_path,
        String nw_ip,
        String nw_gw,
        String nw_mask,
        String nw_nfs_server,
        String nw_host) {
        this(d,name,size,image,initrd,vifs,bargs,root_dev,nfs_root_path,nw_ip,nw_gw,nw_mask,nw_nfs_server,nw_host,null);
    }
    
    public CommandDomainNew(
        Defaults d,
        String name,
        int size,
        String image,
        String initrd,
        int vifs,
        String bargs,
        String root_dev,
        String nfs_root_path,
        String nw_ip,
        String nw_gw,
        String nw_mask,
        String nw_nfs_server,
        String nw_host,
        String usr_dev) {
            this.d = d;
            this.name = name;
            this.size = size;
            this.image = image;
            this.initrd = initrd;
            this.vifs = vifs;
            this.bargs = bargs;
            this.root_dev = root_dev;
            this.nfs_root_path = nfs_root_path;
            this.nw_ip = nw_ip;
            this.nw_gw = nw_gw;
            this.nw_mask = nw_mask;
            this.nw_nfs_server = nw_nfs_server;
            this.nw_host = nw_host;
            this.usr_dev = usr_dev;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        Runtime r = Runtime.getRuntime();
        int domain_id = -1;
        BufferedReader br;
        int idx;
        int i;
        File image_tmp = null;
        File initrd_tmp = null;
        String domain_ip = "";

        String create_cmdarray[] = new String[3];
        String build_cmdarray[] = new String[6];
        String vifinit_cmdarray[] = new String[4];

        try {
            try {
                /* Some initial sanity checks */
                if (root_dev.equals("/dev/nfs") && (vifs == 0)) {
                    throw new CommandFailedException("Cannot use NFS root without VIFs configured");
                }

                /* Uncompress the image and initrd */
                if (image.endsWith(".gz")) {
                    image_tmp = getUncompressed("xen-image-", image);
                    image = image_tmp.getPath();
                }

                if (initrd != null && initrd.endsWith(".gz")) {
                    initrd_tmp = getUncompressed("xen-initrd-", initrd);
                    initrd = initrd_tmp.getPath();
                }

                /* Create a new empty domain */
                Process create_p;
                int create_rc;
                create_cmdarray[0] = d.xiToolsDir + "xi_create";
                create_cmdarray[1] = "" + size;
                create_cmdarray[2] = name;
                if (Settings.TEST) {
                    reportCommand(create_cmdarray);
                    domain_id = 1;
                    create_rc = 0;
                } else {
                    create_p = r.exec(create_cmdarray);
                    br =
                        new BufferedReader(
                            new InputStreamReader(create_p.getInputStream()));
		    try
		      {
			domain_id = Integer.parseInt(br.readLine());
		      }
		    catch (NumberFormatException nfe) 
		      {
			domain_id = -1;
		      }
                    create_rc = create_p.waitFor();
                }
		d.domainNumber = domain_id;

                if (create_rc != 0) {
                    throw CommandFailedException.xiCommandFailed(
                        "Failed to create domain",
                        create_cmdarray);
                } else if (domain_id > d.maxDomainNumber) {
                    throw new CommandFailedException(
                        "Cannot configure more than "
                            + d.maxDomainNumber
                            + " domains");
                }

                /* Set up boot parameters to pass to xi_build. */
                if (root_dev.equals("/dev/nfs")) {
                    if (vifs == 0) {
                        throw new CommandFailedException("Cannot use NFS root without VIFs configured");
                    }
                    if (nfs_root_path == null) {
                        throw new CommandFailedException("No NFS root specified");
                    }
                    if (nw_nfs_server == null) {
                        throw new CommandFailedException("No NFS server specified");
                    }
                    bargs =
                        (bargs
                            + " root=/dev/nfs "
                            + "nfsroot="
                            + StringPattern.parse(nfs_root_path).resolve(
                                domain_id)
                            + " ");
                } else {
                    bargs =
                        (bargs
                            + " root="
                            + StringPattern.parse(root_dev).resolve(domain_id)
                            + " ro ");

                }
                
                if (usr_dev != null && !usr_dev.equals("")) {
                    bargs = bargs + " usr=" + StringPattern.parse(usr_dev).resolve(domain_id) + " ";
                }

                if (vifs > 0) {
                    domain_ip =
                        InetAddressPattern.parse(nw_ip).resolve(domain_id);
                 /*   if (nw_host == null) {
                        try {
                            nw_host =
                                InetAddress.getByName(domain_ip).getHostName();
                        } catch (UnknownHostException uhe) {
                            nw_host = "" + nw_ip;
                        }

                    }*/
                    bargs =
                        ("ip="
                            + domain_ip
                            + ":"
                            + ((nw_nfs_server == null)
                                ? ""
                                : (InetAddressPattern
                                    .parse(nw_nfs_server)
                                    .resolve(domain_id)))
                            + ":"
                            + ((nw_gw == null)
                                ? ""
                                : (InetAddressPattern
                                    .parse(nw_gw)
                                    .resolve(domain_id)))
                            + ":"
                            + ((nw_mask == null)
                                ? ""
                                : InetAddressPattern.parse(nw_mask).resolve(
                                    domain_id))
                            + ":"
                            + ((nw_host == null) ? "" : nw_host)
                            + ":eth0:off "
                            + bargs);
                }

                /* Build the domain */
                Process build_p;
                int build_rc;
                idx = 0;
                for (i = 0; i < build_cmdarray.length; i++) {
                    build_cmdarray[i] = "";
                }
                build_cmdarray[idx++] = d.xiToolsDir + "xi_build";
                build_cmdarray[idx++] = "" + domain_id;
                build_cmdarray[idx++] = "" + image;
                build_cmdarray[idx++] = "" + vifs;
                if (initrd != null) {
                    build_cmdarray[idx++] = "initrd=" + initrd;
                }
                build_cmdarray[idx++] = "" + bargs;
                if (Settings.TEST) {
                    reportCommand(build_cmdarray);
                    build_rc = 0;
                } else {
                    build_p = r.exec(build_cmdarray);
                    build_rc = build_p.waitFor();
                }

                if (build_rc != 0) {
                    throw CommandFailedException.xiCommandFailed(
                        "Failed to build domain",
                        build_cmdarray);
                }

                /* Set up the first VIF if necessary */
                if (vifs > 0) {
                    Process vifinit_p;
                    int vifinit_rc;
                    vifinit_cmdarray[0] = d.xiToolsDir + "xi_vifinit";
                    vifinit_cmdarray[1] = "" + domain_id;
                    vifinit_cmdarray[2] = "0";
                    vifinit_cmdarray[3] = domain_ip;
                    if (Settings.TEST) {
                        reportCommand(vifinit_cmdarray);
                        vifinit_rc = 0;
                    } else {
                        vifinit_p = r.exec(vifinit_cmdarray);
                        vifinit_rc = vifinit_p.waitFor();
                    }

                    if (vifinit_rc != 0) {
                        throw CommandFailedException.xiCommandFailed(
                            "Failed to initialise VIF 0",
                            vifinit_cmdarray);
                    }
                }
            } finally {
                if (image_tmp != null) {
                    image_tmp.delete();
                }
                if (initrd_tmp != null) {
                    initrd_tmp.delete();
                }
            }
        } catch (CommandFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailedException(
                "Could not create new domain (" + e + ")",
                e);
        }

        output = new String[vifs > 0 ? 6 : 4];
        output[0] = "Domain created with arguments:";
        output[1] = "";
        for (i = 0; i < create_cmdarray.length; i++) {
            output[1] += create_cmdarray[i] + " ";
        }
        output[2] = "Domain built with arguments:";
        output[3] = "";
        for (i = 0; i < build_cmdarray.length; i++) {
            output[3] += build_cmdarray[i] + " ";
        }
        if (vifs > 0) {
            output[4] = "VIF 0 initialized with arguments:";
            output[5] = "";
            for (i = 0; i < vifinit_cmdarray.length; i++) {
                output[5] += vifinit_cmdarray[i] + " ";
            }
        }
        
        this.domain_id = domain_id;

        return null;
    }

    /**
     * Get uncompressed version of file.
     * @param prefix Temp file prefix.
     * @param original Original filename.
     * @return Uncompressed file.
     * @throws IOException if decompression failed.
     */
    private File getUncompressed(String prefix, String original)
        throws IOException {
        FileOutputStream fos;
        GZIPInputStream gis;
        File result;
        byte buffer[] = new byte[1024];
        int l;

        result = File.createTempFile(prefix, null);

        try {
            fos = new FileOutputStream(result);
            gis = new GZIPInputStream(new FileInputStream(original));
            while ((l = gis.read(buffer, 0, buffer.length)) != -1) {
                fos.write(buffer, 0, l);
            }
        } catch (IOException ioe) {
            result.delete();
            throw ioe;
        }

        return result;
    }
}
