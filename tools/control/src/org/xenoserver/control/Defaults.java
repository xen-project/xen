package org.xenoserver.control;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

/**
 * The Defaults class stores the default settings to be used by the
 * management utilities. On construction it parses the defaults file
 * located through the Settings class.
 */
public class Defaults {
    /** Default domain name. */
    public String domainName;
    /** Default domain memory size in KB. */
    public int domainSizeKB;
    /** Default domain kernel image. */
    public String domainImage;
    /** Default domain initrd. */
    public String domainInitRD;
    /** Default number of virtual interfaces. */
    public int domainVIFs;
    /** Default root device. */
    public String rootDevice;
    /** Default usr device. */
    public String usrDevice;
    /** Default IP address pattern. */
    public String nwIP;
    /** Default gateway pattern. */
    public String nwGateway;
    /** Default netmask patterh. */
    public String nwMask;
    /** Default hostname pattern. */
    public String nwHost;
    /** Default NFS server pattern. */
    public String nwNFSServer;
    /** Default NFS root pattern. */
    public String nwNFSRoot;
    /** Maximum domain number. */
    public int maxDomainNumber = Integer.MAX_VALUE;
    /** Default boot arguments. */
    public String args = "";
    /** Directory to find XI tools. */
    public String xiToolsDir = "";
    /** Domain number */
    public int domainNumber;

    
    /**
     * Create defaults instance and parse the defaults file.
     */
    public Defaults() {
        File f = Settings.getDefaultsFile();

        if (f == null) {
            return;
        }

        try {
            XMLReader xr = new org.apache.crimson.parser.XMLReaderImpl();
            Handler handler = new Handler();
            xr.setContentHandler(handler);
            xr.setErrorHandler(handler);
            xr.parse(new InputSource(new FileReader(f)));
        } catch (Exception e) {
            System.err.println(
                "Could not read defaults file " + f + "\nException: " + e);
            e.printStackTrace();
            return;
        }
    }

    /**
     * Describe the defaults to System.out
     */
    public void describe() {
        System.out.println("Domain defaults:");
        System.out.println("   name            " + domainName);
        System.out.println("   size            " + domainSizeKB);
        System.out.println("   vifs            " + domainVIFs);
        System.out.println("   domainImage     " + domainImage);
        System.out.println("   domainInitRD    " + domainInitRD);
        System.out.println("   rootDevice      " + rootDevice);
        System.out.println("   usrDevice       " + usrDevice);
        System.out.println("   NWIP            " + nwIP);
        System.out.println("   NWGW            " + nwGateway);
        System.out.println("   NWMask          " + nwMask);
        System.out.println("   MaxDomainNumber " + maxDomainNumber);
        System.out.println("   NWNFSServer     " + nwNFSServer);
        System.out.println("   NWNFSRoot       " + nwNFSRoot);
        System.out.println("   XIToolsDir      " + xiToolsDir);
        System.out.println("   args            " + args);
    }

    /**
     * SAX event handler.
     */
    private class Handler extends DefaultHandler {
        /** Are we inside the defaults node. */
        boolean inDomctlDefaults;
        /** Last element name read. */
        String lastName;

        /**
         * @see org.xml.sax.ContentHandler#startElement(java.lang.String, java.lang.String, java.lang.String, org.xml.sax.Attributes)
         */
        public void startElement(
            String uri,
            String name,
            String qname,
            Attributes atts) {
            if (qname.equals("domctl_defaults")) {
                inDomctlDefaults = true;
            } else {
                lastName = qname;
            }
        }

        /**
         * @see org.xml.sax.ContentHandler#endElement(java.lang.String, java.lang.String, java.lang.String)
         */
        public void endElement(String uri, String name, String qname) {
            lastName = "";
            if (qname.equals("domctl_defaults")) {
                inDomctlDefaults = false;
            }
        }

        /**
         * @see org.xml.sax.ContentHandler#characters(char[], int, int)
         */
        public void characters(char ch[], int start, int length) {
            String s = new String(ch, start, length);
            if (lastName != null) {
                if (lastName.equals("domain_size_kb")) {
                    domainSizeKB = Integer.parseInt(s);
                } else if (lastName.equals("domain_image")) {
                    domainImage = s;
                } else if (lastName.equals("domain_name")) {
                    domainName = s;
                } else if (lastName.equals("domain_number")) {
                    domainNumber = Integer.parseInt(s);
                } else if (lastName.equals("domain_init_rd")) {
                    domainInitRD = s;
                } else if (lastName.equals("domain_vifs")) {
                    domainVIFs = Integer.parseInt(s);
                } else if (lastName.equals("root_device")) {
                    rootDevice = s;
                } else if (lastName.equals("usr_device")) {
                    usrDevice = s;
                } else if (lastName.equals("nw_ip")) {
                    nwIP =
                        expandDefault(
                            s,
                            runCommand(xiToolsDir + Settings.XI_HELPER + " ip")
                                .trim());
                } else if (lastName.equals("nw_gw")) {
                    nwGateway =
                        expandDefault(
                            s,
                            runCommand(
                                xiToolsDir + Settings.XI_HELPER + " route")
                                .trim());
                } else if (lastName.equals("nw_mask")) {
                    nwMask =
                        expandDefault(
                            s,
                            runCommand(
                                xiToolsDir + Settings.XI_HELPER + " mask")
                                .trim());
                } else if (lastName.equals("nw_host")) {
                    nwHost = s;
                } else if (lastName.equals("nw_nfs_server")) {
                    nwNFSServer = s;
                } else if (lastName.equals("nw_nfs_root")) {
                    nwNFSRoot = s;
                } else if (lastName.equals("args")) {
                    args = s;
                } else if (lastName.equals("max_domain_number")) {
                    maxDomainNumber = Integer.parseInt(s);
                } else if (lastName.equals("xi_tools_dir")) {
                    xiToolsDir = s;
                }
            }
        }
    }

    /**
     * Expand a defaults pattern.
     * @param supplied Supplied pattern.
     * @param self Own value for variable.
     * @return Appropriate value.
     */
    private String expandDefault(String supplied, String self) {
        if (supplied.startsWith("=")) {
            if (supplied.length() > 1) {
                return self + supplied.substring(1, supplied.length());
            } else {
                return self;
            }
        } else {
            return supplied;
        }
    }

    /**
     * Run a command for the Defaults object.
     * @param command Command string to run.
     * @return Command's output.
     */
    String runCommand(String command) {
        Runtime runtime = Runtime.getRuntime();
        String outline;
        StringBuffer output = new StringBuffer();

        try {
            Process process = runtime.exec(command);
            BufferedReader in =
                new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            outline = in.readLine();
            while (outline != null) {
                output.append("\n" + outline);
                outline = in.readLine();
            }
        } catch (IOException e) {
            return e.toString();
        }

        return output.toString();
    }

}
