package org.xenoserver.control;

import java.io.File;
import java.util.StringTokenizer;

/**
 * The Settings class is a repository for global settings such as the IP of
 * the machine and the location of the defaults file.
 */
public final class Settings {
    /** Filename for the defaults file. */
    public static final String DEFAULTS_FILE =
        System.getProperty("DEFAULTS_FILE", "xenctl.xml");
    /** Path to search for the defaults file. */
    public static final String DEFAULTS_PATH =
        System.getProperty("DEFAULTS_PATH", ".:/etc:/var/lib/xen");
    /** If set, do not call any xi_ commands, just print their command lines. */
    public static final boolean TEST = (System.getProperty("TEST") != null);
    /** Name of xi_helper utility. */
    public static final String XI_HELPER =
        System.getProperty("XI_HELPER", "xi_helper");
    /** File to parse to get partition info. */
    public static final String PARTITIONS_FILE =
        System.getProperty("PARTITIONS_FILE", "/proc/xeno/blkdev_info");
    /** File to load virtual disk state from. */
    public static final String STATE_INPUT_FILE =
        System.getProperty("STATE_INPUT_FILE", "/var/lib/xen/vdstate.xml");
    /** File to save virtual disk state to. */
    public static final String STATE_OUTPUT_FILE =
        System.getProperty("STATE_OUTPUT_FILE", "/var/lib/xen/vdstate.xml");
    /** Size of a sector in bytes. */
    public static final int SECTOR_SIZE =
        Integer.parseInt(System.getProperty("SECTOR_SIZE", "512"));

    /**
     * Search for the defaults file in the path configured in DEFAULTS_PATH.
     * @return Reference to the defaults file.
     */
    public static File getDefaultsFile() {
        StringTokenizer tok = new StringTokenizer(DEFAULTS_PATH, ":");
        File result = null;
        File probe;

        while (tok.hasMoreTokens()) {
            String probe_dir = tok.nextToken();
            probe = new File(probe_dir, DEFAULTS_FILE);
            if (probe.exists()) {
                result = probe;
                break;
            }
        }

        if (result == null) {
            System.err.println(
                "Could not find "
                    + DEFAULTS_FILE
                    + " in path "
                    + DEFAULTS_PATH);
        }

        return result;
    }
}
