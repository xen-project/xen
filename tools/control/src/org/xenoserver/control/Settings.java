package org.xenoserver.control;

import java.io.File;
import java.util.StringTokenizer;

/**
 * The Settings class is a repository for global settings such as the IP of
 * the machine and the location of the defaults file.
 */
public final class Settings
{
  public static final String DEFAULTS_FILE = System.getProperty ("DEFAULTS_FILE", "domctl.xml");
  public static final String DEFAULTS_PATH = System.getProperty ("DEFAULTS_PATH", ".:/etc:/var/lib/xen");
  public static final String LOCAL_IP = System.getProperty ("LOCAL_IP");
  public static final String LOCAL_MASK = System.getProperty ("LOCAL_MASK");
  public static final String LOCAL_GW = System.getProperty ("LOCAL_ROUTE");
  public static final boolean TEST = (System.getProperty ("TEST") != null);
  public static final String XI_HELPER = System.getProperty ("XI_HELPER", "xi_helper");
  public static final String PARTITIONS_FILE = System.getProperty("PARTITIONS_FILE", "/proc/partitions");
  public static final String STATE_INPUT_FILE = System.getProperty("STATE_INPUT_FILE", "/var/lib/xen/vdstate.xml");
  public static final String STATE_OUTPUT_FILE = System.getProperty("STATE_OUTPUT_FILE", "/var/lib/xen/vdstate.xml");
  public static final int SECTOR_SIZE = Integer.parseInt( System.getProperty("SECTOR_SIZE", "512") );

  public static File getDefaultsFile() {
    StringTokenizer tok = new StringTokenizer (DEFAULTS_PATH, ":");
    File result = null;
    File probe;

    while (tok.hasMoreTokens ()) {
      String probe_dir = tok.nextToken ();
      probe = new File (probe_dir, DEFAULTS_FILE);
      if (probe.exists ()) {
	result = probe;
	break;
      }
    }

    if (result == null) {
      System.err.println ("Could not find " + DEFAULTS_FILE + " in path " + DEFAULTS_PATH);
    }

    return result;
  }
}
