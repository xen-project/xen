package uk.ac.cam.cl.xeno.domctl;

import java.util.*;
import java.io.*;
import org.xml.sax.*;

public final class Settings
{
  public static final String DEFAULTS_FILE = System.getProperty ("DEFAULTS_FILE");
  public static final String DEFAULTS_PATH = System.getProperty ("DEFAULTS_PATH");
  public static final String LOCAL_IP = System.getProperty ("LOCAL_IP");
  public static final String LOCAL_MASK = System.getProperty ("LOCAL_MASK");
  public static final String LOCAL_GW = System.getProperty ("LOCAL_ROUTE");
  public static final boolean TEST = (System.getProperty ("TEST") != null);


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
      System.exit (1);
    }

    return result;
  }
}
