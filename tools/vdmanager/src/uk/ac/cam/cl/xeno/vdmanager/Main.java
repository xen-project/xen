/*
 * Main.java
 * 03.03.26 aho creation
 */

package uk.ac.cam.cl.xeno.vdmanager;

import java.util.Date;

public class
Main
{
  static String state_filename_in  = "/var/run/vdmanager.xml";
  static String state_filename_out = "/var/run/vdmanager.xml";
  static String partition_filename = "/proc/partitions";

  void
  go (String[] argv)
  {
    PartitionManager pm = new PartitionManager(partition_filename);
    VirtualDiskManager vdm = new VirtualDiskManager();;
    Parser parser = new Parser(pm, vdm);

    XML.load_state(pm, vdm, state_filename_in);
    parser.parse_main(argv);
    XML.dump_state(pm, vdm, state_filename_out);
  }

  public static void
  main (String[] argv)
  {
    Main foo = new Main();
    foo.go(argv);
  }
}
