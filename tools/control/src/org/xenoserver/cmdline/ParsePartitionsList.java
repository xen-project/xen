package org.xenoserver.cmdline;

import java.util.Iterator;
import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Library;
import org.xenoserver.control.Partition;
import org.xenoserver.control.PartitionManager;
import org.xenoserver.control.Settings;
import org.xenoserver.control.XML;

public class ParsePartitionsList extends CommandParser {

  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    XML.load_state( PartitionManager.it, Settings.STATE_INPUT_FILE );
    Iterator i = PartitionManager.it.iterator();
    int idx = 1;
    System.out.println( "     maj:min " + "    blocks " + "start sect " +
                        " num sects " + "name" );
    while (i.hasNext()) {
      Partition p = (Partition) i.next();

      if (p.getIsXeno()) {
        System.out.print("[ ");
      } else {
        System.out.print("  ");
      }
      System.out.print(Library.format(idx++, 2, 0) + " ");
      System.out.print(Library.format(p.getMajor(),3,0) + ":" + 
          Library.format(p.getMinor(),3,1) + " " +
          Library.format(p.getBlocks(),10,0) + " " +
          Library.format(p.getStartSect(),10,0) + " " +
          Library.format(p.getNumSects(),10,0) + " " +
          Library.format(p.getName(),7,1));   
      if (p.getIsXeno()) {
        System.out.println("]");
      } else {
        System.out.println();
      }
    }
  }

  public String getName() {
    return "list";
  }

  public String getUsage() {
    return "";
  }

  public String getHelpText() {
    return "List real partition information";
  }

}
