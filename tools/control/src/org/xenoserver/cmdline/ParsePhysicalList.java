package org.xenoserver.cmdline;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map.Entry;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandPhysicalList;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Extent;
import org.xenoserver.control.Library;
import org.xenoserver.control.Partition;
import org.xenoserver.control.PartitionManager;

public class ParsePhysicalList extends CommandParser {

  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    int domain_id = getIntParameter(args, 'n', 0);
    if (domain_id == 0)
      throw new ParseFailedException("Expected -n<domain_id>");

    // Initialise the partition manager
    loadState();
    
    CommandPhysicalList list = new CommandPhysicalList( d, domain_id );
    String output = list.execute();
    if ( output != null )
      System.out.println( output );
      
    System.out.println( "maj:min " + "    blocks " + "start sect " +
                        " num sects " + "name    " + "access" );
    Iterator i = list.extents().entrySet().iterator();
    while ( i.hasNext() )
    {
      Entry entry = (Entry) i.next(); 
      Extent e = (Extent) entry.getKey();
      String mode = entry.getValue().toString();
      Partition p = PartitionManager.it.get_partition( e );
      if ( p != null ) {
        System.out.println(Library.format(p.getMajor(),3,0) + ":" + 
          Library.format(p.getMinor(),3,1) + " " +
          Library.format(p.getBlocks(),10,0) + " " +
          Library.format(p.getStartSect(),10,0) + " " +
          Library.format(p.getNumSects(),10,0) + " " +
          Library.format(p.getName(),7,1) + " " +
          Library.format(mode,2,1));   
      } else {
        System.out.println(Library.format(e.getMajor(),3,0) + ":" +
          Library.format(e.getMinor(),3,1) + " " +
          "          " + " " +
          Library.format(e.getOffset(),10,0) + " " +
          Library.format(e.getSize(),10,0) + " " +
          "       " + " " +
          Library.format(mode,2,1));
      }
    }
  }

  public String getName() {
    return "list";
  }

  public String getUsage() {
    return "[-n<domain_id>]";
  }

  public String getHelpText() {
    return "List all physical access which the given domain has been granted.";
  }

}
