package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandPhysicalGrant;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Extent;
import org.xenoserver.control.Mode;
import org.xenoserver.control.Partition;
import org.xenoserver.control.PartitionManager;

public class ParsePhysicalGrant extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    int domain_id = getIntParameter(args, 'n', 0);
    boolean force = getFlagParameter(args, 'f');
    String partition_name = getStringParameter(args, 'p', "");
    boolean write = getFlagParameter(args, 'w');
    
    if (domain_id == 0)
      throw new ParseFailedException("Expected -n<domain_id>");
    if (partition_name.equals(""))
      throw new ParseFailedException("Expected -p<partition_name>");
      
    Mode mode;
    if (write)
      mode = Mode.READ_WRITE;
    else
      mode = Mode.READ_ONLY;
      
    // Initialise the partition manager and look up the partition
    loadState();
    Partition p = PartitionManager.it.get_partition(partition_name);
    
    if ( p == null )
      throw new CommandFailedException("Partition " + partition_name + " does not exist.");
    
    // Check if this partition belongs to the VDM
    if (p.getIsXeno() && !force)
      throw new CommandFailedException("Refusing to grant physical access as the given partition is allocated to the virtual disk manager. Use -f if you are sure.");
     
    // Convert the partition into a physical extent
    Extent e = p.toExtent();
    int partition_no = p.getMinor() & 0x1F;
    
    String output = new CommandPhysicalGrant( d, domain_id, e, mode, partition_no ).execute();
    if ( output != null )
      System.out.println( output );
  }

  public String getName() {
    return "grant";
  }

  public String getUsage() {
    return "[-f] [-w] [-n<domain_id>] [-p<partition_name>]";
  }

  public String getHelpText() {
    return "Grant the specified domain access to the given partition.  -w grants" +
           " read-write instead of read-only.  -f forcibly grants access.";
  }

}
