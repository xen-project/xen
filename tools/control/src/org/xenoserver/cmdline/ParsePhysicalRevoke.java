package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandPhysicalRevoke;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Extent;
import org.xenoserver.control.Partition;
import org.xenoserver.control.PartitionManager;

public class ParsePhysicalRevoke extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    int domain_id = getIntParameter(args, 'n', 0);
    String partition_name = getStringParameter(args, 'p', "");
    
    if (domain_id == 0)
      throw new ParseFailedException("Expected -n<domain_id>");
    if (partition_name.equals(""))
      throw new ParseFailedException("Expected -p<partition_name>");
      
    // Initialise the partition manager and look up the partition
    loadState();
    Partition p = PartitionManager.IT.getPartition(partition_name);
    
    if ( p == null )
      throw new CommandFailedException("Partition " + partition_name + " does not exist.");

    // Convert the partition into a physical extent
    Extent e = p.toExtent();
    
    String output = new CommandPhysicalRevoke( d, domain_id, e ).execute();
    if ( output != null )
      System.out.println( output );
  }

  public String getName() {
    return "revoke";
  }

  public String getUsage() {
    return "[-n<domain_id>] [-p<partition_name>]";
  }

  public String getHelpText() {
    return "Revoke access to the given partition from the specified domain.";
  }

}
