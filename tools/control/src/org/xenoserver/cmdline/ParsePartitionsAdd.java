package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandPartitionAdd;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Library;
import org.xenoserver.control.Partition;
import org.xenoserver.control.PartitionManager;
import org.xenoserver.control.Settings;

public class ParsePartitionsAdd extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    boolean force = getFlagParameter(args, 'f');
    String partition_name = getStringParameter(args, 'p', "");
    String size = getStringParameter(args, 'c', "128M");
    
    if (partition_name.equals("")) {
      throw new ParseFailedException("Expected -p<partition_name>");
    }
      
    long chunksize = Library.parseSize( size ) / Settings.SECTOR_SIZE;
    if ( chunksize <= 0 ) {
      throw new CommandFailedException("Chunk size " + size + " is smaller than sector size.");
    }
    
    // Initialise the partition manager and look up the partition
    loadState();
    Partition p = PartitionManager.IT.getPartition(partition_name);
    
    if ( p == null ) {
      throw new CommandFailedException("Partition " + partition_name + " does not exist.");
    }
    
    // Check if this partition belongs to the VDM
    if (p.isXeno() && !force) {
      throw new CommandFailedException("Refusing to add partition as it is already allocated to the virtual disk manager. Use -f if you are sure.");
    }
    
    String output = new CommandPartitionAdd( p, chunksize ).execute();
    if ( output != null ) {
      System.out.println( output );
    }
    saveState();
  }

  public String getName() {
    return "add";
  }

  public String getUsage() {
    return "-p<partition_name> [-f] [-c<chunk_size>]";
  }

  public String getHelpText() {
    return "Add the specified partition to the virtual disk manager's free\n" +
           "space. -c changes the default chunk size. -f forces add.";
  }
}
