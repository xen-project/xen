package org.xenoserver.cmdline;

import java.util.Iterator;
import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Extent;
import org.xenoserver.control.Library;
import org.xenoserver.control.Settings;
import org.xenoserver.control.VirtualDisk;
import org.xenoserver.control.VirtualDiskManager;

public class ParseVdFree extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    boolean verbose = getFlagParameter(args, 'v');
    
    loadState();
    VirtualDisk free = VirtualDiskManager.it.getFreeVirtualDisk();
    System.out.println( "Free disk has " + free.getExtentCount() + " extents totalling "
                      + Library.format_size(free.getSize()*Settings.SECTOR_SIZE,8,1) );
    if ( verbose ) {
      Iterator i = free.iterator();
      System.out.println("  disk       offset         size");
      while (i.hasNext()) {
        Extent e = (Extent) i.next();
        System.out.println( Library.format(e.getDisk(), 6, 0) + " "
                          + Library.format(e.getOffset(), 12, 0) + " "
                          + Library.format(e.getSize(), 12, 0) );
      }
    }
  }

  public String getName() {
    return "free";
  }

  public String getUsage() {
    return "[-v]";
  }

  public String getHelpText() {
    return "Show free space allocated to virtual disk manager. -v enables verbose output.";
  }
}
