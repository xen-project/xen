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

public class ParseVdShow extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    int vd_num = getIntParameter(args,'n',-1);
    
    loadState();
    
    if ( vd_num < 0 ) {
      System.out.println("num key        expiry                       name                 size");
      for (int i=0;i<VirtualDiskManager.it.getVirtualDiskCount();i++) {
        VirtualDisk vd = VirtualDiskManager.it.getVirtualDisk(i);
        System.out.print( Library.format(i,3,0) + " " + vd.getKey() + " " );
        if ( vd.getExpiry() != null )
          System.out.print( vd.getExpiry().toString() );
        else
          System.out.print( "                            " );
        System.out.println( " " + Library.format(vd.getName(),16,1) + " "
                          + Library.format_size(vd.getSize()*Settings.SECTOR_SIZE,8,0) );
      }
    } else {
      VirtualDisk vd = VirtualDiskManager.it.getVirtualDisk(vd_num);
      if ( vd == null )
        throw new CommandFailedException("There is no virtual disk " + vd_num );
        
      System.out.println("  name: " + vd.getName());
      System.out.println("   key: " + vd.getKey());
      System.out.println("  size: " + Library.format_size(vd.getSize()*Settings.SECTOR_SIZE,8,1));
      if ( vd.getExpiry() != null )
        System.out.println("expiry: " + vd.getExpiry());
      System.out.println();
 
      Iterator i = vd.iterator();
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
    return "show";
  }

  public String getUsage() {
    return "[-n<diskno>]";
  }

  public String getHelpText() {
    return "Show a summary of all virtual disks, or details of one disk if -n is given";
  }
}
