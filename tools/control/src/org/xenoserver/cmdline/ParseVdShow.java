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
    String key = getStringParameter(args,'k',"");
    
    loadState();
    
    if ( key.equals("") ) {
      System.out.println("key        expiry                       name                 size");
      Iterator i = VirtualDiskManager.IT.getVirtualDisks();
      while ( i.hasNext() ) {
        VirtualDisk vd = (VirtualDisk) i.next();
        System.out.print( vd.getKey() + " " );
        if ( vd.getExpiry() != null ) {
          System.out.print( vd.getExpiry().toString() );
        } else {
          System.out.print( "                            " );
        }
        System.out.println( " " + Library.format(vd.getName(),16,true) + " "
                          + Library.formatSize(vd.getSize()*Settings.SECTOR_SIZE,8,false) );
      }
    } else {
      VirtualDisk vd = VirtualDiskManager.IT.getVirtualDisk(key);
      if ( vd == null ) {
        throw new CommandFailedException("There is no virtual disk " + key );
      }
        
      System.out.println("  name: " + vd.getName());
      System.out.println("   key: " + vd.getKey());
      System.out.println("  size: " + Library.formatSize(vd.getSize()*Settings.SECTOR_SIZE,8,true));
      if ( vd.getExpiry() != null ) {
        System.out.println("expiry: " + vd.getExpiry());
      }
      System.out.println();
 
      Iterator i = vd.extents();
      System.out.println("  disk       offset         size");
      while (i.hasNext()) {
        Extent e = (Extent) i.next();
        System.out.println( Library.format(e.getDisk(), 6, false) + " "
                          + Library.format(e.getOffset(), 12, false) + " "
                          + Library.format(e.getSize(), 12, false) );
      }
    }
  }

  public String getName() {
    return "show";
  }

  public String getUsage() {
    return "[-k<key>]";
  }

  public String getHelpText() {
    return "Show a summary of all virtual disks, or details of one disk if -k is given";
  }
}
