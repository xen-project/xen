package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandVdDelete;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.VirtualDiskManager;

public class ParseVdDelete extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    String vd_key = getStringParameter(args,'k',"");
    
    if ( vd_key.equals("") )
      throw new ParseFailedException("Expected -k<key>");
    
    loadState();
    if ( VirtualDiskManager.it.get_virtual_disk_key(vd_key) == null )
      throw new CommandFailedException("Virtual disk " + vd_key + " does not exist");
      
    String output = new CommandVdDelete(vd_key).execute();
    if ( output != null )
      System.out.println( output );
      
    saveState();
  }

  public String getName() {
    return "delete";
  }

  public String getUsage() {
    return "[-k<key>]";
  }

  public String getHelpText() {
    return "Deletes the virtual disk with the specified key.";
  }

}
