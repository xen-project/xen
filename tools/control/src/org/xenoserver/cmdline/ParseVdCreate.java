package org.xenoserver.cmdline;

import java.util.Date;
import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandVdCreate;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Library;
import org.xenoserver.control.Settings;

public class ParseVdCreate extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    String name = getStringParameter(args,'n',"");
    String size_s = getStringParameter(args,'s',"");
    String expiry_s = getStringParameter(args,'e',"");
    Date expiry;
    
    if ( name.equals("") )
      throw new ParseFailedException("Expected -n<name>");
    if ( size_s.equals("") )
      throw new ParseFailedException("Expected -s<size>");
    if ( expiry_s.equals("") )
      expiry = null;
    else
      expiry = new Date(Date.parse(expiry_s));
      
    long size = Library.parse_size(size_s);
    
    loadState();
    String output = new CommandVdCreate(name,size/Settings.SECTOR_SIZE,expiry).execute();
    if ( output != null )
      System.out.println( output );
    saveState();
  }

  public String getName() {
    return "create";
  }

  public String getUsage() {
    return "[-n<name>] [-s<size>] [-e<expiry>]";
  }

  public String getHelpText() {
    return "Create a new virtual disk with the specified parameters";
  }

}
