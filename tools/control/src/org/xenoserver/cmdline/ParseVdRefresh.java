package org.xenoserver.cmdline;

import java.util.Date;
import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandVdRefresh;
import org.xenoserver.control.Defaults;

public class ParseVdRefresh extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    String vd_key = getStringParameter(args,'k',"");
    String expiry_s = getStringParameter(args,'e',"");
    Date expiry;
    
    if ( vd_key.equals("") )
      throw new ParseFailedException("Expected -k<key>");
    if ( expiry_s.equals("") )
      expiry = null;
    else
      expiry = new Date(Date.parse(expiry_s));
      
    loadState();
    String output = new CommandVdRefresh(vd_key,expiry).execute();
    if ( output != null )
      System.out.println(output);
    saveState();
  }

  public String getName() {
    return "refresh";
  }

  public String getUsage() {
    return "-k<key> [-e<expiry>]";
  }

  public String getHelpText() {
    return "Refresh the expiry for the specified virtual disk. Omitting -e will cause the disk to never expire.";
  }

}
