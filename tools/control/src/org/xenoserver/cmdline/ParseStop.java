package org.xenoserver.cmdline;

import org.xenoserver.control.Command;
import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandStop;
import org.xenoserver.control.Defaults;

public class ParseStop extends CommandParser {

  public void parse(Defaults d, String[] args) throws ParseFailedException, CommandFailedException {
    int domain_id = getIntParameter(args, 'n', 0);
    
    if (domain_id == 0) {
      throw new ParseFailedException("Expected -n<domain_id>");
    }

    String output = new CommandStop(d, domain_id).execute();
    if ( output != null )
      System.out.println( output );
  }

  public String getName()
  {
    return "stop";
  }

  public String getUsage()
  {
    return "[-n<domain_id>]";
  }

  public String getHelpText()
  {
    return
      "Stop the specified domain.";
  }
}
