package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.Defaults;

public class ParseHelp extends CommandParser {

  public void parse(Defaults d, LinkedList args) {
    if (args.size() == 0) {
      System.out.println("Usage:");
      Main.parser.printUsage(null);
    } else {
      System.out.print("xenctl ");
      Main.parser.printHelpText(args);
    }

    System.out.println("");
  }
  
  public String getName()
  {
    return "help";
  }

  public String getUsage()
  {
    return "";
  }

  public String getHelpText()
  {
    return "This message";
  }  
}
