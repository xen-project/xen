package org.xenoserver.cmdline;

import org.xenoserver.control.Command;
import org.xenoserver.control.Defaults;

public class ParseHelp extends CommandParser {

  public void parse(Defaults d, String[] args) {
    if (args.length <= 1) {
      System.out.println("Usage:");
      for (int i = 0; i < Main.commands.length; i++) {
        String name = Main.commands[i].getName();
        String usage = Main.commands[i].getUsage();
        while (name.length() < 12)
          name = name + " ";
        System.out.println("   " + name + usage);
      }
    } else {
      for (int i = 0; i < Main.commands.length; i++) {
        String name = Main.commands[i].getName();
        String usage = Main.commands[i].getUsage();
        if (name.equals(args[1])) {
          doHelpFor(Main.commands[i]);
          break;
        }
      }
    }

    System.out.println("");
  }
  
  public void doHelpFor(CommandParser c)
  {
    System.out.println ("xenctl " + c.getName() + " " + c.getUsage());
    System.out.println ();
    System.out.println (c.getHelpText ());
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
