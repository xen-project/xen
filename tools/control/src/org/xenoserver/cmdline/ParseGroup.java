package org.xenoserver.cmdline;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

public class ParseGroup extends CommandParser {
  private final String name;
  private final CommandParser[] commands;
  
  /**
   * Constructor for ParseGroup.
   * @param name Name of this group of commands
   * @param commands Array of commands to include
   */
  public ParseGroup(String name, CommandParser[] commands) {
    this.name = name;
    this.commands = commands;
  }

  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    int i;
    String c = (String) args.removeFirst();
    for (i = 0; i < commands.length; i++) {
      if (commands[i].getName().equals(c)) {
        if (getFlagParameter(args, '?')) {
          commands[i].printHelpText(null);
        } else {
          commands[i].parse(d, args);
        }
        break;
      }
    }
    if (i == commands.length) {
      throw new ParseFailedException("Unknown command " + c);
    }
  }

  public String getName() {
    return name;
  }

  public String getUsage() {
    // TODO Auto-generated method stub
    return null;
  }

  public String getHelpText() {
    // TODO Auto-generated method stub
    return null;
  }

  public void printUsage(String prefix) {
    if ( prefix == null )
      prefix = name;
    else
      prefix += " " + name;
    for ( int i=0; i<commands.length; i++ )
      commands[i].printUsage(prefix);
  }

  public void printHelpText(LinkedList args) {
    if ( name != null )
      System.out.print( name + " " );
    int i;
    String c = (String) args.removeFirst();
    for (i = 0; i < commands.length; i++) {
      if (commands[i].getName().equals(c)) {
        commands[i].printHelpText(args);
        break;
      }
    }
  }
}
