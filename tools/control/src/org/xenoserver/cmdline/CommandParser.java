package org.xenoserver.cmdline;

import org.xenoserver.control.Command;
import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

/**
 * Subclasses of Parser know how to parse arguments for a given command
 * and execute it, displaying any output.
 */
public abstract class CommandParser {
  /**
   * Subclasses should implement this method such that it outputs any successful
   * output to the screen, or throws an exception if required arguments
   * are missing or malformed. It also may propagate exceptions from the
   * command execution.
   * 
   * @param d The defaults object to use.
   * @param args The arguments to parse.
   * @throws ParseFailedException if the arguments are not suitable.
   * @throws CommandFailedException if the command did not execute successfully.
   */
  public abstract void parse(Defaults d, String args[]) throws ParseFailedException, CommandFailedException;

  /** Return the command name which will be matched on the command line. */  
  public abstract String getName();     
  /** Return a usage string for this command. */
  public abstract String getUsage();
  /** Return the help text for this command. */
  public abstract String getHelpText();

  public String getStringParameter(String args[], char key, String def)
  {
    String r = getParameter (args, key);
    return (r == null) ? def : r;
  }

  public int getIntParameter(String args[], char key, int def)
  {
    String r = getParameter (args, key);
    return (r == null) ? def : (Integer.parseInt (r));
  }

  public boolean getFlagParameter(String args[], char key)
  {
    String r = getParameter (args, key);
    return (r == null) ? false : true;
  }

  protected String getParameter (String args[], char key)
  {
    int i;
    String result = null;
    for (i = 0; i < args.length; i ++)
      {
  if (args[i].startsWith("-" + key)) 
    {
      if (args[i].length() > 2)
        {
    result = args[i].substring(2, args[i].length());
        }
      else
        {
    result = "";
        }
    }
      }
    return result;
  }
}
