package org.xenoserver.cmdline;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.PartitionManager;
import org.xenoserver.control.Settings;
import org.xenoserver.control.VirtualDiskManager;
import org.xenoserver.control.XML;

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
  public abstract void parse(Defaults d, LinkedList args)
    throws ParseFailedException, CommandFailedException;

  /** Return the command name which will be matched on the command line. */
  public abstract String getName();
  /** Return a usage string for this command. */
  public abstract String getUsage();
  /** Return the help text for this command. */
  public abstract String getHelpText();
  
  /** Print a usage string for this command. */
  public void printUsage(String prefix)
  {
    String name = getName();
    if ( prefix != null )
      name = prefix + " " + name;
    String usage = getUsage();
    while (name.length() < 16)
      name = name + " ";
    System.out.println("   " + name + usage);
  }
  
  /** Prints the help text for this command. */
  public void printHelpText(LinkedList args)
  {
    System.out.println(getName() + " " + getUsage());
    System.out.println();
    System.out.println(getHelpText());
  }

  public String getStringParameter(List args, char key, String def) {
    String r = getParameter(args, key);
    return (r == null) ? def : r;
  }

  public int getIntParameter(List args, char key, int def) {
    String r = getParameter(args, key);
    return (r == null) ? def : (Integer.parseInt(r));
  }

  public boolean getFlagParameter(List args, char key) {
    String r = getParameter(args, key);
    return (r == null) ? false : true;
  }

  protected String getParameter(List args, char key) {
    String result = null;
    Iterator i = args.iterator();
    while ( i.hasNext() ) {
      String arg = (String) i.next();
      if (arg.startsWith("-" + key)) {
        if (arg.length() > 2) {
          result = arg.substring(2);
        } else {
          result = "";
        }
      }
    }
    return result;
  }

  protected void loadState() {
    XML.loadState( PartitionManager.IT, VirtualDiskManager.IT, Settings.STATE_INPUT_FILE );
  }
  
  protected void saveState() {
    XML.saveState( PartitionManager.IT, VirtualDiskManager.IT, Settings.STATE_OUTPUT_FILE );
  }
}
