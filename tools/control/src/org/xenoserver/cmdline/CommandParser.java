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

    /** @return The command name which will be matched on the command line. */
    public abstract String getName();
    /** @return A usage string for this command. */
    public abstract String getUsage();
    /** @return The help text for this command. */
    public abstract String getHelpText();

    /**
     * Print a usage string for this command.
     * @param prefix The command prefix for this command
     */
    public void printUsage(String prefix) {
        String name = getName();
        if (prefix != null) {
            name = prefix + " " + name;
        }
        String usage = getUsage();
        while (name.length() < 16) {
            name = name + " ";
        }
        System.out.println("   " + name + usage);
    }

    /**
     * Prints the help text for this command.
     * @param args Command arguments, ignored for normal commands.
     */
    public void printHelpText(LinkedList args) {
        System.out.println(getName() + " " + getUsage());
        System.out.println();
        System.out.println(getHelpText());
    }

    /**
     * Get a string parameter
     * @param args Argument list to search
     * @param key Argument key
     * @param def Default value
     * @return parameter, or default if none found
     */
    public String getStringParameter(List args, char key, String def) {
        String r = getParameter(args, key);
        return (r == null) ? def : r;
    }

    /**
     * Get an int parameter
     * @param args Argument list to search
     * @param key Argument key
     * @param def Default value
     * @return parameter, or default if none found
     */
    public int getIntParameter(List args, char key, int def) {
        String r = getParameter(args, key);
        return (r == null) ? def : (Integer.parseInt(r));
    }

    /**
     * Get a boolean parameter
     * @param args Argument list to search
     * @param key Argument key
     * @return parameter, or false if none found
     */
    public boolean getFlagParameter(List args, char key) {
        String r = getParameter(args, key);
        return (r == null) ? false : true;
    }

    /**
     * Get a parameter
     * @param args Argument list to search
     * @param key Key to look for
     * @return Value, or "" if no value, or null if no such argument
     */
    protected String getParameter(List args, char key) {
        String result = null;
        Iterator i = args.iterator();
        while (i.hasNext()) {
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

    /**
     * Load the partition and disk manager state
     */
    protected void loadState() {
        XML.loadState(
            PartitionManager.IT,
            VirtualDiskManager.IT,
            Settings.STATE_INPUT_FILE);
    }

    /**
     * Save the partition and disk manager state
     */
    protected void saveState() {
        XML.saveState(
            PartitionManager.IT,
            VirtualDiskManager.IT,
            Settings.STATE_OUTPUT_FILE);
    }
}
