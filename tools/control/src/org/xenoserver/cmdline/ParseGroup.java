package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

/**
 * Parses a group of commands; taking the first argument, it searches its
 * array of commands until it finds a match, and then, removing the matched
 * argument from the command line, invokes it. This allows hierarchical
 * parsing.
 */
public class ParseGroup extends CommandParser {
    /** Name of this group, i.e. the prefix to the command line */
    private final String name;
    /** The commands this group will attempt to match its arguments against. */
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

    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        if (args.isEmpty()) {
            Main.help.parse(null,null);
            return;
        }
        
        int i;
        String c = (String) args.removeFirst();
        for (i = 0; i < commands.length; i++) {
            if (commands[i].getName().equals(c)) {
                if (!args.isEmpty() && args.getFirst().equals("-?")) {
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
        return null;
    }

    public String getHelpText() {
        return null;
    }

    public void printUsage(String prefix) {
        if (prefix == null) {
            prefix = name;
        } else {
            prefix += " " + name;
        }
        for (int i = 0; i < commands.length; i++) {
            commands[i].printUsage(prefix);
        }
    }

    public void printHelpText(LinkedList args) {
        if (args == null) {
            Main.help.parse(null,null);
            return;            
        }
        if (name != null) {
            System.out.print(name + " ");
        }
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
