package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandPartitionAdd;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Library;

public class ParsePartitionsAdd extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        boolean force = getFlagParameter(args, 'f');
        String partition_name = getStringParameter(args, 'p', "");
        String size = getStringParameter(args, 'c', "128M");

        if (partition_name.equals("")) {
            throw new ParseFailedException("Expected -p<partition_name>");
        }

        loadState();
        String output =
            new CommandPartitionAdd(partition_name, Library.parseSize(size),force)
                .execute();
        if (output != null) {
            System.out.println(output);
        }
        saveState();
    }

    public String getName() {
        return "add";
    }

    public String getUsage() {
        return "-p<partition_name> [-f] [-c<chunk_size>]";
    }

    public String getHelpText() {
        return "Add the specified partition to the virtual disk manager's free\n"
            + "space. -c changes the default chunk size. -f forces add.";
    }
}
