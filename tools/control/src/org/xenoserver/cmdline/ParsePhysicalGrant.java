package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.CommandPhysicalGrant;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Mode;

public class ParsePhysicalGrant extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        int domain_id = getIntParameter(args, 'n', d.domainNumber);
        boolean force = getFlagParameter(args, 'f');
        String partition_name = getStringParameter(args, 'p', "");
        boolean write = getFlagParameter(args, 'w');
	int subst = getIntParameter(args, 'x', -1);

        if (domain_id == 0) {
            throw new ParseFailedException("Expected -n<domain_id>");
        }
        if (partition_name.equals("")) {
            throw new ParseFailedException("Expected -p<partition_name>");
        }

        Mode mode;
        if (write) {
            mode = Mode.READ_WRITE;
        } else {
            mode = Mode.READ_ONLY;
        }

        // Initialise the partition manager and look up the partition
        loadState();
        String output =
            new CommandPhysicalGrant(d, domain_id, partition_name, mode, force,subst)
                .execute();
        if (output != null) {
            System.out.println(output);
        }
    }

    public String getName() {
        return "grant";
    }

    public String getUsage() {
        return "-p<partition_name> [-n<domain_id>] [-f] [-w] [-x<subst>]";
    }

    public String getHelpText() {
        return "Grant the specified domain access to the given partition.  -w grants"
            + " read-write instead of read-only.  -f forcibly grants access.";
    }

}
