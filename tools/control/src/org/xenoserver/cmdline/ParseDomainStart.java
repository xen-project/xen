package org.xenoserver.cmdline;

import java.util.LinkedList;

import org.xenoserver.control.CommandDomainStart;
import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

public class ParseDomainStart extends CommandParser {
    public void parse(Defaults d, LinkedList args)
        throws ParseFailedException, CommandFailedException {
        int domain_id = getIntParameter(args, 'n', d.domainNumber);

        if (domain_id == 0) {
            throw new ParseFailedException("Expected -n<domain_id>");
        }

        String output = new CommandDomainStart(d, domain_id).execute();
        if (output != null)
            System.out.println(output);
    }

    public String getName() {
        return "start";
    }

    public String getUsage() {
        return "[-n<domain_id>]";
    }

    public String getHelpText() {
        return "Start the specified domain.";
    }
}
