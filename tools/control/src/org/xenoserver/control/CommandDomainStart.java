package org.xenoserver.control;

/**
 * Starts a domain.
 */
public class CommandDomainStart extends Command {
    /** Defaults instance in use. */
    private Defaults d;
    /** Domain ID to start */
    private int domain_id;
    
    /**
    * Constructor for CommandDomainStart.
    * @param d Defaults object to use.
    * @param domain_id Domain to start.
    */
    public CommandDomainStart(Defaults d, int domain_id) {
        this.d = d;
        this.domain_id = domain_id;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        Runtime r = Runtime.getRuntime();
        String output = null;

        try {
            Process start_p;
            String start_cmdarray[] = new String[2];
            int start_rc;
            start_cmdarray[0] = d.xiToolsDir + "xi_start";
            start_cmdarray[1] = "" + domain_id;

            if (Settings.TEST) {
                output = reportCommand(start_cmdarray);
            } else {
                start_p = r.exec(start_cmdarray);
                start_rc = start_p.waitFor();
                if (start_rc != 0) {
                    throw CommandFailedException.xiCommandFailed(
                        "Could not start domain",
                        start_cmdarray);
                }
                output = "Started domain " + domain_id;
            }
        } catch (CommandFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailedException(
                "Could not start new domain (" + e + ")",
                e);
        }

        return output;
    }
}
