package org.xenoserver.control;

/**
 * Stops a domain.
 */
public class CommandDomainStop extends Command {
    /** Defaults instance in use */
    private Defaults d;
    /** Domain ID to stop */
    private int domain_id;

    /**
     * Constructor for CommandDomainStop.
     * @param d The defaults object to use.
     * @param domain_id The domain to stop.
     */
    public CommandDomainStop(Defaults d, int domain_id) {
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
            Process stop_p;
            String stop_cmdarray[] = new String[2];
            int stop_rc;
            stop_cmdarray[0] = d.xiToolsDir + "xi_stop";
            stop_cmdarray[1] = "" + domain_id;

            if (Settings.TEST) {
                output = reportCommand(stop_cmdarray);
            } else {
                stop_p = r.exec(stop_cmdarray);
                stop_rc = stop_p.waitFor();

                if (stop_rc != 0) {
                    throw CommandFailedException.xiCommandFailed(
                        "Could not stop domain",
                        stop_cmdarray);
                }
                output = "Stopped domain " + domain_id;
            }
        } catch (CommandFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailedException(
                "Could not stop new domain (" + e + ")",
                e);
        }

        return output;
    }
}
