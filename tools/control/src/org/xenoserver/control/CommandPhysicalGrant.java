package org.xenoserver.control;

/**
 * Grant physical access to a partition for a given domain.
 */
public class CommandPhysicalGrant extends Command {
    /** Defaults instance to use */
    private Defaults d;
    /** Domain ID to grant access for */ 
    private int domain_id;
    /** Partition to grant access to */
    private Partition partition;
    /** Access mode to grant */
    private Mode mode;

    /**
     * Constructor for CommandPhysicalGrant.
     * @param d Defaults object to use.
     * @param domain_id Domain to grant access for.
     * @param partition Partition to grant access to.
     * @param mode Access mode to grant.
     */
    public CommandPhysicalGrant(
        Defaults d,
        int domain_id,
        Partition partition,
        Mode mode) {
        this.d = d;
        this.domain_id = domain_id;
        this.partition = partition;
        this.mode = mode;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        Runtime r = Runtime.getRuntime();
        String output = null;

        try {
            Process start_p;
            String start_cmdarray[] = new String[7];
            int start_rc;
            start_cmdarray[0] = d.xiToolsDir + "xi_phys_grant";
            if (mode == Mode.READ_WRITE) {
                start_cmdarray[1] = "rw";
            } else if (mode == Mode.READ_ONLY) {
                start_cmdarray[1] = "ro";
            } else {
                throw new CommandFailedException(
                    "Unknown access mode '" + mode + "'");
            }
            start_cmdarray[2] = Integer.toString(domain_id);
            Extent e = partition.toExtent();
            start_cmdarray[3] = Integer.toString(e.getDisk());
            start_cmdarray[4] = Long.toString(e.getOffset());
            start_cmdarray[5] = Long.toString(e.getSize());
            start_cmdarray[6] = Integer.toString(partition.getPartitionIndex());

            if (Settings.TEST) {
                output = reportCommand(start_cmdarray);
            } else {
                start_p = r.exec(start_cmdarray);
                start_rc = start_p.waitFor();
                if (start_rc != 0) {
                    throw CommandFailedException.xiCommandFailed(
                        "Could not grant physical access",
                        start_cmdarray);
                }
                output = "Granted physical access to domain " + domain_id;
            }
        } catch (CommandFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailedException(
                "Could not grant physical access (" + e + ")",
                e);
        }

        return output;
    }

}
