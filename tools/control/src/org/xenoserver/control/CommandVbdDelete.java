package org.xenoserver.control;

/**
 * Delete a virtual block device. Note that this does not update anything inside
 * Xen, and therefore should only be done if you are certain that the domain has
 * either not been started, or has been destroyed, or you are sure it will not
 * try to access the VBD again. Since the mapping is not removed in Xen, any
 * subsequent changes to the underlying virtual disk will affect the domain,
 * probably adversely.
 */
public class CommandVbdDelete extends Command {
    /** Domain id to delete from */
    private int domain_id;
    /** VBD number to delete */
    private int vbd_num;

    /**
     * Constructor for CommandVbdDelete.
     * @param domain_id Domain ID to delete from
     * @param vbd_num VBD number to delete
     */
    public CommandVbdDelete(int domain_id, int vbd_num) {
        this.domain_id = domain_id;
        this.vbd_num = vbd_num;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        if (VirtualDiskManager
            .IT
            .deleteVirtualBlockDevice(domain_id, vbd_num)) {
            return "Deleted VBD " + vbd_num + " from domain " + domain_id;
        } else {
            throw new CommandFailedException(
                "No such virtual block device "
                    + vbd_num
                    + " in domain "
                    + domain_id);
        }
    }
}
