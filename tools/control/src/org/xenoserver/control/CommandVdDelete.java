package org.xenoserver.control;

/**
 * Delete virtual disk.
 */
public class CommandVdDelete extends Command {
    /** Key of disk to delete. */
    private String key;
    /** Force deletion? */
    private boolean force;

    /**
     * Constructor for CommandVdDelete.
     * @param key The key of the disk to delete.
     */
    public CommandVdDelete(String key,boolean force) {
        this.key = key;
        this.force = force;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        if (VirtualDiskManager.IT.getVirtualDisk(key) == null) {
            throw new CommandFailedException(
                "Virtual disk " + key + " does not exist");
        }
        if ( !force ) {
            CommandVbdList list = new CommandVbdList();
            list.execute();
            VirtualBlockDevice[] vbds = list.vbds();
            for (int i=0;i<vbds.length;i++) {
                if (vbds[i].getVirtualDisk().getKey().equals(key)) {
                    throw new CommandFailedException("Virtual disk " + key + " is in use.");
                }
            }
        }

        VirtualDiskManager.IT.deleteVirtualDisk(key);
        return "Deleted virtual disk " + key;
    }
}
