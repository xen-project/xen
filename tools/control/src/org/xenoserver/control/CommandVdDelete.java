package org.xenoserver.control;

/**
 * Delete virtual disk.
 */
public class CommandVdDelete extends Command {
    /** Key of disk to delete. */
    private String key;

    /**
     * Constructor for CommandVdDelete.
     * @param key The key of the disk to delete.
     */
    public CommandVdDelete(String key) {
        this.key = key;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        VirtualDiskManager.IT.deleteVirtualDisk(key);
        return "Deleted virtual disk " + key;
    }
}
