package org.xenoserver.control;

import java.util.Date;

/**
 * Refresh the expiry time on a virtual disk.
 */
public class CommandVdRefresh extends Command {
    /** Key of disk to refresh */
    private String key;
    /** New expiry */
    private Date expiry;

    /**
     * Constructor for CommandVdRefresh.
     * @param key Key to refresh.
     * @param expiry New expiry (null for no expiry).
     */
    public CommandVdRefresh(String key, Date expiry) {
        this.key = key;
        this.expiry = expiry;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        VirtualDisk vd = VirtualDiskManager.IT.getVirtualDisk(key);
        if (vd == null) {
            throw new CommandFailedException("No such virtual disk " + key);
        }
        vd.refreshExpiry(expiry);
        return "Refreshed virtual disk " + key;
    }
}
