package org.xenoserver.control;

import java.util.Date;

/**
 * Create a virtual disk.
 */
public class CommandVdCreate extends Command {
    /** Name of new disk. */
    private String name;
    /** Size of new disk in bytes. */
    private long size;
    /** Expiry date of new disk. */
    private Date expiry;

    /**
     * Constructor for CommandVdCreate.
     * @param name Name of new virtual disk.
     * @param size Size in bytes.
     * @param expiry Expiry time, or null for never.
     */
    public CommandVdCreate(String name, long size, Date expiry) {
        this.name = name;
        this.size = size;
        this.expiry = expiry;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        VirtualDisk vd =
            VirtualDiskManager.IT.createVirtualDisk(
                name,
                size / Settings.SECTOR_SIZE,
                expiry);
        if (vd == null) {
            throw new CommandFailedException("Not enough free space to create disk");
        }
        return "Virtual Disk created with key: " + vd.getKey();
    }
}
