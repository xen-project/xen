package org.xenoserver.control;

/**
 * Flush (delete) all virtual block devices.
 */
public class CommandVbdFlush extends Command {
    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        VirtualDiskManager.IT.flushVirtualBlockDevices();
        return "Flushed virtual block devices";
    }
}
