package org.xenoserver.control;

/**
 * Add a disk partition to the VirtualDiskManager as a XenoPartition.
 */
public class CommandPartitionAdd extends Command {
    /** Partition to add as a XenoPartition. */
    private Partition partition;
    /** Chunk size to split partition into (in sectors). */
    private long chunksize;

    /**
     * Constructor for CommandPartitionAdd.
     * @param partition Partition to add.
     * @param chunksize Chunk size to split partition into (in sectors).
     */
    public CommandPartitionAdd(Partition partition, long chunksize) {
        this.partition = partition;
        this.chunksize = chunksize;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        VirtualDiskManager.IT.addPartition(partition, chunksize);
        PartitionManager.IT.addXenoPartition(partition);
        return "Added partition " + partition.getName();
    }
}
