package org.xenoserver.control;

/**
 * Add a disk partition to the VirtualDiskManager as a XenoPartition.
 */
public class CommandPartitionAdd extends Command {
    /** True to force creation. */
    private boolean force;
    /** Partition to add as a XenoPartition. */
    private String partition_name;
    /** Chunk size to split partition into (in bytes). */
    private long chunksize;

    /**
     * Constructor for CommandPartitionAdd.
     * @param partition_name Partition to add.
     * @param chunksize Chunk size to split partition into (in bytes).
     * @param force True to force creation.
     */
    public CommandPartitionAdd(String partition_name, long chunksize, boolean force) {
        this.partition_name = partition_name;
        this.chunksize = chunksize;
        this.force = force;
    }

    /**
     * @see org.xenoserver.control.Command#execute()
     */
    public String execute() throws CommandFailedException {
        Partition p = PartitionManager.IT.getPartition(partition_name);
        if (p == null) {
            throw new CommandFailedException(
                "Partition " + partition_name + " does not exist.");
        }
        // Check if this partition belongs to the VDM
        if (p.isXeno() && !force) {
          throw new CommandFailedException("Refusing to add partition as it is already allocated to the virtual disk manager. Use -f if you are sure.");
        }
        
        long size = chunksize / Settings.SECTOR_SIZE;
        if ( chunksize <= 0 ) {
          throw new CommandFailedException("Chunk size is smaller than sector size.");
        }
    
        VirtualDiskManager.IT.addPartition(p, size);
        PartitionManager.IT.addXenoPartition(p);
        return "Added partition " + p.getName();
    }
}
