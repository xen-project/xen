package org.xenoserver.control;

public class CommandPartitionAdd extends Command {
  private Partition partition;
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

  public String execute() throws CommandFailedException {
    VirtualDiskManager.it.add_xeno_partition(partition,chunksize);
    PartitionManager.it.add_xeno_partition(partition);
    return "Added partition " + partition.getName();
  }
}
