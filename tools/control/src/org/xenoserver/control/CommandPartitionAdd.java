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
    VirtualDiskManager.IT.addPartition(partition,chunksize);
    PartitionManager.IT.addXenoPartition(partition);
    return "Added partition " + partition.getName();
  }
}
