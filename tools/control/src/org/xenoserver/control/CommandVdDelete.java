package org.xenoserver.control;

public class CommandVdDelete extends Command {
  private String key;
  
  /**
   * Constructor for CommandVdDelete.
   * @param key The key of the disk to delete.
   */
  public CommandVdDelete(String key) {
    this.key = key;
  }

  public String execute() throws CommandFailedException {
    VirtualDiskManager.IT.deleteVirtualDisk(key);
    return "Deleted virtual disk " + key;
  }
}
