package org.xenoserver.control;

import java.util.Date;

public class CommandVdRefresh extends Command {
  private String key;
  private Date expiry;
  
  /**
   * Constructor for CommandVdRefresh.
   * @param key Key to refresh.
   * @param expiry New expiry.
   */
  public CommandVdRefresh(String key, Date expiry) {
    this.key = key;
    this.expiry = expiry;
  }

  public String execute() throws CommandFailedException {
    VirtualDiskManager.it.refresh_virtual_disk(key,expiry);
    return "Refreshed virtual disk " + key;
  }
}
