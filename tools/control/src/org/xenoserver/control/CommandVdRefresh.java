package org.xenoserver.control;

import java.util.Date;

public class CommandVdRefresh extends Command {
  private String key;
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

  public String execute() throws CommandFailedException {
    VirtualDisk vd = VirtualDiskManager.IT.getVirtualDisk(key);
    if ( vd == null )
      throw new CommandFailedException( "No such virtual disk " + key );
    vd.refreshExpiry(expiry);
    return "Refreshed virtual disk " + key;
  }
}
