package org.xenoserver.control;

import java.util.Date;

public class CommandVdCreate extends Command {
  private String name;
  private long size;
  private Date expiry;

  /**
   * Constructor for CommandVdCreate.
   * @param name Name of new virtual disk.
   * @param size Size in sectors.
   * @param expiry Expiry time, or null for never.
   */
  public CommandVdCreate(String name, long size, Date expiry) {
    this.name = name;
    this.size = size;
    this.expiry = expiry;
  }

  public String execute() throws CommandFailedException {
    VirtualDisk vd = VirtualDiskManager.it.create_virtual_disk(name,size,expiry);
    if ( vd == null )
      throw new CommandFailedException( "Not enough free space to create disk" );
    return "Virtual Disk created with key: " + vd.getKey();
  }
}
