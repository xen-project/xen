/*
 * VirtualDiskManager.java
 * 03.03.26 aho creation
 */

package uk.ac.cam.cl.xeno.vdmanager;

import java.util.Enumeration;
import java.util.Vector;
import java.util.Hashtable;
import java.util.Date;
import java.io.PrintWriter;

public class
VirtualDiskManager
{
  VirtualDisk free;
  Vector virtual_disks;
  Hashtable virtual_block_devices;
  Hashtable key_hash;

  VirtualDiskManager ()
  {
    free = new VirtualDisk("free");

    virtual_disks = new Vector(10,5);
    flush_virtual_block_devices();
    key_hash = new Hashtable(100);
  }

  public VirtualDisk
  get_virtual_disk_key (String key)
  {
    return ((VirtualDisk) key_hash.get(key));
  }

  public void
  add_xeno_partition (Partition partition, long size)
  {
    free.add_new_partition (partition, size);
    return;
  }

  /*
   * create a new virtual disk
   */

  public VirtualDisk
  create_virtual_disk(String name, long size, Date expiry)
  {
    VirtualDisk vd = new VirtualDisk (name, expiry);

    while (size > 0)
    {
      Extent e;

      e = free.remove_extent();
      if (e == null)
      {
	return null;
      }
      size -= e.size;
      vd.add_extent(e);
    }

    add_virtual_disk(vd);

    return vd;
  }

  /*
   * delete a new virtual disk.  extents go back into the free pool
   */

  public void
  delete_virtual_disk (String key)
  {
    VirtualDisk vd;

    vd = (VirtualDisk) key_hash.get(key);
    if (vd != null)
    {
      Extent e;

      key_hash.remove(key);
      virtual_disks.remove(vd);

      e = vd.remove_extent();
      while (e != null)
      {
	free.add_extent(e);
	e = vd.remove_extent();
      }
    }
    return;
  }

  /*
   * reset the expiry time for a virtual disk
   */

  public void
  refresh_virtual_disk (String key, Date expiry)
  {
    VirtualDisk vd = (VirtualDisk) key_hash.get(key);
    if (vd != null)
    {
      vd.set_expiry(expiry);
    }
  }

  /*
   * create a new virtual block device
   */
  public VirtualBlockDevice
  create_virtual_block_device (String key, int domain, int vbd_num, 
			       String mode)
  {
    VirtualBlockDevice vbd = new VirtualBlockDevice();
    VirtualDisk vd = get_virtual_disk_key(key);

    if (vd == null)
    {
      System.err.println("create virtual block device error: unknown key " +
			 "[" + key + "]");
      return null;
    }

    vbd.key = key;
    vbd.domain = domain;
    vbd.vbdnum = vbd_num;

    if (mode.equals(Mode.READ_ONLY.toString()) ||
	mode.equals("RO") ||
	mode.equals("ro"))
    {
      vbd.mode = Mode.READ_ONLY;
    }
    else if (mode.equals(Mode.READ_WRITE.toString()) ||
	     mode.equals("RW") ||
	     mode.equals("rw"))
    {
      vbd.mode = Mode.READ_WRITE;
    }
    else
    {
      System.err.println("create virtual block device error: unknown mode " +
			 "[" + mode + "]");
      return null;
    }

    add_virtual_block_device(vbd);

    return vbd;
  }

  /*
   * delete a virtual block device 
   */
  public void
  delete_virtual_block_device (int domain, int vbd_num)
  {
    Object hash = get_vbd_hash(domain, vbd_num);
    VirtualBlockDevice vbd = (VirtualBlockDevice)virtual_block_devices.remove(hash);
    return;
  }

  /*
   * flush all virtual block devices
   */
  public void
  flush_virtual_block_devices ()
  {
                            /* isn't automatic garbage collection wonderful? */
    virtual_block_devices = new Hashtable(100);
  }

  public void
  add_virtual_disk (VirtualDisk vd)
  {
    virtual_disks.add(vd);
    key_hash.put(vd.get_key(), vd);
  }

  public void
  add_virtual_block_device (VirtualBlockDevice vbd)
  {
    Object hash = get_vbd_hash(vbd.domain, vbd.vbdnum);
    virtual_block_devices.put(hash, vbd);
  }

  Object
  get_vbd_hash (int domain, int vbd_num)
  {
    return new Integer(domain * 16 + vbd_num);
  }

  public void
  add_free (VirtualDisk vd)
  {
    free = vd;
  }

  public String
  dump_virtualdisk (int segment)
  {
    if (segment < 0 || segment >= virtual_disks.size())
    {
      return null;
    }
    else
    {
      VirtualDisk vd = (VirtualDisk) virtual_disks.get(segment);
      return (vd.dump(true, true));
    }
  }

  public String
  dump_free()
  {
    return(free.dump(true, false));
  }

  public String
  dump_virtualdisks()
  {
    StringBuffer sb = new StringBuffer();

    for (int i = 0; i < virtual_disks.size(); i++)
    {
      VirtualDisk vd = (VirtualDisk) virtual_disks.get(i);
      if (i == 0)
      {
	sb.append(vd.dump(false, true));
      }
      sb.append(vd.dump(false, false));
    }

    return sb.toString();
  }

  public String
  dump_virtualblockdevices()
  {
    StringBuffer sb = new StringBuffer();
    boolean first = true;

    for (Enumeration enumeration = virtual_block_devices.elements() ; 
	 enumeration.hasMoreElements() ;) 
    {
      VirtualBlockDevice vbd = (VirtualBlockDevice) enumeration.nextElement();
      if (first)
      {
	sb.append(vbd.dump(true));
	first = false;
      }

      sb.append(vbd.dump(false));
    }

    return sb.toString();
  }

  public void
  dump_xml(PrintWriter out)
  {
    out.println("<free>");
    free.dump_xml(out);
    out.println("</free>");
    out.println("<virtual_disks>");
    for (int i = 0; i < virtual_disks.size(); i++)
    {
      VirtualDisk vd = (VirtualDisk) virtual_disks.get(i);
      vd.dump_xml(out);
    }
    out.println("</virtual_disks>");
    out.println("<virtual_block_devices>");
    for (Enumeration enumeration = virtual_block_devices.elements() ; 
	 enumeration.hasMoreElements() ;) 
    {
      VirtualBlockDevice vbd = (VirtualBlockDevice) enumeration.nextElement();
      vbd.dump_xml(out);
    }
 
    out.println("</virtual_block_devices>");

    return;
  }
}
