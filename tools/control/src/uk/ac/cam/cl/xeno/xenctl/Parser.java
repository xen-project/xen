/*
 * Parser.java
 * 03.03.27 aho creation
 */

package uk.ac.cam.cl.xeno.xenctl;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.Date;

public class
Parser
{
  static String prompt = "vdmanager> ";
  static String default_addpartition_chunksize = "104857600";        /* 100M */
  static int    default_sector_size = 512;

  PartitionManager pm;
  VirtualDiskManager vdm;

  Parser (PartitionManager pm, VirtualDiskManager vdm)
  {
    this.pm = pm;
    this.vdm = vdm;
  }

  void
  parse_main (String[] argv)
  {
    if (argv.length == 0)
    {
      parse_input(null);
    }
    else
    {
      parse_commandline(argv);
    }
  }

  void
  parse_input (String filename)
  {
    String line;
    BufferedReader in;

    if (filename != null)
    {
      try
      {
	in = new BufferedReader(new FileReader(filename));
      }
      catch (FileNotFoundException fnfe)
      {
	System.err.println (fnfe);
	return;
      }
    }
    else
    {
      in = new BufferedReader(new InputStreamReader(System.in));
    }

    try
    {
      if (filename == null)
      {
	System.out.print (prompt);
      }
      line = in.readLine();
      while (line != null)
      {
	StringTokenizer st = new StringTokenizer(line);
	Vector v = new Vector();

	while (st.hasMoreTokens()) 
	{
	  v.add(st.nextToken());
	}

	if (parse_commandline((String[]) v.toArray(new String[v.size()])))
	{
	  return;
	}
	
	if (filename == null)
	{
	  System.out.print (prompt);
	}
	line = in.readLine();
      }
    }
    catch (IOException ioe)
    {
      System.err.println(ioe);
    }

    if (filename == null)
    {
      System.out.println ("");
    }
    return;
  }

  boolean
  parse_commandline (String[] commands)
  {
    if (commands.length == 0)
    {
      return false;
    }

    String keyword = commands[0].toLowerCase();
    if (keyword.equals("file"))
    {
      if (commands.length < 2)
      {
	System.out.println ("file [filename]");
	return false;
      }
      for (int i = 1; i < commands.length; i++)
      {
	System.out.println ("file " + commands[i]);
	parse_input(commands[i]);
      }
    }
    else if (keyword.equals("show"))
    {
      parse_show(commands);
    }
    else if (keyword.equals("addpartition"))
    {
      parse_addpartition(commands);
    }
    else if (keyword.equals("vdcreate"))
    {
      parse_vdcreate(commands);
    }
    else if (keyword.equals("vddelete"))
    {
      parse_vddelete(commands);
    }
    else if (keyword.equals("vdrefresh"))
    {
      parse_vdrefresh(commands);
    }
    else if (keyword.equals("vbdcreate"))
    {
      parse_vbdcreate(commands);
    }
    else if (keyword.equals("vbddelete"))
    {
      parse_vbddelete(commands);
    }
    else if (keyword.equals("vbdflush"))
    {
      vdm.flush_virtual_block_devices();
    }
    else if (keyword.equals("load"))
    {
      if (commands.length < 2)
      {
	System.out.println ("load <filename>");
	return false;
      }
      XML.load_state (pm, vdm, commands[1]);
    }
    else if (keyword.equals("save"))
    {
      if (commands.length < 2)
      {
	System.out.println ("save <filename>");
	return false;
      }
      XML.dump_state (pm, vdm, commands[1]);
    }
    else if (keyword.equals("help") ||
	     keyword.equals("?"))
    {
      parse_help();
    }
    else if (keyword.equals("exit") ||
	     keyword.equals("quit"))
    {
      return true;
    }
    else
    {
      System.out.println ("unknown command [" + commands[0] + "]. " +
			  "try \"help\"");
    }
    return false;
  }

  void
  parse_vdcreate (String[] commands)
  {
    VirtualDisk vd;

    if (commands.length < 4)
    {
      System.out.println ("vdcreate name size expiry");
      return;
    }

    vd = vdm.create_virtual_disk(commands[1],
		     Library.parse_size(commands[2]) / default_sector_size,
				 new Date());

    System.out.println ("Virtual Disk created with key: " + vd.get_key());
  }

  void
  parse_vddelete (String[] commands)
  {
    if (commands.length < 2)
    {
      System.out.println ("vddelete key");
      return;
    }

    vdm.delete_virtual_disk(commands[1]);
  }

  void
  parse_vdrefresh (String[] commands)
  {
    if (commands.length < 3)
    {
      System.out.println ("vdrefresh key expiry");
      return;
    }

    vdm.refresh_virtual_disk(commands[1],
			     new Date());
  }

  void
  parse_vbdcreate (String[] commands)
  {
    VirtualDisk vd;
    VirtualBlockDevice vbd;

    if (commands.length < 4)
    {
      System.out.println ("vbdcreate <key> <domain number> <vbd number>");
      return;
    }

    if (commands[1].startsWith("sd") ||
	commands[1].startsWith("hd"))
    {
      /*
       * this is a gross hack to allow you to create a virtual block
       * device that maps directly to a physical partition
       */

      /* find the appropriate partition */
      Partition partition = pm.get_partition(commands[1]);
      if (partition == null)
      {
	System.out.println ("vbdcreate error: couldn't find partition \"" +
			    commands[1] + "\"");
	return;
      }

      /* create a virtual disk */
      vd = new VirtualDisk("vbd:" + commands[1]);
      vd.add_new_partition(partition, partition.nr_sects);


      /* display result */
      System.out.print("domain:" + commands[2] + " ");
      if (commands.length == 4)
      {
	System.out.print ("rw ");
      }
      else
      {
	System.out.print(commands[4] + " ");
      }
      System.out.print("segment:" + commands[3] + " ");
      System.out.print(vd.dump_xen());
      System.out.println("");

      return;
    } 

    if (commands.length == 4)
    {
      vbd =
      vdm.create_virtual_block_device(commands[1],
				      Integer.decode(commands[2]).intValue(),
				      Integer.decode(commands[3]).intValue(),
				      "rw");
    }
    else
    {
      vbd =
      vdm.create_virtual_block_device(commands[1],
				      Integer.decode(commands[2]).intValue(),
				      Integer.decode(commands[3]).intValue(),
				      commands[4]);
    }

    /* display commandline to user */
    {
      vd = vdm.get_virtual_disk_key(commands[1]);
      System.out.println ("\n" + vd.dump_xen(vbd) + "\n");
    }
  }

  void
  parse_vbddelete (String[] commands)
  {
    if (commands.length < 3)
    {
      System.out.println ("vbddelete <domain number> <vbd number>");
      return;
    }

    vdm.delete_virtual_block_device(Integer.decode(commands[1]).intValue(),
				    Integer.decode(commands[2]).intValue());
  }

  static String show_helptxt = "show <partitions | free | vd [vd number] | vbd>";
  void
  parse_show (String[] commands)
  {
    String subword;
      
    if (commands.length < 2)
    {
      System.out.println (show_helptxt);
      return;
    }

    subword = commands[1].toLowerCase();
    if (subword.equals("partition") ||
	subword.equals("partitions"))
    {
      System.out.println(pm.dump(true));
    }
    else if (subword.equals("vd"))
    {
      String text;

      if (commands.length < 3)
      {
	System.out.println(vdm.dump_virtualdisks());
	return;
      }
      text = vdm.dump_virtualdisk(Integer.decode(commands[2]).intValue());
      if (text == null)
      {
	System.out.println("show vd error: invalid virtual disk number");
      }
      else
      {
	System.out.println(text);
      }
    }
    else if (subword.equals("vbd"))
    {
      System.out.println(vdm.dump_virtualblockdevices());
    }
    else if (subword.equals("free"))
    {
      System.out.println(vdm.dump_free());
    }
    else
    {
      System.out.println (show_helptxt);
      return;
    }
  }

  void
  parse_addpartition(String[] commands)
  {
    String chunksize = default_addpartition_chunksize;

    if (commands.length > 3 || commands.length < 2)
    {
      System.out.println ("addpartition <partition number> [chunksize]");
      return;
    }
    if (commands.length == 3)
    {
      chunksize = commands[2];
    }

    System.out.println ("add partition " + commands[1] + " " + chunksize);

    vdm.add_xeno_partition(pm.get_partition(Integer.parseInt(commands[1])), 
			   Library.parse_size(chunksize)/default_sector_size);
    pm.add_xeno_partition(pm.get_partition(Integer.parseInt(commands[1])));
  }

  void
  parse_help()
  {
    System.out.println ("file <filename>     " +
			"read the contents of a file as input to vdmanager");
    System.out.println ("addpartition <partition number> [chunksize]");
    System.out.println ("                    " +
			"add a partition as a xeno partition");
    System.out.println ("vdcreate <name> <size> <expiry>");
    System.out.println ("                    " +
			"create a new virtual disk");
    System.out.println ("vddelete <key>      " +
			"delete a virtual disk");
    System.out.println ("vdrefresh <key> <expiry>");
    System.out.println ("                    " +
			"reset virtual disk expiry");
    System.out.println ("vbdcreate <key> <domain number> <vbd number> [rw|ro]");
    System.out.println ("                    " +
			"create a new virtual block device");
    System.out.println ("vbddelete <domain number> <vbd number>");
    System.out.println ("                    " +
			"delete a new virtual block device");
    System.out.println ("vbdflush            " +
			"remove all virtual block devices");
    System.out.println ("show partitions     " +
			"display a complete list of disk partitions");
    System.out.println ("show vd <vd number> " +
			"display virtual disk information");
    System.out.println ("show vbd            " +
			"display virtual virtual block device list");
    System.out.println ("show free           " +
			"display details about unallocated space");
    System.out.println ("load <filename>     " +
			"load new state from file");
    System.out.println ("save <filename>     " +
			"save state to file");
    System.out.println ("help                " +
			"display this help message");
    System.out.println ("quit                " +
			"exit");
  }
}
