/*
 * XMLHelper.java
 * 03.03.27 aho creation
 */

package uk.ac.cam.cl.xeno.xenctl;

import java.util.Date;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class
XMLHelper
{
  static void
  dump_document (Document document)
  {
    dump_element(document.getDocumentElement(), 0);
  }

  static void
  dump_element (Element element, int indent)
  {
    NodeList nl = element.getChildNodes();

    System.out.println ("<" + element.getTagName() + ">");
    dump_nodelist(nl, indent + 1);
    System.out.println("</" + element.getTagName() + ">");
  }

  static void
  dump_nodelist (NodeList nl, int indent)
  {
    for (int loop = 0; loop < nl.getLength(); loop++)
    {
      Node node = nl.item(loop);
      switch (node.getNodeType())
      {
	case Node.ELEMENT_NODE : 
	{
	  dump_element((Element)node, indent);
	  break;
	}
	case Node.TEXT_NODE :
	{
	  System.out.println("TEXT: " + node.getNodeValue());
	  break;
	}
	default :
	{
	  System.out.println("NODE: " + node.getNodeType());
	}
      }
    }
  }

  static Node 
  get_subnode (String name, Node node) 
  {
    if (node.getNodeType() != Node.ELEMENT_NODE) 
    {
      System.err.println("Error: Search node not of element type");
      return null;
    }

    if (!node.hasChildNodes()) return null;

    NodeList list = node.getChildNodes();
    for (int i=0; i < list.getLength(); i++) 
    {
      Node subnode = list.item(i);
      if (subnode.getNodeType() == Node.ELEMENT_NODE) 
      {
	if (subnode.getNodeName() == name) return subnode;
      }
    }
    return null;
  }

  static String 
  get_text (Node node) 
  {
    StringBuffer result = new StringBuffer();
    if (node==null || !node.hasChildNodes()) return "";

    NodeList list = node.getChildNodes();
    for (int i=0; i < list.getLength(); i++) 
    {
      Node subnode = list.item(i);
      if (subnode.getNodeType() == Node.TEXT_NODE) 
      {
	result.append(subnode.getNodeValue());
      }
    }
    return result.toString();
  }

  static void
  parse (PartitionManager pm, VirtualDiskManager vdm, Document document)
  {
    if (document == null) return;

    /* parse partitions */
    parse_partitions(pm, document.getElementsByTagName("partition"));

    /* parse virtual disks */
    NodeList list = document.getElementsByTagName("virtual_disk");
    for (int i = 0; i < list.getLength(); i++)
    {
      Node subnode = list.item(i);
      String parent = subnode.getParentNode().getNodeName();
      VirtualDisk vd =  parse_virtual_disk(subnode);

      if (parent.equals("free"))
      {
	vdm.add_free(vd);
      }
      else if (parent.equals("virtual_disks"))
      {
	vdm.add_virtual_disk(vd);
      }
      else
      {
	System.out.println ("XML parse error: unknown parent for virtual_disk "
			    + "[" + parent + "]");
      }
    }

    /* parse virtual block devices */
    parse_virtual_block_devices(vdm, document.getElementsByTagName("virtual_block_device"));

    return;
  }

  static VirtualDisk
  parse_virtual_disk(Node node)
  {
    VirtualDisk vd;
    Date date = new Date();
    NodeList list;

    date.setTime(Long.parseLong(XMLHelper.get_text(XMLHelper.get_subnode("expiry", node))));
    vd = new VirtualDisk(XMLHelper.get_text(XMLHelper.get_subnode("name", node)),
			 date,
			 XMLHelper.get_text(XMLHelper.get_subnode("key", node)));

    list = XMLHelper.get_subnode("extents", node).getChildNodes();
    for (int i = 0; i < list.getLength(); i++)
    {
      Node enode = list.item(i);

      if (enode.getNodeType() == Node.ELEMENT_NODE &&
	  enode.getNodeName().equals("extent"))
      {
	Extent extent = new Extent();

	extent.disk = Integer.parseInt(XMLHelper.get_text(XMLHelper.get_subnode("disk", enode)));
	extent.size = Long.parseLong(XMLHelper.get_text(XMLHelper.get_subnode("size", enode)));
	extent.offset = Long.parseLong(XMLHelper.get_text(XMLHelper.get_subnode("offset", enode)));
	vd.add_extent(extent);
      }
    }

    return vd;
  }

  static void
  parse_partitions (PartitionManager pm, NodeList nl)
  {
    Partition partition;

    for (int loop = 0; loop < nl.getLength(); loop++)
    {
      Node node = nl.item(loop);

      partition = new Partition();
      partition.major = Integer.parseInt(XMLHelper.get_text(XMLHelper.get_subnode("major", node)));
      partition.minor = Integer.parseInt(XMLHelper.get_text(XMLHelper.get_subnode("minor", node)));
      partition.blocks = Integer.parseInt(XMLHelper.get_text(XMLHelper.get_subnode("blocks", node)));
      partition.start_sect = Integer.parseInt(XMLHelper.get_text(XMLHelper.get_subnode("start_sect", node)));
      partition.nr_sects = Integer.parseInt(XMLHelper.get_text(XMLHelper.get_subnode("nr_sects", node)));
      partition.name = XMLHelper.get_text(XMLHelper.get_subnode("name", node));

      pm.add_xeno_partition(partition);
    }
  }

  static void
  parse_virtual_block_devices (VirtualDiskManager vdm, NodeList nl)
  {
    VirtualBlockDevice vbd;

    for (int loop = 0; loop < nl.getLength(); loop++)
    {
      Node node = nl.item(loop);

      vdm.create_virtual_block_device(XMLHelper.get_text(XMLHelper.get_subnode("key", node)),
				      Integer.parseInt(XMLHelper.get_text(XMLHelper.get_subnode("domain", node))),
				      Integer.parseInt(XMLHelper.get_text(XMLHelper.get_subnode("vbdnum", node))),
				      XMLHelper.get_text(XMLHelper.get_subnode("mode", node)));
    }
  }
}
