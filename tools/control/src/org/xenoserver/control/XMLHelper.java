/*
 * XMLHelper.java
 * 03.03.27 aho creation
 */

package org.xenoserver.control;

import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * XMLHelper contains helper methods used to parse the XML state files.
 */
class XMLHelper {
    /**
     * Find a subnode with the specified name.
     * @param name Name to look for.
     * @param node Node from which to start search.
     * @return The first subnode found, or null if none.
     */
    private static Node getSubNode(String name, Node node) {
        if (node.getNodeType() != Node.ELEMENT_NODE) {
            System.err.println("Error: Search node not of element type");
            return null;
        }

        if (!node.hasChildNodes()) {
            return null;
        }

        NodeList list = node.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            Node subnode = list.item(i);
            if (subnode.getNodeType() == Node.ELEMENT_NODE) {
                if (subnode.getNodeName() == name) {
                    return subnode;
                }
            }
        }
        return null;
    }

    /**
     * Get all the text of a given node.
     * @param node The node to examine.
     * @return The node's text.
     */
    private static String getText(Node node) {
        StringBuffer result = new StringBuffer();
        if (node == null || !node.hasChildNodes()) {
            return "";
        }

        NodeList list = node.getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            Node subnode = list.item(i);
            if (subnode.getNodeType() == Node.TEXT_NODE) {
                result.append(subnode.getNodeValue());
            }
        }
        return result.toString();
    }

    /**
     * Parse the given configuration document and configure the managers.
     * @param pm PartitionManager instance to configure.
     * @param vdm VirtualDomainManager instance to configure.
     * @param document Document to parse.
     */
    static void parse(
        PartitionManager pm,
        VirtualDiskManager vdm,
        Document document) {
        if (document == null) {
            return;
        }

        /* parse partitions */
        parsePartitions(pm, document.getElementsByTagName("partition"));

        /* parse virtual disks */
        NodeList list = document.getElementsByTagName("virtual_disk");
        for (int i = 0; i < list.getLength(); i++) {
            Node subnode = list.item(i);
            String parent = subnode.getParentNode().getNodeName();
            VirtualDisk vd = parseVirtualDisk(subnode);

            if (parent.equals("free")) {
                vdm.setFreeDisk(vd);
            } else if (parent.equals("virtual_disks")) {
                vdm.insertVirtualDisk(vd);
            } else {
                System.out.println(
                    "XML parse error: unknown parent for virtual_disk "
                        + "["
                        + parent
                        + "]");
            }
        }

        /* parse virtual block devices */
        parseVirtualBlockDevices(
            vdm,
            document.getElementsByTagName("virtual_block_device"));

        return;
    }

    /**
     * Parse a node representing a virtual disk.
     * @param node The node to parse.
     * @return The VirtualDisk this node represents.
     */
    private static VirtualDisk parseVirtualDisk(Node node) {
        VirtualDisk vd;
        Date date = new Date();
        NodeList list;

        long timestamp =
            Long.parseLong(
                XMLHelper.getText(XMLHelper.getSubNode("expiry", node)));
        if (timestamp == 0) {
            date = null;
        } else {
            date.setTime(timestamp);
        }
        vd =
            new VirtualDisk(
                XMLHelper.getText(XMLHelper.getSubNode("name", node)),
                date,
                XMLHelper.getText(XMLHelper.getSubNode("key", node)));

        list = XMLHelper.getSubNode("extents", node).getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            Node enode = list.item(i);

            if (enode.getNodeType() == Node.ELEMENT_NODE
                && enode.getNodeName().equals("extent")) {
                Extent extent =
                    new Extent(
                        Integer.parseInt(
                            XMLHelper.getText(
                                XMLHelper.getSubNode("disk", enode))),
                        Long.parseLong(
                            XMLHelper.getText(
                                XMLHelper.getSubNode("size", enode))),
                        Long.parseLong(
                            XMLHelper.getText(
                                XMLHelper.getSubNode("offset", enode))));
                vd.addExtent(extent);
            }
        }

        return vd;
    }

    /**
     * Parse a list of partition nodes.
     * @param pm The partition manager to configure.
     * @param nl The list of partition nodes.
     */
    private static void parsePartitions(PartitionManager pm, NodeList nl) {
        Partition partition;

        for (int loop = 0; loop < nl.getLength(); loop++) {
            Node node = nl.item(loop);

            partition =
                new Partition(
                    Integer.parseInt(
                        XMLHelper.getText(XMLHelper.getSubNode("major", node))),
                    Integer.parseInt(
                        XMLHelper.getText(XMLHelper.getSubNode("minor", node))),
                    Integer.parseInt(
                        XMLHelper.getText(
                            XMLHelper.getSubNode("blocks", node))),
                    Integer.parseInt(
                        XMLHelper.getText(
                            XMLHelper.getSubNode("start_sect", node))),
                    Integer.parseInt(
                        XMLHelper.getText(
                            XMLHelper.getSubNode("nr_sects", node))),
                    XMLHelper.getText(XMLHelper.getSubNode("name", node)),
                    true);

            pm.addXenoPartition(partition);
        }
    }

    /**
     * Parse a list of virtual block device nodes.
     * @param vdm The VirtualDiskManager to configure. 
     * @param nl The node list.
     */
    private static void parseVirtualBlockDevices(
        VirtualDiskManager vdm,
        NodeList nl) {
        for (int loop = 0; loop < nl.getLength(); loop++) {
            Node node = nl.item(loop);
            Mode mode;

            if (XMLHelper
                .getText(XMLHelper.getSubNode("mode", node))
                .equals("rw")) {
                mode = Mode.READ_WRITE;
            } else {
                mode = Mode.READ_ONLY;
            }

            vdm.createVirtualBlockDevice(
                vdm.getVirtualDisk(
                    XMLHelper.getText(XMLHelper.getSubNode("key", node))),
                Integer.parseInt(
                    XMLHelper.getText(XMLHelper.getSubNode("domain", node))),
                Integer.parseInt(
                    XMLHelper.getText(XMLHelper.getSubNode("vbdnum", node))),
                mode);
        }
    }
}
