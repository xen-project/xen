/**
 * (C) Copyright IBM Corp. 2005
 *
 * $Id: XmlToBin.java,v 1.2 2005/06/17 20:00:04 rvaldez Exp $
 *
 * Author: Ray Valdez
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * XmlToBin  Class.  
 * <p>
 *
 * Translates a xml representation of a SHYPE policy into a binary  
 * format.  The class processes an xml policy file based on elment tags 
 * defined in a schema definition files: SecurityPolicySpec.xsd.
 *
 * XmlToBin Command line Options: 
 *
 *      -i              inputFile:      name of policyfile (.xml)
 *      -o              outputFile:     name of binary policy file (Big Endian)
 *      -xssid          SsidFile:       xen ssids to types text file
 *      -xssidconf      SsidConf:   	xen conflict ssids to types text file
 *      -debug                          turn on debug messages
 *      -help                           help. This printout
 *
 * <p>
 *
 *
 */
import java.util.*;
import java.io.*;
import java.io.IOException;
import java.io.FileNotFoundException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Attr;
import org.w3c.dom.NodeList;
import org.w3c.dom.NamedNodeMap;
import org.xml.sax.*;
import javax.xml.parsers.*;
import org.xml.sax.helpers.*;

public class XmlToBin 
 implements XmlToBinInterface
{
  class SlotInfo {
	String bus;
	String slot;
  }

 boolean LittleEndian = false;
 boolean debug = false;

 static final String JAXP_SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";

 static final String W3C_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";

 public static void printUsage()
 {
  System.out.println("XmlToBin Command line Options: ");
  System.out.println("\t-i\t\tinputFile:\tname of policyfile (.xml)");
  System.out.println("\t-o\t\toutputFile:\tname of binary policy file (Big Endian)");
  System.out.println("\t-xssid\t\tSsidFile:\tXen ssids to named types text file");
  System.out.println("\t-xssidconf\tSsidConfFile:\tXen conflict ssids to named types text file");
  System.out.println("\t-debug\t\t\t\tturn on debug messages");
  System.out.println("\t-help\t\t\t\thelp. This printout");
  return;
 }

 public void printDebug(String message) 
 {
  if (debug)
    System.out.println(message);
 }

 public void writeBinPolicy(byte[] binPolicy, String outputFileName)
  throws Exception
 {
    if (debug) 
    	printHex(binPolicy,binPolicy.length);

    DataOutputStream writeObj = new DataOutputStream(
                                new FileOutputStream(outputFileName));

    writeObj.write(binPolicy);
    writeObj.flush();
    writeObj.close();
    System.out.println(" wBP:: wrote outputfile: " + outputFileName);

    return; 
 }  

 public void writeXenTypeVectorFile(Vector list, String outputFileName)
  throws Exception
 {
  PrintWriter out;

  if (0 == list.size())
  {
   	printDebug(" wSTF : size of input is zero when writing :" + outputFileName); 
	return;
  }
 out = new PrintWriter(
	 	new BufferedWriter(
                      new FileWriter(outputFileName)));


  for (int i = 0; i < list.size(); i++)
  {
	Vector	ee = (Vector) list.elementAt(i);
   	out.println(i + " " +ee.toString());
  } 
    out.close();
   
    return; 
 }

 public void writeXenTypeFile(Vector list, String outputFileName, boolean slabel)
  throws Exception
 {
  Vector entry; 
  String strTypes = "";
  SecurityLabel ee;
  PrintWriter out;

  if (0 == list.size())
  {
   	printDebug(" wSTF : size of input is zero when writing :" + outputFileName); 
	return;
  }
  out = new PrintWriter(
	 	new BufferedWriter(
                      new FileWriter(outputFileName)));

  for (int i = 0; i < list.size(); i++)
  {
	ee = (SecurityLabel) list.elementAt(i);

	if (slabel)
	{
		entry = ee.steTypes; 
	} else {

		entry = ee.chwTypes; 
	}
	if (null == entry) continue;

	Enumeration e = entry.elements(); 
	while (e.hasMoreElements())
	{
  	  String typeName = (String) e.nextElement(); 
	  strTypes = strTypes + " " + typeName;
        }
    	  printDebug(" WXTF:: ssid : "+i +" :"+strTypes); 
   	  out.println(i +" "+strTypes);
	  strTypes = "";
  } 
  out.close();
   
  return; 
 }

 public void setDebug(boolean value)
 {
  debug=value;
 }

 public void setEndian(boolean value)
 {
  LittleEndian = value;
 }

 public byte[] generateVlanSsids(Vector bagOfSsids)
  throws Exception
 {
  /**
        typedef struct {
        u16 vlan;
        u16 ssid_ste;
        } acm_vlan_entry_t;
  **/

  Hashtable  vlanSsid = new Hashtable();
  printDebug(" gVS::Size of bagOfSsids: "+ bagOfSsids.size());

  /* Get the number of partitions */
  for (int i = 0; i < bagOfSsids.size(); i++)
  {
	SecurityLabel entry = (SecurityLabel) bagOfSsids.elementAt(i);

	if (null == entry.vlans)
	  continue;

	Enumeration e = entry.vlans.elements(); 
	while (e.hasMoreElements())
	{
  	  String id = (String) e.nextElement(); 
      	  printDebug(" gVS:: vlan: " + id + "has ste ssid: " + entry.steSsidPosition);
	  if (-1 == entry.steSsidPosition)
		continue;  

	  /* Only use ste for vlan */
	  SsidsEntry  ssidsObj = new SsidsEntry();

	  ssidsObj.id = Integer.parseInt(id); 
	  ssidsObj.ste = entry.steSsidPosition;

	  if (vlanSsid.contains(id))
      	  	printDebug(" gVS:: Error already in the Hash part:" + ssidsObj.id);
	  else 
 		vlanSsid.put(id, ssidsObj);
      	  	printDebug(" gVS:: added part: " + id + "has ste ssid: " + entry.steSsidPosition);
	}
  }

  /* allocate array */ 
  int numOfVlan = vlanSsid.size();
  int totalSize = (numOfVlan * vlanEntrySz);  

  if (0 == numOfVlan) 
  {
  	printDebug(" gVS:: vlan: binary ==> zero");
        return new byte[0];
  }

  byte[] vlanArray = new byte[totalSize];

  int index = 0;

  Enumeration e = vlanSsid.elements(); 
  while (e.hasMoreElements())
  {
  	SsidsEntry entry = (SsidsEntry) e.nextElement(); 
      	printDebug(" gVS:: part: " + entry.id + " ste ssid: " + entry.ste);

	/* Write id */
   	writeShortToStream(vlanArray,(short)entry.id,index);
	index = index + u16Size;

	/* write ste ssid */
   	writeShortToStream(vlanArray,(short) entry.ste,index);
	index = index + u16Size;
  }

  printDebug(" gVS:: vlan: num of vlans  " + numOfVlan);
  printDebug(" gVS:: vlan: binary ==> Length "+ vlanArray.length);

  if (debug) 
	printHex(vlanArray,vlanArray.length);
  printDebug("\n");

  return vlanArray; 
 }  

 public byte[] generateSlotSsids(Vector bagOfSsids)
  throws Exception
 {
  /**
        typedef struct {
        u16 slot_max;
        u16 slot_offset;
        } acm_slot_buffer_t;

        typedef struct {
        u16 bus;
        u16 slot;
        u16 ssid_ste;
        } acm_slot_entry_t;
  **/
  Hashtable  slotSsid = new Hashtable();
  printDebug(" gSS::Size of bagOfSsids: "+ bagOfSsids.size());

  /* Find the number of VMs */ 
  for (int i = 0; i < bagOfSsids.size(); i++)
  {
	SecurityLabel entry = (SecurityLabel) bagOfSsids.elementAt(i);

	if (null == entry.slots)
	  continue;

	Enumeration e = entry.slots.elements(); 
	while (e.hasMoreElements())
	{
  	  SlotInfo item = (SlotInfo) e.nextElement(); 
      	  printDebug(" gSS:: bus slot: " + item.bus + " "+ item.slot + " " +  entry.steSsidPosition);
	  if (-1 == entry.steSsidPosition)
		continue;  

	  SsidsEntry  ssidsObj = new SsidsEntry();

	  String id = item.bus +" "+item.slot;
	  ssidsObj.bus = Integer.parseInt(item.bus); 
	  ssidsObj.slot = Integer.parseInt(item.slot); 
	  /* set ste ssid */
	  ssidsObj.ste = entry.steSsidPosition;

	  if (slotSsid.contains(id))
      	  	printDebug(" gSS:: Error already in the Hash part:" + id);
	  else 
	  	slotSsid.put(id, ssidsObj);

      	  	printDebug(" gSS:: added slot: " + id + "has ste ssid: " + entry.steSsidPosition);
	}
  }

  /* allocate array */
  int numOfSlot = slotSsid.size();

  if (0 == numOfSlot) 
  {
  	printDebug(" gVS:: slot: binary ==> zero");
        return new byte[0];
  }

  int totalSize = (numOfSlot * slotEntrySz);  

  byte[] slotArray = new byte[totalSize];

  int index = 0;

  Enumeration e = slotSsid.elements(); 
  while (e.hasMoreElements())
  {
  	SsidsEntry entry = (SsidsEntry) e.nextElement(); 
      	System.out.println(" gSS:: bus slot: " + entry.bus + " " + entry.slot + " ste ssid: " + entry.ste);

	/* Write bus */
   	writeShortToStream(slotArray,(short)entry.bus,index);
	index = index + u16Size;

	/* Write slot */ 
   	writeShortToStream(slotArray,(short)entry.slot,index);
	index = index + u16Size;

	/* Write ste ssid */
   	writeShortToStream(slotArray,(short) entry.ste,index);
	index = index + u16Size;

  }
   
  printDebug(" gSS:: slot: num of vlans  " + numOfSlot);
  printDebug(" gSS:: slot: binary ==> Length "+ slotArray.length);

  if (debug) 
 	 printHex(slotArray,slotArray.length);
  printDebug("\n");

  return slotArray; 

 }  

 public byte[] generatePartSsids(Vector bagOfSsids, Vector bagOfChwSsids)
  throws Exception
 {
  /**
        typedef struct {
        u16 id;
        u16 ssid_ste;
        u16 ssid_chwall;
        } acm_partition_entry_t;

  **/
  Hashtable  partSsid = new Hashtable();
  printDebug(" gPS::Size of bagOfSsids: "+ bagOfSsids.size());

  /* Find the number of VMs */ 
  for (int i = 0; i < bagOfSsids.size(); i++)
  {
	SecurityLabel entry = (SecurityLabel) bagOfSsids.elementAt(i);

	if (null == entry.ids)
	  continue;

	Enumeration e = entry.ids.elements(); 
	while (e.hasMoreElements())
	{
  	  String id = (String) e.nextElement(); 
      	  printDebug(" gPS:: part: " + id + "has ste ssid: " + entry.steSsidPosition);
	  if (-1 == entry.steSsidPosition)
		continue;  

	  SsidsEntry  ssidsObj = new SsidsEntry();

	  ssidsObj.id = Integer.parseInt(id); 
	  ssidsObj.ste = entry.steSsidPosition;

	  if (partSsid.contains(id))
      	  	printDebug(" gPS:: Error already in the Hash part:" + ssidsObj.id);
	  else 
 		partSsid.put(id, ssidsObj);
      	  	printDebug(" gPS:: added part: " + id + "has ste ssid: " + entry.steSsidPosition);
	}

  }

  for (int i = 0; i < bagOfChwSsids.size(); i++)
  {
	SecurityLabel entry = (SecurityLabel) bagOfChwSsids.elementAt(i);

	Enumeration e = entry.chwIDs.elements(); 
	while (e.hasMoreElements())
	{
  	  String id = (String) e.nextElement(); 
      	  printDebug(" gPS:: part: " + id + "has chw ssid: " + entry.chwSsidPosition);
	  if (partSsid.containsKey(id))
	  {
		SsidsEntry item = (SsidsEntry) partSsid.get(id);
		item.chw = entry.chwSsidPosition;
      	  	printDebug(" gPS:: added :" + item.id +" chw: " + item.chw);
	  }
	  else 
	  {
      	  	printDebug(" gPS:: creating :" + id +" chw: " + entry.chwSsidPosition);
	  	SsidsEntry  ssidsObj = new SsidsEntry();
	  	ssidsObj.id = Integer.parseInt(id); 
	  	ssidsObj.chw = entry.chwSsidPosition;
 		partSsid.put(id, ssidsObj);

	  }
	}
  }	  

  /* Allocate array */
  int numOfPar = partSsid.size();
  int totalSize =  (numOfPar * partitionEntrySz);  

  if (0 == numOfPar) 
  {
  	printDebug(" gPS:: part: binary ==> zero");
        return new byte[0];
  }

  byte[] partArray = new byte[totalSize];

  int index = 0;

  Enumeration e = partSsid.elements(); 
  while (e.hasMoreElements())
  {
  	SsidsEntry entry = (SsidsEntry) e.nextElement(); 
      	printDebug(" gPS:: part: " + entry.id + " ste ssid: " + entry.ste + " chw ssid: "+ entry.chw);

	/* Write id */
   	writeShortToStream(partArray,(short)entry.id,index);
	index = index + u16Size;

	/* Write ste ssid */
   	writeShortToStream(partArray,(short) entry.ste,index);
	index = index + u16Size;

	/* Write chw ssid */
   	writeShortToStream(partArray,(short) entry.chw,index);
	index = index + u16Size;
  }

  printDebug(" gPS:: part: num of partitions  " + numOfPar);
  printDebug(" gPS:: part: binary ==> Length " + partArray.length);

  if (debug) 
	printHex(partArray,partArray.length);
  printDebug("\n");
   
   return partArray; 
 }

 public  byte[] GenBinaryPolicyBuffer(byte[] chwPolicy, byte[] stePolicy, byte [] partMap, byte[] vlanMap, byte[] slotMap)
 {
  byte[] binBuffer;
  short chwSize =0;
  short steSize =0;
  int	index = 0;

  /* Builds data structure acm_policy_buffer_t */
  /* Get number of colorTypes */
  if (null != chwPolicy)
	chwSize = (short) chwPolicy.length;

  if (null != stePolicy)
    	steSize = (short) stePolicy.length;

  int totalDataSize = chwSize + steSize + resourceOffsetSz +  3 *(2 * u16Size);

  /*  Add vlan and slot */ 
  totalDataSize = totalDataSize +partMap.length + vlanMap.length + slotMap.length; 
  binBuffer = new byte[binaryBufferHeaderSz +totalDataSize];
	

  try {
	/* Write magic */
	writeIntToStream(binBuffer,ACM_MAGIC,index);
	index = u32Size;

	/* Write policy version */
	writeIntToStream(binBuffer,POLICY_INTERFACE_VERSION,index);
  	index = index + u32Size;

	/* write len */
	writeIntToStream(binBuffer,binBuffer.length,index);
  	index = index + u32Size;

  } catch (IOException ee) {
    	System.out.println(" GBPB:: got exception : " + ee); 
	return null;
  }

  int offset, address;
  address = index;

  if (null != partMap) 
	offset = binaryBufferHeaderSz + resourceOffsetSz; 
  else
	offset = binaryBufferHeaderSz; 

  try {

	if (null == chwPolicy || null == stePolicy) 
	{
	  writeShortToStream(binBuffer,ACM_NULL_POLICY,index);
  	  index = index + u16Size;

	  writeShortToStream(binBuffer,(short) 0,index);
  	  index = index + u16Size;

	  writeShortToStream(binBuffer,ACM_NULL_POLICY,index);
  	  index = index + u16Size;

	  writeShortToStream(binBuffer,(short) 0,index);
  	  index = index + u16Size;

	}
    	index = address;
	if (null != chwPolicy) 
	{
	  
	  /* Write policy name */
	  writeShortToStream(binBuffer,ACM_CHINESE_WALL_POLICY,index);
  	  index = index + u16Size;

	  /* Write offset */
	  writeShortToStream(binBuffer,(short) offset,index);
  	  index = index + u16Size;

	  /* Write payload. No need increment index */
	  address = offset;
	  System.arraycopy(chwPolicy, 0, binBuffer,address, chwPolicy.length);
	  address = address + chwPolicy.length;
	  
	  if (null != stePolicy) 
	  {	
	  	/* Write policy name */
	  	writeShortToStream(binBuffer,ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY,index);
  	  	index = index + u16Size;

	  	/* Write offset */
	  	writeShortToStream(binBuffer,(short) address,index);
  	  	index = index + u16Size;

		/* Copy array */
	  	System.arraycopy(stePolicy, 0, binBuffer,address, stePolicy.length);
		/* Update address */
		address = address + stePolicy.length;
	  } else {
	  	/* Skip writing policy name and offset */
  	  	index = index +  2 * u16Size;

          }

	} else {

	  if (null != stePolicy) 
	  {	
	  	/* Write policy name */
	  	writeShortToStream(binBuffer,ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY,index);
  	  	index = index + u16Size;

	  	/* Write offset */
		address = offset;
	  	writeShortToStream(binBuffer, (short) offset,index);
  	  	index = index + u16Size;
		
		/* Copy array */
	  	System.arraycopy(stePolicy, 0, binBuffer,address, stePolicy.length);
		/* Update address */
		address = address + stePolicy.length;

		/* Increment index, since there is no secondary */
  	  	index = index + secondaryPolicyCodeSz + secondaryBufferOffsetSz;
		
	  } 

	}
   	int size;
	/* Assumes that you will always have a partition defined in policy */ 
	if ( 0 < partMap.length)
	{
	  writeShortToStream(binBuffer, (short) address,index);
	  index = address;

	  /* Compute num of VMs */
	  size = partMap.length / (3 * u16Size);

	  writeShortToStream(binBuffer, (short)size,index);
  	  index = index + u16Size;

	  /* part, vlan and slot: each one consists of two entries */
	  offset = 3 * (2 * u16Size); 
	  writeShortToStream(binBuffer, (short) offset,index);

	  /* Write partition array at offset */
	  System.arraycopy(partMap, 0, binBuffer,(offset + address), partMap.length);
  	  index = index + u16Size;
	  offset = offset + partMap.length;
	}

	if ( 0 < vlanMap.length)
	{
	  size = vlanMap.length / (2 * u16Size);
	  writeShortToStream(binBuffer, (short) size,index);
  	  index = index + u16Size;

	  writeShortToStream(binBuffer, (short) offset,index);
  	  index = index + u16Size;
	  System.arraycopy(vlanMap, 0, binBuffer,(offset + address), vlanMap.length);
	} else {
	  /* Write vlan max */
	  writeShortToStream(binBuffer, (short) 0,index);
  	  index = index + u16Size;
 
	  /* Write vlan offset */
	  writeShortToStream(binBuffer, (short) 0,index);
  	  index = index + u16Size;
	  
   	}

	offset = offset + vlanMap.length;
	if ( 0 < slotMap.length)
	{
	  size = slotMap.length / (3 * u16Size);
	  writeShortToStream(binBuffer, (short) size,index);
  	  index = index + u16Size;

	  writeShortToStream(binBuffer, (short) offset,index);
  	  index = index + u16Size;
	  System.arraycopy(slotMap, 0, binBuffer,(offset + address), slotMap.length);
	}

     } catch (IOException ee)
    {
    	System.out.println(" GBPB:: got exception : " + ee); 
	return null; 
    }

    printDebug(" GBP:: Binary Policy ==> length " + binBuffer.length); 
    if (debug) 
   	printHex(binBuffer,binBuffer.length);

   return  binBuffer;   
 } 

 public  byte[] generateChwBuffer(Vector Ssids, Vector ConflictSsids, Vector ColorTypes)
 {
  byte[] chwBuffer;
  int index = 0;
  int position = 0;

  /* Get number of rTypes */
  short maxTypes = (short) ColorTypes.size();

  /* Get number of SSids entry */
  short maxSsids = (short) Ssids.size();

  /* Get number of conflict sets */
  short maxConflict = (short) ConflictSsids.size();

   
  if (maxTypes * maxSsids == 0)
	return null; 
  /*
     data structure acm_chwall_policy_buffer_t;
    
     uint16 policy_code;
     uint16 chwall_max_types;
     uint16 chwall_max_ssidrefs;
     uint16 chwall_max_conflictsets;
     uint16 chwall_ssid_offset;
     uint16 chwall_conflict_sets_offset;
     uint16 chwall_running_types_offset;
     uint16 chwall_conflict_aggregate_offset;
  */
  int totalBytes = chwHeaderSize  + u16Size *(maxTypes * (maxSsids + maxConflict)); 

  chwBuffer = new byte[ totalBytes ];
  int address = chwHeaderSize + (u16Size * maxTypes * maxSsids );

  printDebug(" gCB:: chwall totalbytes : "+totalBytes); 

  try {
	index = 0;
	writeShortToStream(chwBuffer,ACM_CHINESE_WALL_POLICY,index);
	index = u16Size; 

	writeShortToStream(chwBuffer,maxTypes,index);
	index = index + u16Size; 

	writeShortToStream(chwBuffer,maxSsids,index);
	index = index + u16Size; 

	writeShortToStream(chwBuffer,maxConflict,index);
	index = index + u16Size; 

        /*  Write chwall_ssid_offset */
	writeShortToStream(chwBuffer,chwHeaderSize,index);
	index = index + u16Size; 

	/* Write chwall_conflict_sets_offset */
	writeShortToStream(chwBuffer,(short) address,index);
	index = index + u16Size; 

	/*  Write chwall_running_types_offset */
	writeShortToStream(chwBuffer,(short) 0,index);
	index = index + u16Size; 

	/*  Write chwall_conflict_aggregate_offset */
	writeShortToStream(chwBuffer,(short) 0,index);
	index = index + u16Size; 

  } catch (IOException ee) {
    	System.out.println(" gCB:: got exception : " + ee); 
	return null;
  }
  int markPos = 0;

  /* Create the SSids entry */
  for (int i = 0; i < maxSsids; i++)
  {
	
	SecurityLabel ssidEntry = (SecurityLabel) Ssids.elementAt(i);
   	/* Get chwall types */
	ssidEntry.chwSsidPosition = i;
	Enumeration e = ssidEntry.chwTypes.elements(); 
	while (e.hasMoreElements())
	{
  	  String typeName = (String) e.nextElement(); 
      	  printDebug(" gCB:: Ssid "+ i+ ": has type : " + typeName);
	  position = ColorTypes.indexOf(typeName);

	  if (position < 0) 
	  {
      	  	System.out.println (" gCB:: Error type : " + typeName + " not found in ColorTypes"); 
		return null; 
	  }
   	  printDebug(" GCB:: type : " + typeName + "  found in ColorTypes at position: " + position); 
	  markPos = ((i * maxTypes + position) * u16Size) + index;	

	  try {
	  	writeShortToStream(chwBuffer,markSymbol,markPos);
  	  } catch (IOException ee) {
   	  	System.out.println(" gCB:: got exception : "); 
		return null; 
  	  }
	}
  }

  if (debug) 
      printHex(chwBuffer,chwBuffer.length);

  /* Add conflict set */
  index = address;
  for (int i = 0; i < maxConflict; i++)
  {
   	/* Get ste types */
	Vector entry = (Vector) ConflictSsids.elementAt(i);
	Enumeration e = entry.elements(); 
	while (e.hasMoreElements())
	{
  	  String typeName = (String) e.nextElement(); 
      	  printDebug (" GCB:: conflict Ssid "+ i+ ": has type : " + typeName);
	  position = ColorTypes.indexOf(typeName);

	  if (position < 0) 
	  {
      	  	System.out.println (" GCB:: Error type : " + typeName + " not found in ColorTypes"); 
		return null; 
	  }
   	  printDebug(" GCB:: type : " + typeName + "  found in ColorTypes at position: " + position); 
	  markPos = ((i * maxTypes + position) * u16Size) + index;	

	  try {
	  	writeShortToStream(chwBuffer,markSymbol,markPos);
  	  } catch (IOException ee) {
   	  	System.out.println(" GCB:: got exception : "); 
		return null; 
  	  }
	}
		
  } 
  printDebug(" gSB:: chw binary  ==> Length " + chwBuffer.length); 
  if (debug) 
   	printHex(chwBuffer,chwBuffer.length);
  printDebug("\n");

  return chwBuffer;
 }

/**********************************************************************
 Generate byte representation of policy using type information
 <p>
 @param Ssids    	      	Vector
 @param ColorTypes         	Vector
 <p>
 @return bytes represenation of simple type enforcement policy 
**********************************************************************/
 public  byte[] generateSteBuffer(Vector Ssids, Vector ColorTypes)
 {
  byte[] steBuffer;
  int index = 0;
  int position = 0;

  /* Get number of colorTypes */
  short numColorTypes = (short) ColorTypes.size();

  /* Get number of SSids entry */
  short numSsids = (short) Ssids.size();
   
  if (numColorTypes * numSsids == 0)
	return null; 

  /* data structure: acm_ste_policy_buffer_t
   * 
   * policy code  (uint16)    >
   *  max_types    (uint16)    >
   * max_ssidrefs (uint16)    >  steHeaderSize
   * ssid_offset  (uint16)    >
   * DATA 	(colorTypes(size) * Ssids(size) *unit16)
   * 
   * total bytes: steHeaderSize * 2B + colorTypes(size) * Ssids(size)
   * 
  */
  steBuffer = new byte[ steHeaderSize + (numColorTypes * numSsids) * 2];

  try {
	
	index = 0;
	writeShortToStream(steBuffer,ACM_SIMPLE_TYPE_ENFORCEMENT_POLICY,index);
	index = u16Size; 

	writeShortToStream(steBuffer,numColorTypes,index);
	index = index + u16Size; 

	writeShortToStream(steBuffer,numSsids,index);
	index = index + u16Size; 

	writeShortToStream(steBuffer,(short)steHeaderSize,index);
	index = index + u16Size; 

  } catch (IOException ee) {
	System.out.println(" gSB:: got exception : " + ee); 
	return null; 
  }
  int markPos = 0;
  for (int i = 0; i < numSsids; i++)
  {
	
	SecurityLabel ssidEntry = (SecurityLabel) Ssids.elementAt(i);
	ssidEntry.steSsidPosition = i;
   	/* Get ste types */
	Enumeration e = ssidEntry.steTypes.elements(); 
	while (e.hasMoreElements())
	{
  	  String typeName = (String) e.nextElement(); 
      	  printDebug (" gSB:: Ssid "+ i+ ": has type : " + typeName);
	  position = ColorTypes.indexOf(typeName);

	  if (position < 0) 
	  {
      	  	printDebug(" gSB:: Error type : " + typeName + " not found in ColorTypes"); 
		return null; 
	  }
   	  printDebug(" gSB:: type : " + typeName + "  found in ColorTypes at position: " + position); 
	  markPos = ((i * numColorTypes + position) * u16Size) + index;	

	  try {
	  	writeShortToStream(steBuffer,markSymbol,markPos);
  	  } catch (IOException ee)
  	  {
   	  	System.out.println(" gSB:: got exception : "); 
		return null; 
  	  }
	}
		
  } 

  printDebug(" gSB:: ste binary  ==> Length " + steBuffer.length); 
  if (debug) 
 	printHex(steBuffer,steBuffer.length);
  printDebug("\n");

  return steBuffer;
 }

 public static  void printHex(byte [] dataArray, int length)
 {
  char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  int hexIndex;
  int value;
  int arraylength;

  arraylength = length;

  if (dataArray == null)
  {
        System.err.print("printHex: input byte array is null");
  }

  if (length > dataArray.length || length < 0)
        arraylength = dataArray.length;

  System.out.print("\n\t");

  int i;
  for(i = 0; i < arraylength; )
  {
        value = dataArray[i] & 0xFF;
        hexIndex = (value >>> 4);
        System.out.print(hexChars[hexIndex]);
        hexIndex = (value & 0x0F);
        System.out.print(hexChars[hexIndex]);

        i++;
        /* if done, print a final newline */
        if (i == arraylength) {
            if (arraylength < dataArray.length) {
                System.out.print("...");
            }
            System.out.println();
        }
        else if ((i % 24) == 0) {
            System.out.print("\n\t");
        }
        else if ((i % 4) == 0) {
                System.out.print(" ");
        }
  }

  return;
 }

  
 private void writeShortToStream(byte[] stream, short value, int index)
  throws IOException
 {
  int littleEndian = 0;
  int byteVal;

  if (index + 2 > stream.length)
  {
      throw new IOException("Writing beyond stream length: " +
                            stream.length + " writing at locations from: " + index + " to " + (index + 4));
  }

  if (!LittleEndian)
  {

	byteVal = value >> 8;
	stream[index ] = (byte) byteVal;

	byteVal = value;
	stream[index + 1] = (byte) byteVal;
  } else {
	stream[index]  = (byte) ((value & 0x00ff) );
	stream[index + 1]  = (byte) ((value & 0xff00) >> 8);
 }
  return;
 }

 private void writeIntToStream(byte[] stream, int value, int index)
  throws IOException
 {
  int littleEndian = 0;
  int byteVal;

  if (4 > stream.length)
  {
      throw new IOException("writeIntToStream: stream length less than 4 bytes " +
                            stream.length);
  }

  /* Do not Write beyond range */
  if (index + 4 > stream.length)
  {
      throw new IOException("writeIntToStream: writing beyond stream length: " +
                            stream.length + " writing at locations from: " + index + " to " + (index + 4));
  }
  if (!LittleEndian)
  {
	byteVal = value >>> 24;
	stream[index] = (byte) byteVal;

	byteVal = value >> 16;
	stream[index + 1] = (byte) byteVal;

	byteVal = value >> 8;
	stream[index + 2] = (byte) byteVal;

	byteVal = value;
	stream[index + 3] = (byte) byteVal;
  } else {
	stream[index] = (byte) value;
	stream[index + 1]  = (byte) ((value & 0x0000ff00) >> 8);
	stream[index + 2]  = (byte) ((value & 0x00ff0000) >> 16);
	stream[index + 3] = (byte) ( value >>> 24);
  }
  return;
 }

 public Document getDomTree(String xmlFileName)
  throws Exception, SAXException, ParserConfigurationException
 {
  javax.xml.parsers.DocumentBuilderFactory dbf = 
	javax.xml.parsers.DocumentBuilderFactory.newInstance();

  /* Turn on namespace aware and validation */
  dbf.setNamespaceAware(true);	
  dbf.setValidating(true);	
  dbf.setAttribute(JAXP_SCHEMA_LANGUAGE,W3C_XML_SCHEMA);

  /* Checks that the document is well-formed */
  javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();

  myHandler errHandler= new myHandler();
  db.setErrorHandler(errHandler);
  Document doc = db.parse(xmlFileName);

  /* Checks for validation errors */
  if (errHandler.isValid)
       printDebug(" gDT:: Xml file: " + xmlFileName + " is valid");
   else
      throw new Exception("Xml file: " + xmlFileName + " is NOT valid");

  return doc;
 }  

 public void processDomTree(
	Document doc,
	Vector bagOfSsids, 	
	Vector bagOfTypes, 
	Vector bagOfChwSsids, 
	Vector bagOfChwTypes, 
	Vector bagOfConflictSsids)
  throws Exception, SAXException, ParserConfigurationException
 {
  boolean found;

  /* print the root Element */
  Element root = doc.getDocumentElement();
  printDebug ("\n pDT:: Document Element: Name = " + root.getNodeName() + ",Value = " + root.getNodeValue());

  /* Go through the list of the root Element's Attributes */
  NamedNodeMap nnm = root.getAttributes();
  printDebug (" pDT:: # of Attributes: " + nnm.getLength());
  for (int i = 0; i < nnm.getLength(); i++)
  {
         Node n = nnm.item (i);
        printDebug (" pDT:: Attribute: Name = " + n.getNodeName() + ", Value = " 
             + n.getNodeValue());
  }

  /* Retrieve the policy definition */ 
  NodeList elementList = root.getElementsByTagName ("url");
  String definitionFileName = elementList.item(0).getFirstChild().getNodeValue();  

  String definitionHash = null;

  /* Note that SecurityPolicySpec.xsd allows for 0 hash value! */
  elementList = root.getElementsByTagName ("hash");
  if (0 != elementList.getLength())
      	definitionHash = elementList.item(0).getFirstChild().getNodeValue();  

  Document definitionDoc = pGetDomDefinition(definitionFileName,definitionHash);
  pGetTypes(definitionDoc,bagOfTypes, bagOfChwTypes, bagOfConflictSsids);


  /* Get VM security information */
  elementList = root.getElementsByTagName ("VM");
  printDebug ("\n pDT:: partition length of NodeList:" + elementList.getLength());


  for (int x = 0; x < elementList.getLength(); x++)
  {
	found = false;

        Node node = elementList.item (x);          

	if (node.getNodeType() == Node.ELEMENT_NODE)
	{
	  printDebug (" pDT:: child: " + x + " is an element node" );
	  Element e1 = (Element) node;

  	  /* Get id */
      	  NodeList elist = e1.getElementsByTagName ("id");
      	  String idStr = elist.item(0).getFirstChild().getNodeValue();  
      	  printDebug (" pDT:: id:" + idStr);

	  /* Get TE */
	  Vector colorTypes = new Vector();
	  pConflictEntries(e1, "TE", bagOfTypes, colorTypes);

	  Enumeration e = bagOfSsids.elements();
	  while (e.hasMoreElements())
	  {
		SecurityLabel elem = (SecurityLabel) e.nextElement(); 
		if ( elem.steTypes.size() == colorTypes.size() && elem.steTypes.containsAll(colorTypes))
		{
		  found = true;
		  elem.ids.add(idStr);
		}
		
	  }
		if (!found && (0 < colorTypes.size()))
		{
		 SecurityLabel entry = new SecurityLabel();
		 entry.steTypes = colorTypes;
		 entry.ids = new Vector();
		 entry.ids.add(idStr);
		 bagOfSsids.add(entry);
		}

		/* Get Chinese wall type */
	 	Vector chwTypes = new Vector();
		pConflictEntries(e1, "ChWall", bagOfChwTypes, chwTypes);

	        found = false;
		e = bagOfChwSsids.elements();

		while (e.hasMoreElements())
		{
  		  SecurityLabel elem = (SecurityLabel) e.nextElement(); 
		  if ( elem.chwTypes.size() == chwTypes.size() && elem.chwTypes.containsAll(chwTypes))
		  {
		    found = true;
		    elem.chwIDs.add(idStr);
		  }
		
		}

		if (!found && (0 < chwTypes.size()))
		{
		 SecurityLabel entry = new SecurityLabel();
		 entry.chwTypes = chwTypes;
		 entry.chwIDs = new Vector();
		 entry.chwIDs.add(idStr);
		 bagOfChwSsids.add(entry);
		}
      }
  } 
  return;
 }

 public Document pGetDomDefinition(
	String definitionFileName, 
	String definitionHash) 
  throws Exception, SAXException, ParserConfigurationException
 {
  printDebug("\n pGDD:: definition file name: " + definitionFileName);
  printDebug("\n pGDD:: definition file hash: " + definitionHash);
  
  Document doc =  getDomTree(definitionFileName);
  return doc; 
 }

 public void pGetTypes(
	Document defDoc,
	Vector bagOfTypes, 
	Vector bagOfChwTypes, 
	Vector bagOfConflictSsids)
  throws Exception
 {


  if (null == defDoc)
      throw new Exception(" pGT:: definition file DOM is null ");

  Element root = defDoc.getDocumentElement();

  /* Get list of TE types */
  NodeList elementList = root.getElementsByTagName ("Types");
  printDebug ("\n pGT:: Types length of NodeList:" + elementList.getLength());
  Element e1 = (Element) elementList.item (0);          
  pGetEntries(e1,"TE",bagOfTypes);

  /* Get list of Chinese types */
  elementList = root.getElementsByTagName ("ChWallTypes");
  printDebug ("\n pGT:: ChwTypes length of NodeList:" + elementList.getLength());
  if (0 ==  elementList.getLength())
  {
  	printDebug ("\n pGT:: ChWallTypes has zero length: :" + elementList.getLength());
  } else {
	e1 = (Element) elementList.item (0);          
	pGetEntries(e1,"ChWall",bagOfChwTypes);
  }
  printDebug (" pGT:: Total number of unique chw types: " + bagOfChwTypes.size());

  /* Get Chinese type conflict sets */
  elementList = root.getElementsByTagName ("ConflictSet");
  printDebug ("\n pGT:: Conflict sets length of NodeList:" + elementList.getLength());
  for (int x = 0; x < elementList.getLength(); x++)
  {
 	Vector conflictEntry  = new Vector();
  	e1 = (Element) elementList.item (x);          
  	printDebug ("\n pGT:: Conflict sets : " + x);

	pConflictEntries(e1, "ChWall", bagOfChwTypes, conflictEntry);

	if (conflictEntry.size() > 0)
	{
	  boolean found = false;
	  Enumeration e = bagOfConflictSsids.elements();
	
	  while (e.hasMoreElements())
	  {
		Vector elem = (Vector) e.nextElement(); 
		if (elem.size() == conflictEntry.size() && elem.containsAll(conflictEntry))
	  	{
	    	  found = true;
	  	}
		
	  }
	  if (!found)
	  {
		bagOfConflictSsids.add(conflictEntry);
	  }
  	}
  }

 }

 public void  pGetEntries(Element doc, String tag, Vector typeBag)
  throws Exception
 {

  if (null == doc)
      throw new Exception(" pGE:: Element doc is null");

  if (null == typeBag)
      throw new Exception(" pGE:: typeBag  is null");

  NodeList elist = doc.getElementsByTagName (tag);
  for (int j = 0; j < elist.getLength(); j++)
  {
  	Node knode = elist.item (j);          
       	Node childNode = knode.getFirstChild();     
       	String value = childNode.getNodeValue();

	printDebug (" pGT:: "+ tag +" type: " + value);

        /* Check if value is known */
	if (!typeBag.contains(value))
		typeBag.addElement(value);
  }
 }

 public void  pConflictEntries(Element doc, String tag, Vector typeBag, Vector conflictEntry)
  throws Exception
 {

  if (null == doc)
      throw new Exception(" pGE:: Element doc is null");

  if (null == typeBag)
      throw new Exception(" pGE:: typeBag  is null");

  if (null == conflictEntry)
      throw new Exception(" pGE:: typeBag  is null");


  NodeList elist = doc.getElementsByTagName (tag);

  for (int j = 0; j < elist.getLength(); j++)
  {
  	Node knode = elist.item (j);          
       	Node childNode = knode.getFirstChild();     
       	String value = childNode.getNodeValue();

	printDebug (" pGE:: "+ tag +" type: " + value);

        /* Check if value is known */
	if (!typeBag.contains(value))
      		throw new Exception(" pCE:: found undefined type set " + value);

	if (!conflictEntry.contains(value))
		conflictEntry.addElement(value);

  }
 }

  public void processDomTreeVlanSlot(
	Document doc,
	Vector bagOfSsids, 	
	Vector bagOfTypes) 	
  throws Exception
 {
      boolean found;

  printDebug(" pDTVS::Size of bagOfSsids: "+ bagOfSsids.size());
  Element root = doc.getDocumentElement();

  NodeList elementList = root.getElementsByTagName ("Vlan");
  printDebug("\n pDTVS:: Vlan length of NodeList:" + elementList.getLength());

  for (int x = 0; x < elementList.getLength(); x++)
  {
	found = false;

        Node node = elementList.item (x);          

	if (node.getNodeType() == Node.ELEMENT_NODE)
	{
	  printDebug(" pDTVS:: child: " + x + " is an element node" );
	  Element e1 = (Element) node;

	  /* Get vid */
      	  NodeList elist = e1.getElementsByTagName ("vid");
      	  String idStr = elist.item(0).getFirstChild().getNodeValue();  
      	  printDebug ("pDTVS:: vid:" + idStr);

	  /* Get TE */
      	  elist = e1.getElementsByTagName ("TE");
          printDebug ("pDTVS:: Total ste types: " + elist.getLength());

	  Vector colorTypes = new Vector();
	  for (int j = 0; j < elist.getLength(); j++)
	  {
		Node knode = elist.item (j);          
        	Node childNode = knode.getFirstChild();     
        	String value = childNode.getNodeValue();

		printDebug (" pDT:: My color is: " + value);
		if (!bagOfTypes.contains(value))
		{
      		  throw new IOException("pDT:: Vlan: " + idStr+ " has unknown type : "+ value);
		}

		if (!colorTypes.contains(value))
		  colorTypes.addElement(value);
	  }
	  Enumeration e = bagOfSsids.elements();
	  while (e.hasMoreElements())
	  {
		SecurityLabel elem = (SecurityLabel) e.nextElement(); 
		if ( elem.steTypes.size() == colorTypes.size() && elem.steTypes.containsAll(colorTypes))
		{
		  found = true;
		  if (null == elem.vlans)
			elem.vlans = new Vector();
		   elem.vlans.add(idStr);
		}
		
	  }
	  if (!found && (0 < colorTypes.size()))
	  {
		 SecurityLabel entry = new SecurityLabel();
		 entry.steTypes = colorTypes;
		 entry.vlans = new Vector();
		 entry.vlans.add(idStr);
		 bagOfSsids.add(entry);
	  }

	}
  } 
  printDebug(" pDTVS::After slot Size of bagOfSsids: "+ bagOfSsids.size());

  elementList = root.getElementsByTagName ("Slot");
  printDebug ("\n pDTVS:: Slot length of NodeList:" + elementList.getLength());

  for (int x = 0; x < elementList.getLength(); x++)
  {
	found = false;

        Node node = elementList.item (x);          

	if (node.getNodeType() == Node.ELEMENT_NODE)
	{
	  printDebug(" pDT:: child: " + x + " is an element node" );
	  Element e1 = (Element) node;


	  /* Get slot and bus */
	  SlotInfo item = new SlotInfo();

	  NodeList elist = e1.getElementsByTagName ("bus");
	  item.bus = elist.item(0).getFirstChild().getNodeValue();  
      	  elist = e1.getElementsByTagName ("slot");
      	  item.slot = elist.item(0).getFirstChild().getNodeValue();  
      	  printDebug ("pDT:: bus and slot:" + item.bus + " "+ item.slot);

	  /* Get TE */
      	  elist = e1.getElementsByTagName ("TE");
          printDebug ("pDT:: Total ste types: " + elist.getLength());

	  Vector colorTypes = new Vector();
	  for (int j = 0; j < elist.getLength(); j++)
	  {
        	Node knode = elist.item (j);          
        	Node childNode = knode.getFirstChild();     
        	String value = childNode.getNodeValue();

		printDebug ("pDT:: My color is: " + value);
		if (!bagOfTypes.contains(value))
		{
		  throw new IOException("pDT:: bus: " + item.bus + " slot: "+ item.slot + " has unknown type : "+ value);
		}

		if (!colorTypes.contains(value))
		  colorTypes.addElement(value);
		}

		Enumeration e = bagOfSsids.elements();
		while (e.hasMoreElements())
		{
  		  SecurityLabel elem = (SecurityLabel) e.nextElement(); 
		  if ( elem.steTypes.size() == colorTypes.size() && elem.steTypes.containsAll(colorTypes))
		  {
			found = true;
			if (null == elem.slots)
			  elem.slots = new Vector();
			elem.slots.add(item);

		  }
		
		}

		if (!found && (0 < colorTypes.size()))
		{
		  SecurityLabel entry = new SecurityLabel();
		  entry.steTypes = colorTypes;
		  entry.slots = new Vector();
		  entry.slots.add(item);
		  bagOfSsids.add(entry);
		}

	}
  }
  return;
 }

 public static void main (String[] args) 
 {
  String xmlFileName = null;        	/* policy file */ 
  String outputFileName = null;     	/* binary policy file */
  String xenSsidOutputFileName = null; 	/* outputfile ssid to named types */	
					/* outputfile conflicts ssid to named types */	
  String xenSsidConfOutputFileName = null; 	

  XmlToBin genObj = new XmlToBin(); 


  for (int i = 0 ; i < args.length ; i++) {

	if ( args[i].equals("-help"))  {
          printUsage();
          System.exit(1);

        } else if ( args[i].equals("-i"))  {
          i++;
          if (i < args.length) {
               xmlFileName = args[i];   
          } else  {
                System.out.println("-i argument needs parameter");
                System.exit(1);
          }

	} else if ( args[i].equals("-o"))  {
          i++;
          if (i < args.length) {
                outputFileName = args[i];   
          } else {
                System.out.println("-o argument needs parameter");
                System.exit(1);
          }

	} else if ( args[i].equals("-xssid"))  {
          i++;
          if (i < args.length) {
                 xenSsidOutputFileName = args[i];   
          } else {
                System.out.println("-xssid argument needs parameter");
                System.exit(1);
          }

	} else if ( args[i].equals("-xssidconf"))  {
          i++;
          if (i < args.length) {
                xenSsidConfOutputFileName = args[i]; 
          } else {
                System.out.println("-xssidconf argument needs parameter");
                System.exit(1);
          }
	} else if ( args[i].equals("-debug"))  { /* turn on debug msg */
	 	genObj.setDebug(true);
        } else {
          System.out.println("bad command line argument: " + args[i]);
          printUsage();
          System.exit(1);
        }

  }

  if (xmlFileName == null)
  { 
	System.out.println("Need to specify input file -i option");
        printUsage();
        System.exit(1);
  }


  try 
  {
	/* Parse and validate */
 	Document doc =  genObj.getDomTree(xmlFileName);

	/* Vectors to hold sets of types */
	Vector bagOfSsids = new Vector();
	Vector bagOfTypes = new Vector();
	Vector bagOfChwSsids = new Vector();
	Vector bagOfChwTypes = new Vector();
	Vector bagOfConflictSsids = new Vector();

	Vector vlanMapSsids = new Vector();
	Vector slotMapSsids = new Vector();

	genObj.processDomTree(doc, bagOfSsids, bagOfTypes, bagOfChwSsids, bagOfChwTypes, bagOfConflictSsids);

	genObj.processDomTreeVlanSlot(doc, bagOfSsids, bagOfTypes);

	/* Get binary representation of policies */
  	byte[] stePolicy = genObj.generateSteBuffer(bagOfSsids, bagOfTypes);
  	byte[] chwPolicy = genObj.generateChwBuffer(bagOfChwSsids, bagOfConflictSsids,bagOfChwTypes);

  	byte[] binPolicy = null;
 	byte[] binaryPartionSsid = null;
  	byte[] binaryVlanSsid = null;
  	byte[] binarySlotSsid = null;

	/* Get binary representation of partition to ssid mapping */
  	binaryPartionSsid = genObj.generatePartSsids(bagOfSsids,bagOfChwSsids);

	/* Get binary representation of vlan to ssid mapping */
  	binaryVlanSsid = genObj.generateVlanSsids(bagOfSsids);

	/* Get binary representation of slot to ssid mapping */
  	binarySlotSsid = genObj.generateSlotSsids(bagOfSsids);

	/* Generate binary representation: policy, partition, slot and vlan */
  	binPolicy = genObj.GenBinaryPolicyBuffer(chwPolicy,stePolicy, binaryPartionSsid, binaryVlanSsid, binarySlotSsid);


	/* Write binary policy into file */
	if (null != outputFileName)
	{
  		genObj.writeBinPolicy(binPolicy, outputFileName);
	} else {
		System.out.println (" No binary policy generated, outputFileName:  " + outputFileName);
	}

	/* Print total number of types */
	System.out.println (" Total number of unique ste types: " + bagOfTypes.size());
	System.out.println (" Total number of Ssids : " + bagOfSsids.size());
	System.out.println (" Total number of unique chw types: " + bagOfChwTypes.size());
	System.out.println (" Total number of conflict ssids : " + bagOfConflictSsids.size());
	System.out.println (" Total number of chw Ssids : " + bagOfChwSsids.size());

   	if (null != xenSsidOutputFileName)
  		genObj.writeXenTypeFile(bagOfSsids, xenSsidOutputFileName, true);

   	if (null != xenSsidConfOutputFileName)
  		genObj.writeXenTypeFile(bagOfChwSsids, xenSsidConfOutputFileName, false);
    } 
    catch (Exception e) 
    {
      e.printStackTrace();
    }
  }
}
