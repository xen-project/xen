/**
 * (C) Copyright IBM Corp. 2005
 *
 * $Id: myHandler.java,v 1.2 2005/06/17 20:00:04 rvaldez Exp $
 *
 * Author: Ray Valdez
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * myHandler Class.  
 *
 * <p>
 *
 * A dummy class used for detecting XML validating/parsing errors.
 *
 * <p>
 *
 *
 */
import org.xml.sax.helpers.*;
import org.xml.sax.SAXParseException;

class myHandler extends DefaultHandler 
{ 
 public boolean isValid = true;

 /* Notification of a recoverable error. */
 public void error(SAXParseException se) 
 { 
  isValid = false;
 } 

 /* Notification of a non-recoverable error. */
 public void fatalError(SAXParseException se) 
 { 
  isValid = false;
 } 

 /* Notification of a warning. */
 public void warning(SAXParseException se) 
 {
  isValid = false;
 }
}
