package org.xenoserver.cmdline;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.StringTokenizer;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.Reader;
import java.io.InputStreamReader;
import java.io.IOException;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;
import org.xenoserver.control.Extent;
import org.xenoserver.control.Library;
import org.xenoserver.control.Settings;
import org.xenoserver.control.VirtualDisk;
import org.xenoserver.control.VirtualDiskManager;

public class ParseScript extends CommandParser {
  public void parse(Defaults d, LinkedList args) throws ParseFailedException, CommandFailedException {
    String filename = getStringParameter(args,'f',null);

    try
      {
	Reader r;
	BufferedReader br;
	String next_line;
	boolean stdin;

	if (filename == null) {
	  r = new InputStreamReader (System.in);
	  stdin = true;
	} else {
	  r = new FileReader (filename);
	  stdin = false;
	}
	br = new BufferedReader (r);
	
	if (stdin) prompt();
	while ((next_line = br.readLine()) != null) 
	  {
	    StringTokenizer tok = new StringTokenizer(next_line, " ");
	    LinkedList arglist = new LinkedList();
	    while (tok.hasMoreTokens()) {
	      arglist.add (tok.nextToken ());
	    }
	    Main.executeArgList (d, arglist);
	    if (stdin) prompt();
	  }
      }
    catch (IOException ioe)
      {
	throw new ParseFailedException ("Could not read script \"" + filename + "\"", ioe);
      }
  }

  void prompt() {
    System.out.print ("$ ");
    System.out.flush ();
  }

  public String getName() {
    return "script";
  }

  public String getUsage() {
    return "[-f<filename>]";
  }

  public String getHelpText() {
    return ("Execute a series of xenctl command lines found in the specified file\n" +
	    "(or from standard input if no filename is given).  Execution terminates\n" +
	    "if any command fails.  If a command requires a domain ID then, if\n" +
	    "ommitted, the domain most recently created by the script will be used\n" +
	    "by default.\n");
  }
}
