package uk.ac.cam.cl.xeno.domctl;

import java.io.*;
import java.net.*;

public class CommandStart extends Command
{
  public int doCommand(Defaults d, String args[])
  {
    Runtime r = Runtime.getRuntime ();
    int domain_id = getIntParameter(args, 'n', 0);
    int rc = 0;

    if (domain_id == 0) {
      System.err.println ("Expected -n<domain_id>");
      rc = -1;
      return rc;
    }

    try
      {
	Process start_p;
	String start_cmdarray[] = new String[2];
	int start_rc;
	start_cmdarray[0] = d.XIToolsDir + "xi_start";
	start_cmdarray[1] = "" + domain_id;

	if (Settings.TEST) {
	  reportCommand (start_cmdarray);
	} else {
	  start_p = r.exec (start_cmdarray);
	  start_rc = start_p.waitFor ();
	  if (start_rc != 0) {
	    return reportXIError ("Could not start domain", start_cmdarray);
	  }
	}
      }
    catch (Exception e) 
      {
	System.err.println ("Could not start new domain (" + e + ")");
	e.printStackTrace ();
	rc = -1;
      }

    return rc;
  }

  public String getName()
  {
    return "start";
  }

  public String getUsage()
  {
    return "[-n<domain_id>]";
  }

  public String getHelpText()
  {
    return
      "Start the specified domain.";
  }
}
