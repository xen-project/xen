package uk.ac.cam.cl.xeno.domctl;

import java.io.*;
import java.net.*;

public class CommandStop extends Command
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
	Process stop_p;
	String stop_cmdarray[] = new String[2];
	int stop_rc;
	stop_cmdarray[0] = d.XIToolsDir + "xi_stop";
	stop_cmdarray[1] = "" + domain_id;

	if (Settings.TEST) {
	  reportCommand (stop_cmdarray);
	} else {
	  stop_p = r.exec (stop_cmdarray);
	  stop_rc = stop_p.waitFor ();
	  
	  if (stop_rc != 0) {
	    return reportXIError ("Could not stop domain", stop_cmdarray);
	  }
	}
      }
    catch (Exception e) 
      {
	System.err.println ("Could not stop new domain (" + e + ")");
	e.printStackTrace ();
	rc = -1;
      }

    return rc;
  }

  public String getName()
  {
    return "stop";
  }

  public String getUsage()
  {
    return "[-n<domain_id>]";
  }

  public String getHelpText()
  {
    return
      "Stop the specified domain.";
  }
}
