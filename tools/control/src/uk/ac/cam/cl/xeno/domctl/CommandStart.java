package uk.ac.cam.cl.xeno.domctl;

import java.io.*;
import java.net.*;

public class CommandStart extends Command
{
  public int doCommand(Defaults d, String args[])
  {
    int domain_id = getIntParameter(args, 'n', 0);
    String output;

    if (domain_id == 0) {
      System.err.println ("Expected -n<domain_id>");
      return -1;
    }

    output = executeCommand(d, domain_id);
    if (output != null)
    {
      System.err.println(output);
      return -1;
    }

    return 0;
  }


  public String
  executeCommand(Defaults d, int domain_id)
  {
    Runtime r = Runtime.getRuntime ();
    String output = null;

    try
      {
	Process start_p;
	String start_cmdarray[] = new String[2];
	int start_rc;
	start_cmdarray[0] = d.XIToolsDir + "xi_start";
	start_cmdarray[1] = "" + domain_id;

	if (Settings.TEST) {
	  output += reportCommand (start_cmdarray);
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
	return ("Could not start new domain (" + e + ")");
      }

    return output;
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
