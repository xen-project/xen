package uk.ac.cam.cl.xeno.domctl;

public abstract class Command
{
  public abstract int doCommand(Defaults d, String args[]);
  public abstract String getName();			
  public abstract String getUsage();
  public abstract String getHelpText();

  public String getStringParameter(String args[], char key, String def)
  {
    String r = getParameter (args, key);
    return (r == null) ? def : r;
  }

  public int getIntParameter(String args[], char key, int def)
  {
    String r = getParameter (args, key);
    return (r == null) ? def : (Integer.parseInt (r));
  }

  public boolean getFlagParameter(String args[], char key)
  {
    String r = getParameter (args, key);
    return (r == null) ? false : true;
  }

  public String getParameter (String args[], char key)
  {
    int i;
    String result = null;
    for (i = 0; i < args.length; i ++)
      {
	if (args[i].startsWith("-" + key)) 
	  {
	    if (args[i].length() > 2)
	      {
		result = args[i].substring(2, args[i].length());
	      }
	    else
	      {
		result = "";
	      }
	  }
      }
    return result;
  }

  public String reportXIError (String message, String cmd_array[])
  {
    StringBuffer sb = new StringBuffer();
    int i;
    sb.append (message + " using: ");
    for (i = 0; i < cmd_array.length; i ++) {
      sb.append (cmd_array[i] + " ");
    }
    sb.append (System.getProperty("line.separator"));
    return sb.toString();
  }

  public String reportError (String message)
  {
    return (message);
  }

  public String reportCommand (String cmd_array[])
  {
    StringBuffer sb = new StringBuffer();
    int i;
    for (i = 0; i < cmd_array.length; i ++) {
      sb.append (cmd_array[i] + " ");
    }
    sb.append (System.getProperty("line.separator"));
    return sb.toString();
  }
}
