package uk.ac.cam.cl.xeno.domctl;

public class CommandHelp extends Command
{
  public int doCommand(Defaults d, String args[])
  {
    if (args.length <= 1)
      {
	System.out.println ("Usage:");
	for (int i = 0; i < Main.commands.length; i ++) 
	  {
	    String name = Main.commands[i].getName ();
	    String usage = Main.commands[i].getUsage ();
	    while (name.length() < 12) name = name + " ";
	    System.out.println ("   " + name + usage);
	  }
      }
    else 
      {
	for (int i = 0; i < Main.commands.length; i ++) 
	  {
	    String name = Main.commands[i].getName ();
	    String usage = Main.commands[i].getUsage ();
	    if (name.equals (args[1]))
	      {
		doHelpFor (Main.commands[i]);
		break;
	      }
	  }
      }

    System.out.println ("");
    return 0;
  }

  public int doHelpFor (Command c)
  {
    System.out.println ("domctl " + c.getName() + " " + c.getUsage());
    System.out.println ();
    System.out.println (c.getHelpText ());
    return 0;
  }

  public String getName()
  {
    return "help";
  }

  public String getUsage()
  {
    return "";
  }

  public String getHelpText()
  {
    return "This message";
  }  
}
