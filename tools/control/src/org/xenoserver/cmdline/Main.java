package org.xenoserver.cmdline;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

public class Main {
  private static ParseHelp help = new ParseHelp();
  static CommandParser commands[] =
    { help,
      new ParseNew(),
      new ParseStart(),
      new ParseStop(),
      new ParseDestroy(),
      new ParseList() };

  public static void main(String[] args) {
    Defaults d = new Defaults();
    int ec = -1;

    if (args.length == 0) {
      help.parse(d, args);
    } else {
      String c = args[0];
      int i;
      for (i = 0; i < commands.length; i++) {
        if (commands[i].getName().equals(c)) {
          if (commands[i].getFlagParameter(args, '?')) {
            help.doHelpFor(commands[i]);
          } else {
            try {
              commands[i].parse(d, args);
              ec = 0;
            } catch (ParseFailedException e) {
              System.err.println( e.getMessage() );
            } catch (CommandFailedException e) {
              System.err.println( e.getMessage() );
            }
          }
          break;
        }
      }
      if (i == commands.length) {
        System.out.println("Unknown command " + c);
      }
    }

    System.exit(ec);
  }
}
