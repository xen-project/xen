package org.xenoserver.cmdline;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.xenoserver.control.CommandFailedException;
import org.xenoserver.control.Defaults;

public class Main {
  static final ParseHelp help = new ParseHelp();
  static final CommandParser domaincommands[] =
    { new ParseDomainNew(),
      new ParseDomainStart(),
      new ParseDomainStop(),
      new ParseDomainDestroy(),
      new ParseDomainList()
    };
  static final CommandParser commands[] =
    { help,
      new ParseGroup( "domain", domaincommands )
    };
  static final CommandParser parser = new ParseGroup( null, commands );

  public static void main(String[] args) {
    Defaults d = new Defaults();
    int ec = -1;
    LinkedList arglist = new LinkedList();
    for ( int i=0; i<args.length; i++ )
      arglist.add( args[i] );

    if (args.length == 0) {
      help.parse(d, arglist);
    } else {
      try
      {
        parser.parse(d, arglist);
        ec = 0;
      } catch (ParseFailedException e) {
        System.err.println( e.getMessage() );
      } catch (CommandFailedException e) {
        System.err.println( e.getMessage() );
      }
    }

    System.exit(ec);
  }
}
