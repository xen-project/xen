/*
 * Library.java
 * 03.03.28 aho creation
 */

package org.xenoserver.control;

public class
Library
{
  /*
   * convert a number to a fixed width string
   */
  public static String
  format (long input, int width, int prefix)
  {
    String sss = Long.toString(input);
    String space = "                                ";

    if (width < sss.length())
    {
      width = sss.length();
    }

    if (prefix == 0)
    {
      return space.substring(0, width - sss.length()) + sss;
    }
    else
    {
      return sss + space.substring(0, width - sss.length());
    }
  }

  /*
   * convert a string to a fixed width string
   */
  public static String
  format (String input, int width, int prefix)
  {
    String space = "                                ";

    if (width < input.length())
    {
      width = input.length();
    }

    if (prefix == 0)
    {
      return space.substring(0, width - input.length()) + input;
    }
    else
    {
      return input + space.substring(0, width - input.length());
    }
  }

  /*
   * convert a number (string format) into 
   * the corresponding integer value.
   */
  public static long
  parse_size(String size)
  {
    String substring = size;
    int    suffix = 1;
    long   value = 0;

    if (size == null)
    {
      return 0;
    }

    if ((substring = check(size, 'm')) != null)
    {
      suffix = 1024 * 1024;
    }
    else if ((substring = check(size, 'M')) != null)
    {
      suffix = 1024 * 1024;
    }
    else if ((substring = check(size, 'k')) != null)
    {
      suffix = 1024;
    }
    else if ((substring = check(size, 'K')) != null)
    {
      suffix = 1024;
    }
    else if ((substring = check(size, 'g')) != null)
    {
      suffix = 1024 * 1024 * 1024;
    }
    else if ((substring = check(size, 'G')) != null)
    {
      suffix = 1024 * 1024 * 1024;
    }
    else
    {
      substring = size;
    }

    try
    {
      value = Long.decode(substring).longValue() * suffix;
    }
    catch (NumberFormatException e)
    {
      value = 0;
    }

    return value;
  }

  public static String
  check(String size, char suffix)
  {
    int index = size.indexOf(suffix);

    if (index != -1)
    {
      return size.substring(0, index);
    }
    else
    {
      return null;
    }
  }
  
  /**
   * Formats a number of bytes in whichever way makes most sense based
   * on magnitude and width.
   * 
   * @param size Number of bytes.
   * @param width Width of field - at least 5, plz.
   * @param prefix Set to 1 for left justify
   * @return The formatted string.
   */
  public static String format_size(long size,int width,int prefix) {
    char[] suffixes = { ' ', 'k', 'M', 'G' };
    int suffix = 0;
    long before = size;
    float after = 0;
    
    while ( before > 10000 ) {
      after = ((float)(before % 1024)) / 1024;
      before /= 1024;
      suffix++; 
    }
    
    StringBuffer num = new StringBuffer(width);
    num.append( Long.toString( before ) );
    if ( after != 0 ) {
      int space = width - num.length() - 2;
      if ( space > 0 ) {
        num.append( '.' );
        if ( space > 3 )
          space = 3;
        num.append( Integer.toString( (int) (after * Math.pow(10,space))));
      }
    }
    num.append( suffixes[suffix] );
    
    return format(num.toString(),width,prefix);
  }
}
