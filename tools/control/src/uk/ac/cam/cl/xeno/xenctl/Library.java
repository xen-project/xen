/*
 * Library.java
 * 03.03.28 aho creation
 */

package uk.ac.cam.cl.xeno.xenctl;

public class
Library
{
  /*
   * convert a number to a fixed width string
   */
  static String
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
  static String
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
  static long
  parse_size(String size)
  {
    String substring = size;
    int    suffix = 1;

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

    return Long.decode(substring).longValue() * suffix;
  }

  static String
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
}
