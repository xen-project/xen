package uk.ac.cam.cl.xeno.domctl;

public class StringPattern
{
  String base;
  int bn;
  boolean addDom;
  boolean appendDom;

  static StringPattern parse (String t)
  {
    StringPattern result = new StringPattern ();
    char[] ca = t.toCharArray ();
    int idx = 0;
    int len = ca.length;

    if (len == 0) {
      result.base = "";
      result.bn = 0;
      result.addDom = false;
    } else if (ca[len - 1] == '+') {
      idx = len - 2;
      if ((idx >= 0) && (ca[idx] >= '0') && (ca[idx] <= '9')) {
	while ((idx >= 0) && (ca[idx] >= '0') && (ca[idx] <= '9')) {
	  idx --;
	}
	result.base = t.substring(0, idx + 1);
	result.bn = Integer.parseInt (t.substring (idx + 1, len - 1));
	result.addDom = true;
      } else {
	result.base = t.substring(0, len - 1);
	result.appendDom = true;
      }
    } else {
      result.base = t;
    }

    return result;
  }

  public String resolve (int domain_id) {
    if (addDom) {
      return base + (bn + domain_id);
    } else if (appendDom) {
      return base + domain_id;
    } else {
      return base;
    }
  }

  public String toString () {
    return ("[" + 
	    base + 
	    (addDom ? "+" + bn : "") + 
	    ((addDom || appendDom) ? "+ID" : "") + 
	    "]");
  }

}
