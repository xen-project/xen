package org.xenoserver.control;

/**
 * This utility class expands configuration file patterns.
 */
public class StringPattern {
    /** The base string for this pattern. */
    private String base;
    /** The base number for this pattern. */
    private int bn;
    /** If true, add the domain number to the base number and append. */
    private boolean addDom;
    /** If true, append the domain number to the base string. */
    private boolean appendDom;

    /**
     * Parse a string into a pattern.
     * @param t The pattern string to parse.
     * @return A usable pattern object.
     */
    static StringPattern parse(String t) {
        StringPattern result = new StringPattern();
        char[] ca = t.toCharArray();
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
                    idx--;
                }
                result.base = t.substring(0, idx + 1);
                result.bn = Integer.parseInt(t.substring(idx + 1, len - 1));
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

    /**
     * Resolve the pattern for the given domain number.
     * @param domain The domain number to use.
     * @return The expanded pattern for the given domain.
     */
    String resolve(int domain) {
        if (addDom) {
            return base + (bn + domain);
        } else if (appendDom) {
            return base + domain;
        } else {
            return base;
        }
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return (
            "["
                + base
                + (addDom ? "+" + bn : "")
                + ((addDom || appendDom) ? "+ID" : "")
                + "]");
    }

}
