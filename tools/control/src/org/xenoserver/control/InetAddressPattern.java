package org.xenoserver.control;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * This utility class expands configuration file patterns.
 */
public class InetAddressPattern {
    /** The base InetAddress for this pattern. */
    private InetAddress base;
    /** If true, add the domain number to the base address. */
    private boolean addDom;

    /**
     * Parse a pattern string into an InetAddressPattern.
     * @param t The pattern string.
     * @return The parsed pattern object.
     */
    static InetAddressPattern parse(String t) {
        InetAddressPattern result = new InetAddressPattern();
        char[] ca = t.toCharArray();
        int len = ca.length;

        try {
            if (len == 0) {
                result.base = null;
                result.addDom = false;
            } else if (ca[len - 1] == '+') {
                result.base = InetAddress.getByName(t.substring(0, len - 1));
                result.addDom = true;
            } else {
                result.base = InetAddress.getByName(t);
                result.addDom = false;
            }
        } catch (UnknownHostException uhe) {
            result.base = null;
            result.addDom = false;
        }

        return result;
    }

    /**
     * Resolve the pattern for the given domain.
     * @param domain_id The domain ID.
     * @return The resolved string.
     */
    String resolve(int domain_id) {
        byte[] b = base.getAddress();
        if (addDom) {
            if (((int) b[3]) + domain_id > 255) {
                if (((int) b[2]) + domain_id > 255) {
                    if (((int) b[1]) + domain_id > 255) {
                        b[0]++;
                    }
                    b[1]++;
                }
                b[2]++;
            }
            b[3] += domain_id;
        }
        return ""
            + (b[0] + (b[0] < 0 ? 256 : 0))
            + "."
            + (b[1] + (b[1] < 0 ? 256 : 0))
            + "."
            + (b[2] + (b[2] < 0 ? 256 : 0))
            + "."
            + (b[3] + (b[3] < 0 ? 256 : 0));
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return "[" + base + (addDom ? "+dom_id" : "") + "]";
    }
}
