/*
 * Library.java
 * 03.03.28 aho creation
 */

package org.xenoserver.control;

/**
 * Library functions.
 */
public class Library {
    /**
     * Convert a number to a fixed width string.
     * @param input The number to convert.
     * @param width The width desired.
     * @param leftAlign True to left-align the number.
     * @return The formatted string.
     */
    public static String format(long input, int width, boolean leftAlign) {
        String sss = Long.toString(input);
        String space = "                                ";

        if (width < sss.length()) {
            width = sss.length();
        }

        if (leftAlign) {
            return sss + space.substring(0, width - sss.length());
        } else {
            return space.substring(0, width - sss.length()) + sss;
        }
    }

    /**
     * Convert a string to a fixed-width string.
     * @param input Input string.
     * @param width Width desired.
     * @param leftAlign True to left-align the string.
     * @return The formatted string.
     */
    public static String format(String input, int width, boolean leftAlign) {
        String space = "                                ";

        if (width < input.length()) {
            width = input.length();
        }

        if (leftAlign) {
            return input + space.substring(0, width - input.length());
        } else {
            return space.substring(0, width - input.length()) + input;
        }
    }

    /**
     * Parse a size which may have a k/m/g suffix into a number.
     * @param size The size string to parse.
     * @return The equivalent number.
     */
    public static long parseSize(String size) {
        String substring = size;
        int suffix = 1;
        long value = 0;

        if (size == null) {
            return 0;
        }

        if ((substring = check(size, 'm')) != null) {
            suffix = 1024 * 1024;
        } else if ((substring = check(size, 'M')) != null) {
            suffix = 1024 * 1024;
        } else if ((substring = check(size, 'k')) != null) {
            suffix = 1024;
        } else if ((substring = check(size, 'K')) != null) {
            suffix = 1024;
        } else if ((substring = check(size, 'g')) != null) {
            suffix = 1024 * 1024 * 1024;
        } else if ((substring = check(size, 'G')) != null) {
            suffix = 1024 * 1024 * 1024;
        } else {
            substring = size;
        }

        try {
            value = Long.decode(substring).longValue() * suffix;
        } catch (NumberFormatException e) {
            value = 0;
        }

        return value;
    }

    /**
     * Check if the given size has the specified suffix.
     * @param size Size string.
     * @param suffix Test suffix.
     * @return Number part of string, or null if suffix does not match.
     */
    private static String check(String size, char suffix) {
        int index = size.indexOf(suffix);

        if (index != -1) {
            return size.substring(0, index);
        } else {
            return null;
        }
    }

    /**
     * Formats a number of bytes in whichever way makes most sense based
     * on magnitude and width.
     * 
     * @param size Number of bytes.
     * @param width Width of field - at least 5, plz.
     * @param leftAlign True for left-align.
     * @return The formatted string.
     */
    public static String formatSize(long size, int width, boolean leftAlign) {
        char[] suffixes = { ' ', 'k', 'M', 'G' };
        int suffix = 0;
        long before = size;
        float after = 0;

        while (before > 10000) {
            after = ((float) (before % 1024)) / 1024;
            before /= 1024;
            suffix++;
        }

        StringBuffer num = new StringBuffer(width);
        num.append(Long.toString(before));
        if (after != 0) {
            int space = width - num.length() - 2;
            if (space > 0) {
                num.append('.');
                if (space > 3) {
                    space = 3;
                }
                num.append(
                    Integer.toString((int) (after * Math.pow(10, space))));
            }
        }
        num.append(suffixes[suffix]);

        return format(num.toString(), width, leftAlign);
    }
}
