/*
 * SystemConfigurationBean.java
 * 03.05.06 aho creation
 */

package org.xenoserver.web;

import org.xenoserver.control.Defaults;

public class SystemConfigurationBean {
    private Defaults defaults;

    public SystemConfigurationBean() {
        defaults = new Defaults();
    }

    public Defaults getDefaults() {
        return defaults;
    }
}
