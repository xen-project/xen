/*
 * RootBean.java
 * 03.05.05 aho creation
 */

package org.xenoserver.web;

import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionBindingListener;

import org.xenoserver.control.PartitionManager;
import org.xenoserver.control.Settings;
import org.xenoserver.control.VirtualDiskManager;
import org.xenoserver.control.XML;

public class RootBean implements HttpSessionBindingListener {
    PartitionManager pm;
    VirtualDiskManager vdm;

    public RootBean() {
        valueBound(null);
    }

    public void valueBound(HttpSessionBindingEvent event) {
        pm = PartitionManager.IT;
        vdm = VirtualDiskManager.IT;
        XML.loadState(pm, vdm, Settings.STATE_INPUT_FILE);
    }

    public void valueUnbound(HttpSessionBindingEvent event) {
        doFlushState();
    }
    
    public PartitionManager pm() {
        return pm;
    }
    
    public VirtualDiskManager vdm() {
        return vdm;
    }

    public void doFlushState() {
        XML.saveState(pm, vdm, Settings.STATE_OUTPUT_FILE);
    }
}
