package org.xenoserver.control;

/**
 * A Domain object holds the details of one domain suitable for returning
 * from methods enquiring about domain status. As it's only used to pass
 * return values back from DomainList, the fields are left public for
 * convenience.
 */
public class Domain {
    /** Domain ID. */
    public int id;
    /** Processor index. */
    public int processor;
    /** Has the CPU at the moment? */
    public boolean cpu;
    /** State index. */
    public int nstate;
    /** State string. */
    public String state;
    /** State string. */
    public int ev;
    /** MCU advances. */
    public int mcu;
    /** Total pages. */
    public int pages;
    /** Name. */
    public String name;

    /**
     * Domain constructor, with default values.
     */
    Domain() {
        id = 0;
        processor = 0;
        cpu = false;
        nstate = 0;
        state = "";
        mcu = 0;
        pages = 0;
        name = "none";
    }
}
