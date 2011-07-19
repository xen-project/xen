/* two abstractions specific to kernel/smpboot.c, mainly to cater to visws
 * which needs to alter them. */

static inline void smpboot_setup_warm_reset_vector(unsigned long start_eip)
{
	unsigned long flags;

	spin_lock_irqsave(&rtc_lock, flags);
	CMOS_WRITE(0xa, 0xf);
	spin_unlock_irqrestore(&rtc_lock, flags);
	flush_tlb_local();
	Dprintk("1.\n");
	*((volatile unsigned short *) TRAMPOLINE_HIGH) = start_eip >> 4;
	Dprintk("2.\n");
	*((volatile unsigned short *) TRAMPOLINE_LOW) = start_eip & 0xf;
	Dprintk("3.\n");
}

static inline void smpboot_restore_warm_reset_vector(void)
{
	unsigned long flags;

	/*
	 * Install writable page 0 entry to set BIOS data area.
	 */
	flush_tlb_local();

	/*
	 * Paranoid:  Set warm reset code and vector here back
	 * to default values.
	 */
	spin_lock_irqsave(&rtc_lock, flags);
	CMOS_WRITE(0, 0xf);
	spin_unlock_irqrestore(&rtc_lock, flags);

	*((volatile int *) maddr_to_virt(0x467)) = 0;
}

static inline void smpboot_setup_io_apic(void)
{
	/*
	 * Here we can be sure that there is an IO-APIC in the system. Let's
	 * go and set it up:
	 */
	if (!skip_ioapic_setup && nr_ioapics)
		setup_IO_APIC();
}
