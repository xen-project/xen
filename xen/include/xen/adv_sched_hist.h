/* Some functions to suport advanced scheduler histograms
   Author: Stephan.Diestelhorst@cl.cam.ac.uk */
//#include <xen/sched.h>
//#include <xen/sched-if.h>
#include <asm/msr.h>
#define ADV_SCHED_HISTO
static inline void adv_sched_hist_start(int cpu) {
	u64 now;
	rdtscll(now);
	if (!schedule_data[cpu].save_tsc)
		schedule_data[cpu].save_tsc = now;
}
static inline void adv_sched_hist_from_stop(int cpu) {
	u64 now;
	rdtscll(now);
	if (schedule_data[cpu].save_tsc) {
		now -= schedule_data[cpu].save_tsc;
		now /= 7;
		if (now < BUCKETS-1)
			schedule_data[cpu].from_hist[now]++;
		else
			schedule_data[cpu].from_hist[BUCKETS-1]++;

		schedule_data[cpu].save_tsc = 0;
	}
}
static inline void adv_sched_hist_to_stop(int cpu) {
	u64 now;
	rdtscll(now);
	if (schedule_data[cpu].save_tsc) {
		now -= schedule_data[cpu].save_tsc;
		now /= 24;
		if (now < BUCKETS-1)
			schedule_data[cpu].to_hist[now]++;
		else
			schedule_data[cpu].to_hist[BUCKETS-1]++;

		schedule_data[cpu].save_tsc = 0;
	}
}
