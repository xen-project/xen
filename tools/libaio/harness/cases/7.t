/* 7.t
- Write overlapping the file size rlimit boundary: should be a short
  write. (7.t)
- Write at the file size rlimit boundary: should give EFBIG.  (I think
  the spec requires that you do NOT deliver SIGXFSZ in this case, where
  you would do so for sync IO.) (7.t)
- Special case: a write of zero bytes at or beyond the file size rlimit
  boundary must return success. (7.t)
*/

#include <sys/resource.h>

void SET_RLIMIT(long long limit)
{
	struct rlimit rlim;
	int res;

	rlim.rlim_cur = limit;			assert(rlim.rlim_cur == limit);
	rlim.rlim_max = limit;			assert(rlim.rlim_max == limit);

	res = setrlimit(RLIMIT_FSIZE, &rlim);	assert(res == 0);
}

#define LIMIT	8192
#define FILENAME	"testdir/rwfile"

#include "common-7-8.h"
