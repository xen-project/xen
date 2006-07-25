/* 8.t
- Ditto for the above three tests at the offset maximum (largest
  possible ext2/3 file size.) (8.t)
 */
#include <sys/vfs.h>

#define EXT2_OLD_SUPER_MAGIC	0xEF51
#define EXT2_SUPER_MAGIC	0xEF53

long long get_fs_limit(int fd)
{
	struct statfs s;
	int res;
	long long lim = 0;

	res = fstatfs(fd, &s);		assert(res == 0);

	switch(s.f_type) {
	case EXT2_OLD_SUPER_MAGIC:
	case EXT2_SUPER_MAGIC:
#if 0
	{
		long long tmp;
		tmp = s.f_bsize / 4;
		/* 12 direct + indirect block + dind + tind */
		lim = 12 + tmp + tmp * tmp + tmp * tmp * tmp;
		lim *= s.f_bsize;
		printf("limit(%ld) = %Ld\n", (long)s.f_bsize, lim);
	}
#endif
		switch(s.f_bsize) {
		case 4096: lim = 2199023251456; break;
		default:
			printf("unknown ext2 blocksize %ld\n", (long)s.f_bsize);
			exit(3);
		}
		break;
	default:
		printf("unknown filesystem 0x%08lx\n", (long)s.f_type);
		exit(3);
	}
	return lim;
}

#define SET_RLIMIT(x)	do ; while (0)
#define LIMIT		get_fs_limit(rwfd)
#define FILENAME	"testdir.ext2/rwfile"

#include "common-7-8.h"
