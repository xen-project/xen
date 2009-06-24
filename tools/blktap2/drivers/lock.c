/*
 * Copyright (c) 2007, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This module implements a "dot locking" style advisory file locking algorithm.
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include "lock.h"

#define unlikely(x) __builtin_expect(!!(x), 0)

/* format: xenlk.hostname.uuid.<xf><rw>*/
#define LF_POSTFIX ".xenlk"
#define LFXL_FORMAT LF_POSTFIX ".%s.%s.x%s"
#define LFFL_FORMAT LF_POSTFIX ".%s.%s.f%s"
#define RETRY_MAX 16

#if defined(LOGS)
#define LOG(format, args...) printf("%d: ", __LINE__); printf(format, ## args)
#else
#define LOG(format, args...)
#endif

/* random wait - up to .5 seconds */
#define XSLEEP usleep(random() & 0x7ffff)

typedef int (*eval_func)(char *name, int readonly);

static char *create_lockfn(char *fn_to_lock)
{
        char *lockfn;
    
        /* allocate string to hold constructed lock file */
        lockfn = malloc(strlen(fn_to_lock) + strlen(LF_POSTFIX) + 1);
        if (unlikely(!lockfn)) {
                return 0;
        }

        /* append postfix to file to lock */
        strcpy(lockfn, fn_to_lock);
        strcat(lockfn, LF_POSTFIX);

        return lockfn;
}

static char *create_lockfn_link(char *fn_to_lock, char *format, 
                                char *uuid, int readonly)
{
        char hostname[128];
        char *lockfn_link;
        char *ptr;

        /* get hostname */
        if (unlikely(gethostname(hostname, sizeof(hostname)) == -1)) {
                return 0;
        }

        /* allocate string to hold constructed lock file link */
        lockfn_link = malloc(strlen(fn_to_lock) + strlen(LF_POSTFIX) +
                             strlen(hostname) + strlen(uuid) + 8);
        if (unlikely(!lockfn_link)) {
                return 0;
        }

        /* construct lock file link with specific format */
        strcpy(lockfn_link, fn_to_lock);
        ptr = lockfn_link + strlen(lockfn_link);
        sprintf(ptr, format, hostname, uuid, readonly ? "r" : "w");

        return lockfn_link;
}

static int NFSnormalizedStatTime(char *fn, struct stat *statnow, int *reterrno)
{
        int result = LOCK_OK;
        int uniq;
        char *buf;
        int fd;
        int pid = (int)getpid();
        int clstat;

        *reterrno = 0;

        /* create file to normalize time */
        srandom((int)time(0) ^ pid);
        uniq = random() % 0xffffff;
        buf = malloc(strlen(fn) + 24);
        if (unlikely(!buf)) { result = LOCK_ENOMEM; goto finish; }

        strcpy(buf, fn);
        sprintf(buf + strlen(buf), ".xen%08d.tmp", uniq);

        fd = open(buf, O_WRONLY | O_CREAT, 0644);
        if (fd == -1) { *reterrno = errno; result = LOCK_EOPEN; goto finish; }
        clstat = close(fd);
        if (unlikely(clstat == -1)) {
                LOG("fail on close\n");
        }
        if (lstat(buf, statnow) == -1) {
                unlink(buf);
                *reterrno = errno;
                result = LOCK_ESTAT;
                goto finish;
        }
        unlink(buf);

finish:
        return result;
}

static int writer_eval(char *name, int readonly) 
{
        return name[strlen(name)-1] == 'w';
}

static int reader_eval(char *name, int readonly) 
{
        return name[strlen(name)-1] == 'r' && !readonly;
}

static int lock_holder(char *fn, char *lockfn, char *lockfn_link, 
                       int force, int readonly, int *stole, eval_func eval,
                       int *elt, int *ioerror)
{
        int status = 0;
        int ustat;
        DIR *pd = 0;
        struct dirent *dptr;
        char *ptr;
        char *dirname = malloc(strlen(lockfn));
        char *uname = malloc(strlen(lockfn_link) + 8);
        int elt_established = 0;
        int fd;
        char tmpbuf[4096];

        *stole = 0;
        *ioerror = 0;
        *elt = 0;

        if (!dirname) goto finish;
        if (!uname) goto finish;

        /* get directory */
        ptr = strrchr(lockfn, '/');
        if (!ptr) {
                strcpy(dirname, ".");
        } else {
                int numbytes = ptr - lockfn;
                strncpy(dirname, lockfn, numbytes);
                dirname[numbytes] = '\0';
        }
        pd = opendir(dirname); 
        if (!pd) {
                *ioerror = errno ? errno : EIO;
                goto finish;
        }

        /* 
         * scan through directory entries and use eval function 
         * if we have a match (i.e. reader or writer lock) but
         * note that if we are forcing, we will remove any and
         * all locks that appear for target of our lock, regardless
         * if it a reader/writer owns the lock.
         */
        errno = 0;
        dptr = readdir(pd);
        if (!dptr) {
            *ioerror = EIO;
        }
        while (dptr) {
                char *p1 = strrchr(fn, '/');
                char *p2 = strrchr(lockfn, '/');
                char *p3 = strrchr(lockfn_link, '/');
                if (p1) p1+=1;
                if (p2) p2+=1;
                if (p3) p3+=1;
                if (strcmp(dptr->d_name, p1 ? p1 : fn) &&
                    strcmp(dptr->d_name, p2 ? p2 : lockfn) &&
                    strcmp(dptr->d_name, p3 ? p3 : lockfn_link) &&
                    !strncmp(dptr->d_name, p1 ? p1 : fn, strlen(p1?p1:fn))) {
                        strcpy(uname, dirname);
                        strcat(uname, "/");
                        strcat(uname, dptr->d_name);
                        if (!elt_established) {
                            /* read final lock file and extract lease time */
                            fd = open(uname, O_RDONLY, 0644); 
                            memset(tmpbuf, 0, sizeof(tmpbuf));
                            if (read(fd, tmpbuf, sizeof(tmpbuf)) < 0) {
                                    *ioerror = errno;
                                    status = 1;
                                    close(fd);
                                    goto finish;
                            }
                            close(fd);
                            ptr = strrchr(tmpbuf, '.');
                            if (ptr) {
                                *elt = atoi(ptr+1);
                                elt_established = 1;
                            }
                        }
                        if (force) {
                                ustat = unlink(uname);
                                if (ustat == -1) {
                                        LOG("failed to unlink %s\n", uname);
                                }
                                *stole = 1;
                                *elt = 0;
                        } else {
                                if ((*eval)(dptr->d_name, readonly)) {
                                        closedir(pd);
                                        status = 1;
                                        goto finish;
                                }
                        }
                }
                dptr = readdir(pd);
                if (!dptr && errno) {
                    *ioerror = EIO;
                }
        }

        closedir(pd);

finish:
        free(dirname);
        free(uname);

        /* if IO error, force a taken status */
        return (*ioerror) ? 1 : status;
}

int lock(char *fn_to_lock, char *uuid, int force, int readonly, int *lease_time, int *retstatus)
{
        char *lockfn = 0;
        char *lockfn_xlink = 0;
        char *lockfn_flink = 0;
        char *buf = 0;
        int fd;
        int status = 0;
        struct stat stat1, stat2;
        int retry_attempts = 0;
        int clstat;
        int tmpstat;
        int stealx = 0;
        int stealw = 0;
        int stealr = 0;
        int established_lease_time = 0;
        char tmpbuf[4096];
        int ioerr;
    
        if (!fn_to_lock || !uuid) {
                *retstatus = LOCK_EBADPARM;
                return EINVAL;
        }

        *retstatus = 0;

        /* seed random with time/pid combo */
        srandom((int)time(0) ^ getpid());

        /* build lock file strings */
        lockfn = create_lockfn(fn_to_lock);
        if (unlikely(!lockfn)) { status = ENOMEM; *retstatus = LOCK_ENOMEM; goto finish; }

        lockfn_xlink = create_lockfn_link(fn_to_lock, LFXL_FORMAT, 
                                          uuid, readonly);
        if (unlikely(!lockfn_xlink)) { status = ENOMEM; *retstatus = LOCK_ENOMEM; goto finish; }

        lockfn_flink = create_lockfn_link(fn_to_lock, LFFL_FORMAT, uuid, 
                                          readonly);
        if (unlikely(!lockfn_flink)) { status = ENOMEM; *retstatus = LOCK_ENOMEM; goto finish; }

try_again:
        if (retry_attempts++ > RETRY_MAX) {
                if (*retstatus == LOCK_EXLOCK_OPEN) {
                        struct stat statnow, stat_exlock;
                        int diff;

                        if (lstat(lockfn, &stat_exlock) == -1) {
                                goto finish;
                        }
                
                        if (NFSnormalizedStatTime(fn_to_lock, &statnow, &ioerr)) {
                                goto finish;
                        }

                        diff = (int)statnow.st_mtime - (int)stat_exlock.st_mtime;
                        if (diff > DEFAULT_LEASE_TIME_SECS) {
                                unlink(lockfn);
                                retry_attempts = 0;
                                goto try_again;
                        }
                }
                goto finish;
        }

        /* try to open exlusive lockfile */
        fd = open(lockfn, O_WRONLY | O_CREAT | O_EXCL, 0644); 
        if (fd == -1) {
                LOG("Initial lockfile creation failed %s force=%d, errno=%d\n",
                     lockfn, force, errno);
                if (errno == EIO) {
                       *retstatus = LOCK_EXLOCK_OPEN;
                       status = EIO;
                       goto finish;
                }
                /* already owned? (hostname & uuid match, skip time bits) */
                errno = 0;
                fd = open(lockfn, O_RDWR, 0644);
                if (fd != -1) {
                        buf = malloc(strlen(lockfn_xlink)+1);
                        if (!buf) {
                                clstat = close(fd);
                                if (unlikely(clstat == -1)) {
                                        LOG("fail on close\n");
                                }
                                *retstatus = LOCK_ENOMEM;
                                status = ENOMEM;
                                goto finish;
                        }
                        if (read(fd, buf, strlen(lockfn_xlink)) !=
                           (strlen(lockfn_xlink))) {
                                clstat = close(fd);
                                if (unlikely(clstat == -1)) {
                                        LOG("fail on close\n");
                                }
                                free(buf);
                                goto force_lock;
                        }
                        if (!strncmp(buf, lockfn_xlink, strlen(lockfn_xlink)-1)) {
                                LOG("lock owned by us, reasserting\n");
                                /* our lock, reassert by rewriting below */
                                if (lseek(fd, 0, SEEK_SET) == -1) {
                                        clstat = close(fd);
                                        if (unlikely(clstat == -1)) {
                                                LOG("fail on close\n");
                                        }
                                        goto force_lock;
                                }
                                free(buf);
                                goto skip;
                        }
                        free(buf);
                        clstat = close(fd);
                        if (unlikely(clstat == -1)) {
                                LOG("fail on close\n");
                        }
                }
force_lock:
                if (errno == EIO) {
                       *retstatus = LOCK_EXLOCK_OPEN;
                       status = EIO;
                       goto finish;
                }
                if (force) {
                        /* remove lock file, we are forcing lock, try again */
                        status = unlink(lockfn);
                        if (unlikely(status == -1)) {
                                if (errno == EIO) {
                                       *retstatus = LOCK_EXLOCK_OPEN;
                                       status = EIO;
                                       goto finish;
                                }
                                LOG("force removal of %s lockfile failed, "
                                    "errno=%d, trying again\n", lockfn, errno);
                        }
                        stealx = 1;
                }
                XSLEEP;
                *retstatus = LOCK_EXLOCK_OPEN;
                goto try_again;
        }

        LOG("lockfile created %s\n", lockfn);

skip:
        /* 
         * write into the temporary xlock
         */
        if (write(fd, lockfn_xlink, strlen(lockfn_xlink)) != 
                strlen(lockfn_xlink)) {
                if (errno == EIO) {
                       *retstatus = LOCK_EXLOCK_WRITE;
                       status = EIO;
                       goto finish;
                }
                status = errno;
                clstat = close(fd);
                if (unlikely(clstat == -1)) {
                        LOG("fail on close\n");
                }
                XSLEEP;
                *retstatus = LOCK_EXLOCK_WRITE;
                if (unlink(lockfn) == -1)  {
                        LOG("removal of %s lockfile failed, "
                            "errno=%d, trying again\n", lockfn, errno);
                }
                goto try_again;
        }
        clstat = close(fd);
        if (unlikely(clstat == -1)) {
                LOG("fail on close\n");
        }

        while (retry_attempts++ < RETRY_MAX) {
                tmpstat = link(lockfn, lockfn_xlink);
                LOG("linking %s and %s\n", lockfn, lockfn_xlink);
                if ((tmpstat == -1) && (errno != EEXIST)) { 
                        LOG("link status is %d, errno=%d\n", tmpstat, errno); 
                }

                if ((lstat(lockfn, &stat1) == -1) || 
                    (lstat(lockfn_xlink, &stat2) == -1)) {
                        /* try again, cleanup first */
                        tmpstat = unlink(lockfn);
                        if (unlikely(tmpstat == -1)) {
                                LOG("error removing lock file %s", lockfn);
                        }
                        tmpstat = unlink(lockfn_xlink);
                        if (unlikely(tmpstat == -1)) {
                                LOG("error removing linked lock file %s", 
                                    lockfn_xlink);
                        }
                        XSLEEP;
                        status = LOCK_ESTAT;
                        goto finish;
                }

                /* compare inodes */
                if (stat1.st_ino == stat2.st_ino) {
                        /* success, inodes are the same */
                        /* should we check that st_nlink's are also 2?? */
                        *retstatus = LOCK_OK;
                        status = 0;
                        tmpstat = unlink(lockfn_xlink);
                        if (unlikely(tmpstat == -1)) {
                                LOG("error removing linked lock file %s", 
                                    lockfn_xlink);
                        }
                        goto finish;
                } else {
                       status = errno;
                        /* try again, cleanup first */
                        tmpstat = unlink(lockfn);
                        if (unlikely(tmpstat == -1)) {
                                LOG("error removing lock file %s", lockfn);
                        }
                        tmpstat = unlink(lockfn_xlink);
                        if (unlikely(tmpstat == -1)) {
                                LOG("error removing linked lock file %s", 
                                    lockfn_xlink);
                        }
                        XSLEEP;
                        *retstatus = LOCK_EINODE;
                        goto try_again;
                }
        }

finish:
        if (!*retstatus) {

                /* we have exclusive lock */

                status = 0;

                /* fast check, see if we own a final lock and are reasserting */
                if (!lstat(lockfn_flink, &stat1)) {
                        char *ptr;

                        /* set the return value to notice this is a reassert */
                        *retstatus = 1; 

                        /* read existing lock file and extract 
                           established lease time */
                        fd = open(lockfn_flink, O_RDONLY, 0644); 
                        memset(tmpbuf, 0, sizeof(tmpbuf));
                        if (read(fd, tmpbuf, sizeof(tmpbuf)) < 0) {
                                if (errno == EIO) {
                                        close(fd);
                                        *retstatus = LOCK_EINODE;
                                        status = EIO;
                                        goto skip_scan;
                                }
                        }
                        close(fd);
                        ptr = strrchr(tmpbuf, '.');
                        if (ptr) {
                            *lease_time = atoi(ptr+1);
                        } else {
                            *lease_time = 10; /* wkchack */
                        }
                        goto skip_scan;
                } else {
                       if (errno == EIO) {
                               *retstatus = LOCK_EINODE;
                               status = EIO;
                               goto skip_scan;
                       }
                }

                /* we allow exclusive writer, or multiple readers */
                if (lock_holder(fn_to_lock, lockfn, lockfn_flink, force,
                                     readonly, &stealw, writer_eval, 
                                     &established_lease_time, &ioerr)) {
                        if (ioerr) {
                            *retstatus = LOCK_EREAD;
                            status = ioerr;
                            goto skip_scan;
                        }
                        *retstatus = LOCK_EHELD_WR;
                } else if (lock_holder(fn_to_lock, lockfn, lockfn_flink, force,
                                     readonly, &stealr, reader_eval, 
                                     &established_lease_time, &ioerr)) {
                        if (ioerr) {
                            *retstatus = LOCK_EREAD;
                            status = ioerr;
                            goto skip_scan;
                        }
                        *retstatus = LOCK_EHELD_RD;
                }
                if (established_lease_time) *lease_time = 
                                                 established_lease_time;
        }

skip_scan:
        if (*retstatus >= 0) {
                /* update file, changes last modify time */
                fd = open(lockfn_flink, O_WRONLY | O_CREAT, 0644); 
                if (fd == -1) {
                        *retstatus = LOCK_EOPEN;
                        status = errno;
                } else {
                        char tmpbuf[32];
                        int failed_write;
                        memset(tmpbuf, 0, sizeof(tmpbuf));
                        sprintf(tmpbuf, ".%d", *lease_time);
                        failed_write = write(fd, lockfn_flink, 
                                             strlen(lockfn_flink)) != 
                                       strlen(lockfn_flink);
                        if (failed_write) status = errno;
                        failed_write |= write(fd, tmpbuf, strlen(tmpbuf)) != 
                                       strlen(tmpbuf);
                        if (failed_write) status = errno;
                        if (failed_write) {
                                clstat = close(fd);
                                if (unlikely(clstat == -1)) {
                                        LOG("fail on close\n");
                                }
                                XSLEEP;
                                *retstatus = LOCK_EUPDATE;
                                goto try_again;
                        }
                }
                clstat = close(fd);
                if (unlikely(clstat == -1)) {
                        LOG("fail on close\n");
                }
        }

        if (!*retstatus && force && (stealx || stealw || stealr)) {
                struct timeval timeout;

                /* enforce quiet time on steal */
                timeout.tv_sec = *lease_time;
                timeout.tv_usec = 0;
                select(0, 0, 0, 0, &timeout);
        }

        /* remove exclusive lock, final read/write locks will hold */
        tmpstat = unlink(lockfn);
        if (unlikely(tmpstat == -1)) {
                LOG("error removing exclusive lock file %s", 
                    lockfn);
        }

        free(lockfn);
        free(lockfn_xlink);
        free(lockfn_flink);

        /* set lease time to -1 if error, so no one is apt to use it */
        if (*retstatus < 0) *lease_time = -1;

        LOG("returning status %d, errno=%d\n", status, errno);
        return status;
}


int unlock(char *fn_to_unlock, char *uuid, int readonly, int *status)
{
        char *lockfn_link = 0;
        int reterrno = 0;

        if (!fn_to_unlock || !uuid) {
                *status = LOCK_EBADPARM;
                return 0;
        }

        lockfn_link = create_lockfn_link(fn_to_unlock, LFFL_FORMAT, uuid, 
                                         readonly);
        if (unlikely(!lockfn_link)) { *status = LOCK_ENOMEM; goto finish; }

        if (unlink(lockfn_link) == -1) {
                LOG("error removing linked lock file %s", lockfn_link);
                reterrno = errno;
                *status = LOCK_ENOLOCK;
                goto finish;
        }

        *status = LOCK_OK;

finish:
        free(lockfn_link);
        return reterrno;
}

int lock_delta(char *fn, int *ret_lease, int *max_lease)
{
        int reterrno = 0;
        DIR *pd = 0;
        struct dirent *dptr;
        char *ptr;
        int result = INT_MAX;
        struct stat statbuf, statnow;
        char *dirname = malloc(strlen(fn));
        char *uname = malloc(strlen(fn) + 8);
        int elt_established = 0;
        char *dotptr;
        char tmpbuf[4096];
        int fd;

        if (!fn || !dirname || !uname) {
                *ret_lease = LOCK_EBADPARM;
                *max_lease = -1;
                return 0;
        }
        
        if (NFSnormalizedStatTime(fn, &statnow, &reterrno)) {
                result = LOCK_ESTAT;
                goto finish;
        }

        /* get directory */
        ptr = strrchr(fn, '/');
        if (!ptr) {
                strcpy(dirname, ".");
                ptr = fn;
        } else {
                int numbytes = ptr - fn;
                strncpy(dirname, fn, numbytes);
                ptr += 1;
        }
        pd = opendir(dirname); 
        if (!pd) { reterrno = errno; goto finish; }

        dptr = readdir(pd);
        while (dptr) {
                if (strcmp(dptr->d_name, ptr) &&
                    !strncmp(dptr->d_name, ptr,  strlen(ptr))) {
                        char *fpath = malloc(strlen(dptr->d_name) + 
                                             strlen(dirname) + 2);
                        if (!fpath) {
                            closedir(pd);
                            result = LOCK_ENOMEM;
                            goto finish;
                        }
                        strcpy(fpath, dirname);
                        strcat(fpath, "/");
                        strcat(fpath, dptr->d_name);
                        if (lstat(fpath, &statbuf) != -1) {
                                int diff = (int)statnow.st_mtime - 
                                           (int)statbuf.st_mtime;
                                /* adjust diff if someone updated the lock
                                   between now and when we created the "now"
                                   file 
                                 */
                                diff = (diff < 0) ? 0 : diff;
                                result = diff < result ? diff : result;
                        } else {
                            closedir(pd);
                            reterrno = errno;
                            goto finish;
                        }

                        if (!elt_established) {
                            /* read final lock file and extract lease time */
                            fd = open(fpath, O_RDONLY, 0644); 
                            memset(tmpbuf, 0, sizeof(tmpbuf));
                            if (read(fd, tmpbuf, sizeof(tmpbuf)) < 0) {
                                /* error on read? */
                            }
                            close(fd);
                            dotptr = strrchr(tmpbuf, '.');
                            if (dotptr) {
                                *max_lease = atoi(dotptr+1);
                                elt_established = 1;
                            }
                        }

                        free(fpath);
                }
                dptr = readdir(pd);
        }

        closedir(pd);

finish:
        free(dirname);
        free(uname);

        /* returns smallest lock time, or error */
        if (result == INT_MAX) result = LOCK_ENOLOCK;

        /* set lease time to -1 if error, so no one is apt to use it */
        if ((result < 0) || reterrno) *max_lease = -1;
        *ret_lease = result;
        return reterrno;
}

#if defined(TEST)
/*
 * the following is for sanity testing.
 */

static void usage(char *prg)
{
        printf("usage %s\n"
               "    dtr <filename>]\n"
               "    p <filename> [num iterations]\n"
               "    u <filename> [0|1] [<uniqid>]\n"
               "    l <filename> [0|1] [0|1] [<uniqid>] [<leasetime>]\n", prg);
        printf("        p : perf test lock take and reassert\n");
        printf("        d : delta lock time\n");
        printf("        t : test the file (after random locks)\n");
        printf("        r : random lock tests (must ^C)\n");
        printf("        u : unlock, readonly? uniqID (default is PID)\n");
        printf("        l : lock, readonly? force?, uniqID (default is PID), lease time\n");
}

static void test_file(char *fn)
{
        FILE *fptr;
        int prev_count = 0;
        int count, pid, time;

        fptr = fopen(fn, "r");
        if (!fptr) {
                LOG("ERROR on file %s open, errno=%d\n", fn, errno);
                return;
        } 

        while (!feof(fptr)) {
                fscanf(fptr, "%d %d %d\n", &count, &pid, &time);
                if (prev_count != count) {
                        LOG("ERROR: prev_count=%d, count=%d, pid=%d, time=%d\n",
                                    prev_count, count, pid, time);
                }
                prev_count = count + 1;
        }
}

static void random_locks(char *fn)
{
        int pid = getpid();
        int status;
        char *filebuf = malloc(256);
        int count = 0;
        int dummy;
        int clstat;
        char uuid[12];
        int readonly;
        int lease = DEFAULT_LEASE_TIME_SECS;
        int err;

        /* this will never return, kill to exit */

        srandom((int)time(0) ^ pid);

        LOG("pid: %d using file %s\n", pid, fn);
        sprintf(uuid, "%08d", pid);

        while (1) {
                XSLEEP;
                readonly = random()  & 1;
                sysstatus = lock(fn, uuid, 0, readonly, &lease, status);
                if (status == LOCK_OK) {
                        /* got lock, open, read, modify write close file */
                        int fd = open(fn, O_RDWR, 0644);
                        if (fd == -1) {
                                LOG("pid: %d ERROR on file %s open, errno=%d\n", 
                                    pid, fn, errno);
                        } else {
                            if (!readonly) {
                                /* ugly code to read data in test format */
                                /* format is "%d %d %d" 'count pid time' */
                                struct stat statbuf;
                                int bytes;
                                status = stat(fn, &statbuf);
                                if (status != -1) {
                                        if (statbuf.st_size > 256) {
                                                lseek(fd, -256, SEEK_END);
                                        } 
                                        memset(filebuf, 0, 256);
                                        bytes = read(fd, filebuf, 256);
                                        if (bytes) {
                                                int bw = bytes-2;
                                                while (bw && filebuf[bw]!='\n') 
                                                        bw--;
                                                if (!bw) bw = -1;
                                                sscanf(&filebuf[bw+1], 
                                                       "%d %d %d", 
                                                       &count, &dummy, &dummy);
                                                count += 1;
                                        }
                                        lseek(fd, 0, SEEK_END);
                                        sprintf(filebuf, "%d %d %d\n", 
                                                count, pid, (int)time(0));
                                        write(fd, filebuf, strlen(filebuf));
                                } else {
                                        LOG("pid: %d ERROR on file %s stat, "
                                            "errno=%d\n", pid, fn, errno);
                                }
                            }
                            clstat = close(fd);
                            if (unlikely(clstat == -1)) {
                                    LOG("fail on close\n");
                            }
                        }
                        XSLEEP;
                        err = unlock(fn, uuid, readonly, &status);
                        LOG("unlock status is %d (err=%d)\n", status, err);
                }
        }
}

static void perf_lock(char *fn, int loops)
{
    int sysstatus;
    char buf[9];
    int start = loops;
    int lease = DEFAULT_LEASE_TIME_SECS;

    sprintf(buf, "%08d", getpid());

    while (loops--) {
        sysstatus = lock(fn, buf, 0, 0, &lease, &status);
        if (status < 0) {
            printf("failed to get lock at iteration %d errno=%d\n", 
                   start - loops, errno);
            return;
        }
    }
    unlock(fn, buf, 0, &status);
}

int main(int argc, char *argv[])
{
        int status;
        char *ptr;
        char uuid[12];
        int force;
        int readonly;
        int max_lease, cur_lease;
        int intstatus;
        int lease = DEFAULT_LEASE_TIME_SECS;

        if (argc < 3) {
                usage(argv[0]);
                return 0;
        }

        sprintf(uuid, "%08d", getpid());
        ptr = uuid;

        if (!strcmp(argv[1],"d")) {
                status = lock_delta(argv[2], &cur_lease, &max_lease);

                printf("lock delta for %s is %d seconds, max lease is %d\n", 
                       argv[2], cur_lease, max_lease);
        } else if (!strcmp(argv[1],"t")) {
                test_file(argv[2]);
        } else if (!strcmp(argv[1],"r")) {
                random_locks(argv[2]);
        } else if (!strcmp(argv[1],"p")) {
                perf_lock(argv[2], argc < 3 ? 100000 : atoi(argv[3]));
        } else if (!strcmp(argv[1],"l")) {
                if (argc < 4) force = 0; else force = atoi(argv[3]);
                if (argc < 5) readonly = 0; else readonly = atoi(argv[4]);
                if (argc >= 6) ptr = argv[5];
                if (argc == 7) lease = atoi(argv[6]);
                status = lock(argv[2], ptr, readonly, force, &lease, &intstatus);
                printf("lock status = %d\n", status);
        } else if (!strcmp(argv[1],"u") ) {
                if (argc < 5) readonly = 0; else readonly = atoi(argv[3]);
                if (argc == 5) ptr = argv[4];
                status = unlock(argv[2], ptr, readonly, &intstatus);
                printf("unlock status = %d\n", intstatus);
        } else {
                usage(argv[0]);
        }

        return status;
}
#elif defined(UTIL)
/*
 * the following is used for non-libary, standalone 
 * program utility as a shell program
 */

static void usage(char *prg)
{
        printf("usage %s\n"
               "    delta <filename>\n"
               "    unlock <filename> <r|w> <uniqid>\n"
               "    lock <filename> <r|w> <0|1> <uniqid> <leasetime>\n", prg);
        printf("        delta : get time since lock last refreshed\n");
        printf("                returns delta time and max lease time in seconds\n");
        printf("        unlock: unlock request filename, r|w,  uniqID\n");
        printf("                returns status (success is 0)\n");
        printf("        lock  : lock request filename,  r|w, force?, uniqID, lease time request\n");
        printf("                returns status (success is 0) and established lease time in seconds\n");
}

int main(int argc, char *argv[])
{
        int status = 0;
        int dlock;
        char *ptr;
        int force;
        int readonly;
        int cur_lease, max_lease, intstatus;
        int lease = DEFAULT_LEASE_TIME_SECS;

        if (argc < 3) {
                if (argc == 2 && !strcmp(argv[1], "-h")) {
                    usage(argv[0]);
                } else {
                    printf("%d\n", LOCK_EUSAGE);
                }
                return 0;
        }

        if (!strcmp(argv[1],"delta") && (argc == 3)) {
                status = lock_delta(argv[2], &cur_lease, &max_lease);
                printf("%d %d\n", cur_lease, max_lease);
        } else if (!strcmp(argv[1],"lock") && (argc == 7)) {
                readonly = (strcmp(argv[3], "r") == 0) ? 1 : 0;
                force = atoi(argv[4]);
                ptr = argv[5];
                lease = atoi(argv[6]);
                status = lock(argv[2], ptr, force, readonly, &lease, &intstatus);
                printf("%d %d\n", intstatus, lease);
        } else if (!strcmp(argv[1],"unlock") && (argc == 5)) {
                readonly = (strcmp(argv[3], "r") == 0) ? 1 : 0;
                ptr = argv[4];
                status = unlock(argv[2], ptr, readonly, &intstatus);
                printf("%d\n", intstatus);
        } else {
                printf("%d\n", LOCK_EUSAGE);
        }

        /* this is either 0 or a system defined errno */
        return status;
}
#endif
