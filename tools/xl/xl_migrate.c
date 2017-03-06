/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

#ifndef LIBXL_HAVE_NO_SUSPEND_RESUME

static pid_t create_migration_child(const char *rune, int *send_fd,
                                        int *recv_fd)
{
    int sendpipe[2], recvpipe[2];
    pid_t child;

    if (!rune || !send_fd || !recv_fd)
        return -1;

    MUST( libxl_pipe(ctx, sendpipe) );
    MUST( libxl_pipe(ctx, recvpipe) );

    child = xl_fork(child_migration, "migration transport process");

    if (!child) {
        dup2(sendpipe[0], 0);
        dup2(recvpipe[1], 1);
        close(sendpipe[0]); close(sendpipe[1]);
        close(recvpipe[0]); close(recvpipe[1]);
        execlp("sh","sh","-c",rune,(char*)0);
        perror("failed to exec sh");
        exit(EXIT_FAILURE);
    }

    close(sendpipe[0]);
    close(recvpipe[1]);
    *send_fd = sendpipe[1];
    *recv_fd = recvpipe[0];

    /* if receiver dies, we get an error and can clean up
       rather than just dying */
    signal(SIGPIPE, SIG_IGN);

    return child;
}

static int migrate_read_fixedmessage(int fd, const void *msg, int msgsz,
                                     const char *what, const char *rune) {
    char buf[msgsz];
    const char *stream;
    int rc;

    stream = rune ? "migration receiver stream" : "migration stream";
    rc = libxl_read_exactly(ctx, fd, buf, msgsz, stream, what);
    if (rc) return 1;

    if (memcmp(buf, msg, msgsz)) {
        fprintf(stderr, "%s contained unexpected data instead of %s\n",
                stream, what);
        if (rune)
            fprintf(stderr, "(command run was: %s )\n", rune);
        return 1;
    }
    return 0;
}

static void migration_child_report(int recv_fd) {
    pid_t child;
    int status, sr;
    struct timeval now, waituntil, timeout;
    static const struct timeval pollinterval = { 0, 1000 }; /* 1ms */

    if (!xl_child_pid(child_migration)) return;

    CHK_SYSCALL(gettimeofday(&waituntil, 0));
    waituntil.tv_sec += 2;

    for (;;) {
        pid_t migration_child = xl_child_pid(child_migration);
        child = xl_waitpid(child_migration, &status, WNOHANG);

        if (child == migration_child) {
            if (status)
                xl_report_child_exitstatus(XTL_INFO, child_migration,
                                           migration_child, status);
            break;
        }
        if (child == -1) {
            fprintf(stderr, "wait for migration child [%ld] failed: %s\n",
                    (long)migration_child, strerror(errno));
            break;
        }
        assert(child == 0);

        CHK_SYSCALL(gettimeofday(&now, 0));
        if (timercmp(&now, &waituntil, >)) {
            fprintf(stderr, "migration child [%ld] not exiting, no longer"
                    " waiting (exit status will be unreported)\n",
                    (long)migration_child);
            break;
        }
        timersub(&waituntil, &now, &timeout);

        if (recv_fd >= 0) {
            fd_set readfds, exceptfds;
            FD_ZERO(&readfds);
            FD_ZERO(&exceptfds);
            FD_SET(recv_fd, &readfds);
            FD_SET(recv_fd, &exceptfds);
            sr = select(recv_fd+1, &readfds,0,&exceptfds, &timeout);
        } else {
            if (timercmp(&timeout, &pollinterval, >))
                timeout = pollinterval;
            sr = select(0,0,0,0, &timeout);
        }
        if (sr > 0) {
            recv_fd = -1;
        } else if (sr == 0) {
        } else if (sr == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "migration child [%ld] exit wait select"
                        " failed unexpectedly: %s\n",
                        (long)migration_child, strerror(errno));
                break;
            }
        }
    }
}

static void migrate_do_preamble(int send_fd, int recv_fd, pid_t child,
                                uint8_t *config_data, int config_len,
                                const char *rune)
{
    int rc = 0;

    if (send_fd < 0 || recv_fd < 0) {
        fprintf(stderr, "migrate_do_preamble: invalid file descriptors\n");
        exit(EXIT_FAILURE);
    }

    rc = migrate_read_fixedmessage(recv_fd, migrate_receiver_banner,
                                   sizeof(migrate_receiver_banner)-1,
                                   "banner", rune);
    if (rc) {
        close(send_fd);
        migration_child_report(recv_fd);
        exit(EXIT_FAILURE);
    }

    save_domain_core_writeconfig(send_fd, "migration stream",
                                 config_data, config_len);

}

static void migrate_domain(uint32_t domid, const char *rune, int debug,
                           const char *override_config_file)
{
    pid_t child = -1;
    int rc;
    int send_fd = -1, recv_fd = -1;
    char *away_domname;
    char rc_buf;
    uint8_t *config_data;
    int config_len, flags = LIBXL_SUSPEND_LIVE;

    save_domain_core_begin(domid, override_config_file,
                           &config_data, &config_len);

    if (!config_len) {
        fprintf(stderr, "No config file stored for running domain and "
                "none supplied - cannot migrate.\n");
        exit(EXIT_FAILURE);
    }

    child = create_migration_child(rune, &send_fd, &recv_fd);

    migrate_do_preamble(send_fd, recv_fd, child, config_data, config_len,
                        rune);

    xtl_stdiostream_adjust_flags(logger, XTL_STDIOSTREAM_HIDE_PROGRESS, 0);

    if (debug)
        flags |= LIBXL_SUSPEND_DEBUG;
    rc = libxl_domain_suspend(ctx, domid, send_fd, flags, NULL);
    if (rc) {
        fprintf(stderr, "migration sender: libxl_domain_suspend failed"
                " (rc=%d)\n", rc);
        if (rc == ERROR_GUEST_TIMEDOUT)
            goto failed_suspend;
        else
            goto failed_resume;
    }

    //fprintf(stderr, "migration sender: Transfer complete.\n");
    // Should only be printed when debugging as it's a bit messy with
    // progress indication.

    rc = migrate_read_fixedmessage(recv_fd, migrate_receiver_ready,
                                   sizeof(migrate_receiver_ready),
                                   "ready message", rune);
    if (rc) goto failed_resume;

    xtl_stdiostream_adjust_flags(logger, 0, XTL_STDIOSTREAM_HIDE_PROGRESS);

    /* right, at this point we are about give the destination
     * permission to rename and resume, so we must first rename the
     * domain away ourselves */

    fprintf(stderr, "migration sender: Target has acknowledged transfer.\n");

    if (common_domname) {
        xasprintf(&away_domname, "%s--migratedaway", common_domname);
        rc = libxl_domain_rename(ctx, domid, common_domname, away_domname);
        if (rc) goto failed_resume;
    }

    /* point of no return - as soon as we have tried to say
     * "go" to the receiver, it's not safe to carry on.  We leave
     * the domain renamed to %s--migratedaway in case that's helpful.
     */

    fprintf(stderr, "migration sender: Giving target permission to start.\n");

    rc = libxl_write_exactly(ctx, send_fd,
                             migrate_permission_to_go,
                             sizeof(migrate_permission_to_go),
                             "migration stream", "GO message");
    if (rc) goto failed_badly;

    rc = migrate_read_fixedmessage(recv_fd, migrate_report,
                                   sizeof(migrate_report),
                                   "success/failure report message", rune);
    if (rc) goto failed_badly;

    rc = libxl_read_exactly(ctx, recv_fd,
                            &rc_buf, 1,
                            "migration ack stream", "success/failure status");
    if (rc) goto failed_badly;

    if (rc_buf) {
        fprintf(stderr, "migration sender: Target reports startup failure"
                " (status code %d).\n", rc_buf);

        rc = migrate_read_fixedmessage(recv_fd, migrate_permission_to_go,
                                       sizeof(migrate_permission_to_go),
                                       "permission for sender to resume",
                                       rune);
        if (rc) goto failed_badly;

        fprintf(stderr, "migration sender: Trying to resume at our end.\n");

        if (common_domname) {
            libxl_domain_rename(ctx, domid, away_domname, common_domname);
        }
        rc = libxl_domain_resume(ctx, domid, 1, 0);
        if (!rc) fprintf(stderr, "migration sender: Resumed OK.\n");

        fprintf(stderr, "Migration failed due to problems at target.\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "migration sender: Target reports successful startup.\n");
    libxl_domain_destroy(ctx, domid, 0); /* bang! */
    fprintf(stderr, "Migration successful.\n");
    exit(EXIT_SUCCESS);

 failed_suspend:
    close(send_fd);
    migration_child_report(recv_fd);
    fprintf(stderr, "Migration failed, failed to suspend at sender.\n");
    exit(EXIT_FAILURE);

 failed_resume:
    close(send_fd);
    migration_child_report(recv_fd);
    fprintf(stderr, "Migration failed, resuming at sender.\n");
    libxl_domain_resume(ctx, domid, 1, 0);
    exit(EXIT_FAILURE);

 failed_badly:
    fprintf(stderr,
 "** Migration failed during final handshake **\n"
 "Domain state is now undefined !\n"
 "Please CHECK AT BOTH ENDS for running instances, before renaming and\n"
 " resuming at most one instance.  Two simultaneous instances of the domain\n"
 " would probably result in SEVERE DATA LOSS and it is now your\n"
 " responsibility to avoid that.  Sorry.\n");

    close(send_fd);
    migration_child_report(recv_fd);
    exit(EXIT_FAILURE);
}

static void migrate_receive(int debug, int daemonize, int monitor,
                            int pause_after_migration,
                            int send_fd, int recv_fd,
                            libxl_checkpointed_stream checkpointed,
                            char *colo_proxy_script,
                            bool userspace_colo_proxy)
{
    uint32_t domid;
    int rc, rc2;
    char rc_buf;
    char *migration_domname;
    struct domain_create dom_info;

    signal(SIGPIPE, SIG_IGN);
    /* if we get SIGPIPE we'd rather just have it as an error */

    fprintf(stderr, "migration target: Ready to receive domain.\n");

    CHK_ERRNOVAL(libxl_write_exactly(
                     ctx, send_fd, migrate_receiver_banner,
                     sizeof(migrate_receiver_banner)-1,
                     "migration ack stream", "banner") );

    memset(&dom_info, 0, sizeof(dom_info));
    dom_info.debug = debug;
    dom_info.daemonize = daemonize;
    dom_info.monitor = monitor;
    dom_info.paused = 1;
    dom_info.migrate_fd = recv_fd;
    dom_info.send_back_fd = send_fd;
    dom_info.migration_domname_r = &migration_domname;
    dom_info.checkpointed_stream = checkpointed;
    dom_info.colo_proxy_script = colo_proxy_script;
    dom_info.userspace_colo_proxy = userspace_colo_proxy;

    rc = create_domain(&dom_info);
    if (rc < 0) {
        fprintf(stderr, "migration target: Domain creation failed"
                " (code %d).\n", rc);
        exit(EXIT_FAILURE);
    }

    domid = rc;

    switch (checkpointed) {
    case LIBXL_CHECKPOINTED_STREAM_REMUS:
    case LIBXL_CHECKPOINTED_STREAM_COLO:
    {
        const char *ha = checkpointed == LIBXL_CHECKPOINTED_STREAM_COLO ?
                         "COLO" : "Remus";
        /* If we are here, it means that the sender (primary) has crashed.
         * TODO: Split-Brain Check.
         */
        fprintf(stderr, "migration target: %s Failover for domain %u\n",
                ha, domid);

        /*
         * If domain renaming fails, lets just continue (as we need the domain
         * to be up & dom names may not matter much, as long as its reachable
         * over network).
         *
         * If domain unpausing fails, destroy domain ? Or is it better to have
         * a consistent copy of the domain (memory, cpu state, disk)
         * on atleast one physical host ? Right now, lets just leave the domain
         * as is and let the Administrator decide (or troubleshoot).
         */
        if (migration_domname) {
            rc = libxl_domain_rename(ctx, domid, migration_domname,
                                     common_domname);
            if (rc)
                fprintf(stderr, "migration target (%s): "
                        "Failed to rename domain from %s to %s:%d\n",
                        ha, migration_domname, common_domname, rc);
        }

        if (checkpointed == LIBXL_CHECKPOINTED_STREAM_COLO)
            /* The guest is running after failover in COLO mode */
            exit(rc ? -ERROR_FAIL: 0);

        rc = libxl_domain_unpause(ctx, domid);
        if (rc)
            fprintf(stderr, "migration target (%s): "
                    "Failed to unpause domain %s (id: %u):%d\n",
                    ha, common_domname, domid, rc);

        exit(rc ? EXIT_FAILURE : EXIT_SUCCESS);
    }
    default:
        /* do nothing */
        break;
    }

    fprintf(stderr, "migration target: Transfer complete,"
            " requesting permission to start domain.\n");

    rc = libxl_write_exactly(ctx, send_fd,
                             migrate_receiver_ready,
                             sizeof(migrate_receiver_ready),
                             "migration ack stream", "ready message");
    if (rc) exit(EXIT_FAILURE);

    rc = migrate_read_fixedmessage(recv_fd, migrate_permission_to_go,
                                   sizeof(migrate_permission_to_go),
                                   "GO message", 0);
    if (rc) goto perhaps_destroy_notify_rc;

    fprintf(stderr, "migration target: Got permission, starting domain.\n");

    if (migration_domname) {
        rc = libxl_domain_rename(ctx, domid, migration_domname, common_domname);
        if (rc) goto perhaps_destroy_notify_rc;
    }

    if (!pause_after_migration) {
        rc = libxl_domain_unpause(ctx, domid);
        if (rc) goto perhaps_destroy_notify_rc;
    }

    fprintf(stderr, "migration target: Domain started successsfully.\n");
    rc = 0;

 perhaps_destroy_notify_rc:
    rc2 = libxl_write_exactly(ctx, send_fd,
                              migrate_report, sizeof(migrate_report),
                              "migration ack stream",
                              "success/failure report");
    if (rc2) exit(EXIT_FAILURE);

    rc_buf = -rc;
    assert(!!rc_buf == !!rc);
    rc2 = libxl_write_exactly(ctx, send_fd, &rc_buf, 1,
                              "migration ack stream",
                              "success/failure code");
    if (rc2) exit(EXIT_FAILURE);

    if (rc) {
        fprintf(stderr, "migration target: Failure, destroying our copy.\n");

        rc2 = libxl_domain_destroy(ctx, domid, 0);
        if (rc2) {
            fprintf(stderr, "migration target: Failed to destroy our copy"
                    " (code %d).\n", rc2);
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "migration target: Cleanup OK, granting sender"
                " permission to resume.\n");

        rc2 = libxl_write_exactly(ctx, send_fd,
                                  migrate_permission_to_go,
                                  sizeof(migrate_permission_to_go),
                                  "migration ack stream",
                                  "permission to sender to have domain back");
        if (rc2) exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}


int main_migrate_receive(int argc, char **argv)
{
    int debug = 0, daemonize = 1, monitor = 1, pause_after_migration = 0;
    libxl_checkpointed_stream checkpointed = LIBXL_CHECKPOINTED_STREAM_NONE;
    int opt;
    bool userspace_colo_proxy = false;
    char *script = NULL;
    static struct option opts[] = {
        {"colo", 0, 0, 0x100},
        /* It is a shame that the management code for disk is not here. */
        {"coloft-script", 1, 0, 0x200},
        {"userspace-colo-proxy", 0, 0, 0x300},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "Fedrp", opts, "migrate-receive", 0) {
    case 'F':
        daemonize = 0;
        break;
    case 'e':
        daemonize = 0;
        monitor = 0;
        break;
    case 'd':
        debug = 1;
        break;
    case 'r':
        checkpointed = LIBXL_CHECKPOINTED_STREAM_REMUS;
        break;
    case 0x100:
        checkpointed = LIBXL_CHECKPOINTED_STREAM_COLO;
        break;
    case 0x200:
        script = optarg;
        break;
    case 0x300:
        userspace_colo_proxy = true;
        break;
    case 'p':
        pause_after_migration = 1;
        break;
    }

    if (argc-optind != 0) {
        help("migrate-receive");
        return EXIT_FAILURE;
    }
    migrate_receive(debug, daemonize, monitor, pause_after_migration,
                    STDOUT_FILENO, STDIN_FILENO,
                    checkpointed, script, userspace_colo_proxy);

    return EXIT_SUCCESS;
}

int main_migrate(int argc, char **argv)
{
    uint32_t domid;
    const char *config_filename = NULL;
    const char *ssh_command = "ssh";
    char *rune = NULL;
    char *host;
    int opt, daemonize = 1, monitor = 1, debug = 0, pause_after_migration = 0;
    static struct option opts[] = {
        {"debug", 0, 0, 0x100},
        {"live", 0, 0, 0x200},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "FC:s:ep", opts, "migrate", 2) {
    case 'C':
        config_filename = optarg;
        break;
    case 's':
        ssh_command = optarg;
        break;
    case 'F':
        daemonize = 0;
        break;
    case 'e':
        daemonize = 0;
        monitor = 0;
        break;
    case 'p':
        pause_after_migration = 1;
        break;
    case 0x100: /* --debug */
        debug = 1;
        break;
    case 0x200: /* --live */
        /* ignored for compatibility with xm */
        break;
    }

    domid = find_domain(argv[optind]);
    host = argv[optind + 1];

    bool pass_tty_arg = progress_use_cr || (isatty(2) > 0);

    if (!ssh_command[0]) {
        rune= host;
    } else {
        char verbose_buf[minmsglevel_default+3];
        int verbose_len;
        verbose_buf[0] = ' ';
        verbose_buf[1] = '-';
        memset(verbose_buf+2, 'v', minmsglevel_default);
        verbose_buf[sizeof(verbose_buf)-1] = 0;
        if (minmsglevel == minmsglevel_default) {
            verbose_len = 0;
        } else {
            verbose_len = (minmsglevel_default - minmsglevel) + 2;
        }
        xasprintf(&rune, "exec %s %s xl%s%.*s migrate-receive%s%s%s",
                  ssh_command, host,
                  pass_tty_arg ? " -t" : "",
                  verbose_len, verbose_buf,
                  daemonize ? "" : " -e",
                  debug ? " -d" : "",
                  pause_after_migration ? " -p" : "");
    }

    migrate_domain(domid, rune, debug, config_filename);
    return EXIT_SUCCESS;
}

int main_remus(int argc, char **argv)
{
    uint32_t domid;
    int opt, rc, daemonize = 1;
    const char *ssh_command = "ssh";
    char *host = NULL, *rune = NULL;
    libxl_domain_remus_info r_info;
    int send_fd = -1, recv_fd = -1;
    pid_t child = -1;
    uint8_t *config_data;
    int config_len;

    memset(&r_info, 0, sizeof(libxl_domain_remus_info));

    SWITCH_FOREACH_OPT(opt, "Fbundi:s:N:ecp", NULL, "remus", 2) {
    case 'i':
        r_info.interval = atoi(optarg);
        break;
    case 'F':
        libxl_defbool_set(&r_info.allow_unsafe, true);
        break;
    case 'b':
        libxl_defbool_set(&r_info.blackhole, true);
        break;
    case 'u':
        libxl_defbool_set(&r_info.compression, false);
        break;
    case 'n':
        libxl_defbool_set(&r_info.netbuf, false);
        break;
    case 'N':
        r_info.netbufscript = optarg;
        break;
    case 'd':
        libxl_defbool_set(&r_info.diskbuf, false);
        break;
    case 's':
        ssh_command = optarg;
        break;
    case 'e':
        daemonize = 0;
        break;
    case 'c':
        libxl_defbool_set(&r_info.colo, true);
        break;
    case 'p':
        libxl_defbool_set(&r_info.userspace_colo_proxy, true);
    }

    domid = find_domain(argv[optind]);
    host = argv[optind + 1];

    /* Defaults */
    libxl_defbool_setdefault(&r_info.blackhole, false);
    libxl_defbool_setdefault(&r_info.colo, false);
    libxl_defbool_setdefault(&r_info.userspace_colo_proxy, false);

    if (!libxl_defbool_val(r_info.colo) && !r_info.interval)
        r_info.interval = 200;

    if (libxl_defbool_val(r_info.userspace_colo_proxy) &&
        !libxl_defbool_val(r_info.colo)) {
        fprintf(stderr, "Option -p must be used in conjunction with -c");
        exit(-1);
    }

    if (libxl_defbool_val(r_info.colo)) {
        if (r_info.interval || libxl_defbool_val(r_info.blackhole) ||
            !libxl_defbool_is_default(r_info.netbuf) ||
            !libxl_defbool_is_default(r_info.diskbuf)) {
            perror("option -c is conflict with -i, -d, -n or -b");
            exit(-1);
        }

        if (libxl_defbool_is_default(r_info.compression)) {
            perror("COLO can't be used with memory compression. "
                   "Disable memory checkpoint compression now...");
            libxl_defbool_set(&r_info.compression, false);
        }
    }

    if (!r_info.netbufscript) {
        if (libxl_defbool_val(r_info.colo))
            r_info.netbufscript = default_colo_proxy_script;
        else
            r_info.netbufscript = default_remus_netbufscript;
    }

    if (libxl_defbool_val(r_info.blackhole)) {
        send_fd = open("/dev/null", O_RDWR, 0644);
        if (send_fd < 0) {
            perror("failed to open /dev/null");
            exit(EXIT_FAILURE);
        }
    } else {

        if (!ssh_command[0]) {
            rune = host;
        } else {
            if (!libxl_defbool_val(r_info.colo)) {
                xasprintf(&rune, "exec %s %s xl migrate-receive %s %s",
                          ssh_command, host,
                          "-r",
                          daemonize ? "" : " -e");
            } else {
                xasprintf(&rune, "exec %s %s xl migrate-receive %s %s %s %s %s",
                          ssh_command, host,
                          "--colo",
                          r_info.netbufscript ? "--coloft-script" : "",
                          r_info.netbufscript ? r_info.netbufscript : "",
                          libxl_defbool_val(r_info.userspace_colo_proxy) ?
                          "--userspace-colo-proxy" : "",
                          daemonize ? "" : " -e");
            }
        }

        save_domain_core_begin(domid, NULL, &config_data, &config_len);

        if (!config_len) {
            fprintf(stderr, "No config file stored for running domain and "
                    "none supplied - cannot start remus.\n");
            exit(EXIT_FAILURE);
        }

        child = create_migration_child(rune, &send_fd, &recv_fd);

        migrate_do_preamble(send_fd, recv_fd, child, config_data, config_len,
                            rune);

        if (ssh_command[0])
            free(rune);
    }

    /* Point of no return */
    rc = libxl_domain_remus_start(ctx, &r_info, domid, send_fd, recv_fd, 0);

    /* check if the domain exists. User may have xl destroyed the
     * domain to force failover
     */
    if (libxl_domain_info(ctx, 0, domid)) {
        fprintf(stderr, "%s: Primary domain has been destroyed.\n",
                libxl_defbool_val(r_info.colo) ? "COLO" : "Remus");
        close(send_fd);
        return EXIT_SUCCESS;
    }

    /* If we are here, it means remus setup/domain suspend/backup has
     * failed. Try to resume the domain and exit gracefully.
     * TODO: Split-Brain check.
     */
    if (rc == ERROR_GUEST_TIMEDOUT)
        fprintf(stderr, "Failed to suspend domain at primary.\n");
    else {
        fprintf(stderr, "%s: Backup failed? resuming domain at primary.\n",
                libxl_defbool_val(r_info.colo) ? "COLO" : "Remus");
        libxl_domain_resume(ctx, domid, 1, 0);
    }

    close(send_fd);
    return EXIT_FAILURE;
}
#endif


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
