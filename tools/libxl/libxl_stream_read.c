/*
 * Copyright (C) 2015      Citrix Ltd.
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

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"

/*
 * Infrastructure for reading and acting on the contents of a libxl
 * migration stream. There are a lot of moving parts here.
 *
 * The logic revolves around two actions; reading another record from
 * the stream, and processing the records.  The stream_continue()
 * function is responsible for choosing the next action to perform.
 *
 * The exact order of reading and processing is controlled by 'phase'.
 * All complete records are held in the record_queue before being
 * processed, and all records will be processed in queue order.
 *
 * Internal states:
 *           running  phase       in_         record   incoming
 *                                checkpoint  _queue   _record
 *
 * Undefined    undef  undef        undef       undef    undef
 * Idle         false  undef        false       0        0
 * Active       true   NORMAL       false       0/1      0/partial
 * Active       true   BUFFERING    true        any      0/partial
 * Active       true   UNBUFFERING  true        any      0
 *
 * While reading data from the stream, 'dc' is active and a callback
 * is expected.  Most actions in process_record() start a callback of
 * their own.  Those which don't return out and stream_continue() sets
 * up the next action.
 *
 * PHASE_NORMAL:
 *   This phase is used for regular migration or resume from file.
 *   Records are read one at time and immediately processed.  (The
 *   record queue will not contain more than a single record.)
 *
 * PHASE_BUFFERING:
 *   This phase is used in checkpointed streams, when libxc signals
 *   the presence of a checkpoint in the stream.  Records are read and
 *   buffered until a CHECKPOINT_END record has been read.
 *
 * PHASE_UNBUFFERING:
 *   Once a CHECKPOINT_END record has been read, all buffered records
 *   are processed.
 *
 * Note:
 *   Record buffers are not allocated from a GC; they are allocated
 *   and tracked manually.  This is to avoid OOM with Remus where the
 *   AO lives for the lifetime of the process.  Per-checkpoint AO's
 *   might be an avenue to explore.
 *
 * Entry points from outside:
 *  - libxl__stream_read_init()
 *     - Initialises state.  Must be called once before _start()
 *  - libxl__stream_read_start()
 *     - Starts reading records from the stream, and acting on them.
 *  - libxl__stream_read_start_checkpoint()
 *     - Starts buffering records at a checkpoint.  Must be called on
 *       a running stream.
 *
 * There are several chains of event:
 *
 * 1) Starting a stream follows:
 *    - libxl__stream_read_start()
 *    - stream_header_done()
 *    - stream_continue()
 *
 * 2) Reading a record follows:
 *    - stream_continue()
 *    - record_header_done()
 *    - record_body_done()
 *    - stream_continue()
 *
 * 3) Processing a record had several chains to follow, depending on
 *    the record in question.
 * 3a) "Simple" record:
 *    - process_record()
 *    - stream_continue()
 * 3b) LIBXC record:
 *    - process_record()
 *    - libxl__xc_domain_restore()
 *    - libxl__xc_domain_restore_done()
 *    - stream_continue()
 * 3c) EMULATOR record:
 *    - process_record()
 *    - stream_write_emulator()
 *    - stream_write_emulator_done()
 *    - stream_continue()
 *
 * Depending on the contents of the stream, there are likely to be several
 * parallel tasks being managed.  check_all_finished() is used to join all
 * tasks in both success and error cases.
 *
 * Failover for remus
 *  - We buffer all records until a CHECKPOINT_END record is received
 *  - We will consume the buffered records when a CHECKPOINT_END record
 *    is received
 *  - If we find some internal error, then rc or retval is not 0 in
 *    libxl__xc_domain_restore_done(). In this case, we don't resume the
 *    guest
 *  - If we need to do failover from primary, then rc and retval are both
 *    0 in libxl__xc_domain_restore_done(). In this case, the buffered
 *    state will be dropped, because we haven't received a CHECKPOINT_END
 *    record, and therefore the buffered state is inconsistent. In
 *    libxl__xc_domain_restore_done(), we just complete the stream and
 *    stream->completion_callback() will be called to resume the guest
 *
 * For back channel stream:
 * - libxl__stream_read_start()
 *    - Set up the stream to running state
 *
 * - libxl__stream_read_continue()
 *     - Set up reading the next record from a started stream.
 *       Add some codes to process_record() to handle the record.
 *       Then call stream->checkpoint_callback() to return.
 */

/* Success/error/cleanup handling. */
static void stream_complete(libxl__egc *egc,
                            libxl__stream_read_state *stream, int rc);
static void checkpoint_done(libxl__egc *egc,
                            libxl__stream_read_state *stream, int rc);
static void stream_done(libxl__egc *egc,
                        libxl__stream_read_state *stream, int rc);
static void conversion_done(libxl__egc *egc,
                            libxl__conversion_helper_state *chs, int rc);
static void check_all_finished(libxl__egc *egc,
                               libxl__stream_read_state *stream, int rc);

/* Event chain for first iteration, from _start(). */
static void stream_header_done(libxl__egc *egc,
                               libxl__datacopier_state *dc,
                               int rc, int onwrite, int errnoval);
static void stream_continue(libxl__egc *egc,
                            libxl__stream_read_state *stream);
static void setup_read_record(libxl__egc *egc,
                              libxl__stream_read_state *stream);
static void record_header_done(libxl__egc *egc,
                               libxl__datacopier_state *dc,
                               int rc, int onwrite, int errnoval);
static void record_body_done(libxl__egc *egc,
                             libxl__datacopier_state *dc,
                             int rc, int onwrite, int errnoval);
static bool process_record(libxl__egc *egc,
                           libxl__stream_read_state *stream);

/* Event chain for processing an emulator blob. */
static void write_emulator_blob(libxl__egc *egc,
                                libxl__stream_read_state *stream,
                                libxl__sr_record_buf *rec);
static void write_emulator_done(libxl__egc *egc,
                                libxl__datacopier_state *dc,
                                int rc, int onwrite, int errnoval);

/* Handlers for checkpoint state mini-loop */
static void checkpoint_state_done(libxl__egc *egc,
                                  libxl__stream_read_state *stream, int rc);

/*----- Helpers -----*/

/* Helper to set up reading some data from the stream. */
static int setup_read(libxl__stream_read_state *stream,
                      const char *what, void *ptr, size_t nr_bytes,
                      libxl__datacopier_callback cb)
{
    libxl__datacopier_state *dc = &stream->dc;

    dc->readwhat      = what;
    dc->readbuf       = ptr;
    dc->bytes_to_read = nr_bytes;
    dc->used          = 0;
    dc->callback      = cb;

    return libxl__datacopier_start(dc);
}

static void free_record(libxl__sr_record_buf *rec)
{
    if (rec) {
        free(rec->body);
        free(rec);
    }
}

/*----- Entrypoints -----*/

void libxl__stream_read_init(libxl__stream_read_state *stream)
{
    assert(stream->ao);

    stream->shs.ao = stream->ao;
    libxl__save_helper_init(&stream->shs);

    stream->chs.ao = stream->ao;
    libxl__conversion_helper_init(&stream->chs);

    stream->rc = 0;
    stream->running = false;
    stream->in_checkpoint = false;
    stream->sync_teardown = false;
    FILLZERO(stream->dc);
    FILLZERO(stream->hdr);
    LIBXL_STAILQ_INIT(&stream->record_queue);
    stream->phase = SRS_PHASE_NORMAL;
    stream->recursion_guard = false;
    stream->incoming_record = NULL;
    FILLZERO(stream->emu_dc);
    stream->emu_carefd = NULL;
}

void libxl__stream_read_start(libxl__egc *egc,
                              libxl__stream_read_state *stream)
{
    libxl__datacopier_state *dc = &stream->dc;
    STATE_AO_GC(stream->ao);
    int rc = 0;

    libxl__stream_read_init(stream);

    stream->running = true;
    stream->phase   = SRS_PHASE_NORMAL;

    if (stream->legacy) {
        /*
         * Convert the legacy stream.
         *
         * This results in a fork()/exec() of conversion helper script.  It is
         * passed the exiting stream->fd as an input, and returns the
         * transformed stream via a new pipe.  The fd of this new pipe then
         * replaces stream->fd, to make the rest of the stream read code
         * agnostic to whether legacy conversion is happening or not.
         */
        libxl__conversion_helper_state *chs = &stream->chs;

        chs->legacy_fd = stream->fd;
        chs->hvm =
            (stream->dcs->guest_config->b_info.type == LIBXL_DOMAIN_TYPE_HVM);
        chs->completion_callback = conversion_done;

        rc = libxl__convert_legacy_stream(egc, &stream->chs);

        if (rc) {
            LOG(ERROR, "Failed to start the legacy stream conversion helper");
            goto err;
        }

        /* There should be no interaction of COLO backchannels and legacy
         * stream conversion. */
        assert(!stream->back_channel);

        /* Confirm *dc is still zeroed out, while we shuffle stream->fd. */
        assert(dc->ao == NULL);
        assert(stream->chs.v2_carefd);
        stream->fd = libxl__carefd_fd(stream->chs.v2_carefd);
        stream->dcs->libxc_fd = stream->fd;
    }
    /* stream->fd is now a v2 stream. */

    dc->ao       = stream->ao;
    dc->copywhat = "restore v2 stream";
    dc->readfd   = stream->fd;
    dc->writefd  = -1;

    if (stream->back_channel)
        return;

    /* Start reading the stream header. */
    rc = setup_read(stream, "stream header",
                    &stream->hdr, sizeof(stream->hdr),
                    stream_header_done);
    if (rc)
        goto err;

    assert(!rc);
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

void libxl__stream_read_start_checkpoint(libxl__egc *egc,
                                         libxl__stream_read_state *stream)
{
    assert(stream->running);
    assert(!stream->in_checkpoint);

    stream->in_checkpoint = true;
    stream->phase = SRS_PHASE_BUFFERING;

    /*
     * Libxc has handed control of the fd to us.  Start reading some
     * libxl records out of it.
     */
    stream_continue(egc, stream);
}

void libxl__stream_read_abort(libxl__egc *egc,
                              libxl__stream_read_state *stream, int rc)
{
    assert(rc);

    if (stream->running)
        stream_complete(egc, stream, rc);
}

/*----- Event logic -----*/

static void stream_header_done(libxl__egc *egc,
                               libxl__datacopier_state *dc,
                               int rc, int onwrite, int errnoval)
{
    libxl__stream_read_state *stream = CONTAINER_OF(dc, *stream, dc);
    libxl__sr_hdr *hdr = &stream->hdr;
    STATE_AO_GC(dc->ao);

    if (rc)
        goto err;

    hdr->ident   = be64toh(hdr->ident);
    hdr->version = be32toh(hdr->version);
    hdr->options = be32toh(hdr->options);

    if (hdr->ident != RESTORE_STREAM_IDENT) {
        rc = ERROR_FAIL;
        LOG(ERROR,
            "Invalid ident: expected 0x%016"PRIx64", got 0x%016"PRIx64,
            RESTORE_STREAM_IDENT, hdr->ident);
        goto err;
    }
    if (hdr->version != RESTORE_STREAM_VERSION) {
        rc = ERROR_FAIL;
        LOG(ERROR, "Unexpected Version: expected %"PRIu32", got %"PRIu32,
            RESTORE_STREAM_VERSION, hdr->version);
        goto err;
    }
    if (hdr->options & RESTORE_OPT_BIG_ENDIAN) {
        rc = ERROR_FAIL;
        LOG(ERROR, "Unable to handle big endian streams");
        goto err;
    }

    LOG(DEBUG, "Stream v%"PRIu32"%s", hdr->version,
        hdr->options & RESTORE_OPT_LEGACY ? " (from legacy)" : "");

    stream_continue(egc, stream);
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

static void stream_continue(libxl__egc *egc,
                            libxl__stream_read_state *stream)
{
    STATE_AO_GC(stream->ao);

    /*
     * Must not mutually recurse with process_record().
     *
     * For records whose processing function is synchronous
     * (e.g. TOOLSTACK), process_record() does not start another async
     * operation, and a further operation should be started.
     *
     * A naive solution, which would function in general, would be for
     * process_record() to call stream_continue().  However, this
     * would allow the content of the stream to cause mutual
     * recursion, and possibly for us to fall off our stack.
     *
     * Instead, process_record() indicates with its return value
     * whether a further operation needs to start, and the
     * recursion_guard is in place to catch any code paths which get
     * this wrong.
     */
    assert(stream->recursion_guard == false);
    stream->recursion_guard = true;

    switch (stream->phase) {
    case SRS_PHASE_NORMAL:
        /*
         * Normal phase (regular migration or restore from file):
         *
         * logically:
         *   do { read_record(); process_record(); } while ( not END );
         *
         * Alternate between reading a record from the stream, and
         * processing the record.  There should never be two records
         * in the queue.
         */
        if (LIBXL_STAILQ_EMPTY(&stream->record_queue))
            setup_read_record(egc, stream);
        else {
            if (process_record(egc, stream))
                setup_read_record(egc, stream);

            /*
             * process_record() had better have consumed the one and
             * only record in the queue.
             */
            assert(LIBXL_STAILQ_EMPTY(&stream->record_queue));
        }
        break;

    case SRS_PHASE_BUFFERING: {
        /*
         * Buffering phase (checkpointed streams only):
         *
         * logically:
         *   do { read_record(); } while ( not CHECKPOINT_END );
         *
         * Read and buffer all records from the stream until a
         * CHECKPOINT_END record is encountered.  We need to peek at
         * the tail to spot the CHECKPOINT_END record, and switch to
         * the unbuffering phase.
         */
        libxl__sr_record_buf *rec = LIBXL_STAILQ_LAST(
            &stream->record_queue, libxl__sr_record_buf, entry);

        assert(stream->in_checkpoint);

        if (!rec || (rec->hdr.type != REC_TYPE_CHECKPOINT_END)) {
            setup_read_record(egc, stream);
            break;
        }

        /*
         * There are now some number of buffered records, with a
         * CHECKPOINT_END at the end. Start processing them all.
         */
        stream->phase = SRS_PHASE_UNBUFFERING;
    }
        /* FALLTHROUGH */
    case SRS_PHASE_UNBUFFERING:
        /*
         * Unbuffering phase (checkpointed streams only):
         *
         * logically:
         *   do { process_record(); } while ( not CHECKPOINT_END );
         *
         * Process all records collected during the buffering phase.
         */
        assert(stream->in_checkpoint);

        while (process_record(egc, stream))
            ; /*
               * Nothing! process_record() helpfully tells us if no specific
               * futher actions have been set up, in which case we want to go
               * ahead and process the next record.
               */
        break;

    default:
        abort();
    }

    assert(stream->recursion_guard == true);
    stream->recursion_guard = false;
}

static void setup_read_record(libxl__egc *egc,
                              libxl__stream_read_state *stream)
{
    libxl__sr_record_buf *rec = NULL;
    STATE_AO_GC(stream->ao);
    int rc;

    assert(stream->incoming_record == NULL);
    stream->incoming_record = rec = libxl__zalloc(NOGC, sizeof(*rec));

    rc = setup_read(stream, "record header",
                    &rec->hdr, sizeof(rec->hdr),
                    record_header_done);
    if (rc)
        goto err;
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

static void record_header_done(libxl__egc *egc,
                               libxl__datacopier_state *dc,
                               int rc, int onwrite, int errnoval)
{
    libxl__stream_read_state *stream = CONTAINER_OF(dc, *stream, dc);
    libxl__sr_record_buf *rec = stream->incoming_record;
    STATE_AO_GC(dc->ao);

    if (rc)
        goto err;

    /* No body? All done. */
    if (rec->hdr.length == 0) {
        record_body_done(egc, dc, 0, 0, 0);
        return;
    }

    size_t bytes_to_read = ROUNDUP(rec->hdr.length, REC_ALIGN_ORDER);
    rec->body = libxl__malloc(NOGC, bytes_to_read);

    rc = setup_read(stream, "record body",
                    rec->body, bytes_to_read,
                    record_body_done);
    if (rc)
        goto err;
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

static void record_body_done(libxl__egc *egc,
                             libxl__datacopier_state *dc,
                             int rc, int onwrite, int errnoval)
{
    libxl__stream_read_state *stream = CONTAINER_OF(dc, *stream, dc);
    libxl__sr_record_buf *rec = stream->incoming_record;
    STATE_AO_GC(dc->ao);

    if (rc)
        goto err;

    LIBXL_STAILQ_INSERT_TAIL(&stream->record_queue, rec, entry);
    stream->incoming_record = NULL;

    stream_continue(egc, stream);
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

/*
 * Returns a boolean indicating whether a further action should be set
 * up by the caller.  This is needed to prevent mutual recursion with
 * stream_continue().
 *
 * It is a bug for this function to ever call stream_continue() or
 * setup_read_record().
 */
static bool process_record(libxl__egc *egc,
                           libxl__stream_read_state *stream)
{
    STATE_AO_GC(stream->ao);
    libxl__domain_create_state *dcs = stream->dcs;
    libxl__sr_record_buf *rec;
    libxl_sr_checkpoint_state *srcs;
    bool further_action_needed = false;
    int rc = 0;

    /* Pop a record from the head of the queue. */
    assert(!LIBXL_STAILQ_EMPTY(&stream->record_queue));
    rec = LIBXL_STAILQ_FIRST(&stream->record_queue);
    LIBXL_STAILQ_REMOVE_HEAD(&stream->record_queue, entry);

    LOG(DEBUG, "Record: %u, length %u", rec->hdr.type, rec->hdr.length);

    switch (rec->hdr.type) {

    case REC_TYPE_END:
        stream_complete(egc, stream, 0);
        break;

    case REC_TYPE_LIBXC_CONTEXT:
        libxl__xc_domain_restore(egc, dcs, &stream->shs, 0, 0, 0);
        break;

    case REC_TYPE_EMULATOR_XENSTORE_DATA:
        if (dcs->guest_config->b_info.device_model_version ==
            LIBXL_DEVICE_MODEL_VERSION_NONE) {
            rc = ERROR_FAIL;
            LOG(ERROR,
                "Received a xenstore emulator record when none was expected");
            goto err;
        }

        if (rec->hdr.length < sizeof(libxl__sr_emulator_hdr)) {
            rc = ERROR_FAIL;
            LOG(ERROR,
                "Emulator xenstore data record too short to contain header");
            goto err;
        }

        rc = libxl__restore_emulator_xenstore_data(dcs,
            rec->body + sizeof(libxl__sr_emulator_hdr),
            rec->hdr.length - sizeof(libxl__sr_emulator_hdr));
        if (rc)
            goto err;

        /*
         * libxl__restore_emulator_xenstore_data() is a synchronous function.
         * Request that our caller queues another action for us.
         */
        further_action_needed = true;
        break;

    case REC_TYPE_EMULATOR_CONTEXT:
        if (dcs->guest_config->b_info.device_model_version ==
            LIBXL_DEVICE_MODEL_VERSION_NONE) {
            rc = ERROR_FAIL;
            LOG(ERROR,
                "Received an emulator context record when none was expected");
            goto err;
        }

        write_emulator_blob(egc, stream, rec);
        break;

    case REC_TYPE_CHECKPOINT_END:
        if (!stream->in_checkpoint) {
            LOG(ERROR, "Unexpected CHECKPOINT_END record in stream");
            rc = ERROR_FAIL;
            goto err;
        }
        checkpoint_done(egc, stream, 0);
        break;

    case REC_TYPE_CHECKPOINT_STATE:
        if (!stream->in_checkpoint_state) {
            LOG(ERROR, "Unexpected CHECKPOINT_STATE record in stream");
            rc = ERROR_FAIL;
            goto err;
        }

        srcs = rec->body;
        checkpoint_state_done(egc, stream, srcs->id);
        break;

    default:
        LOG(ERROR, "Unrecognised record 0x%08x", rec->hdr.type);
        rc = ERROR_FAIL;
        goto err;
    }

    assert(!rc);
    free_record(rec);
    return further_action_needed;

 err:
    assert(rc);
    free_record(rec);
    stream_complete(egc, stream, rc);
    return false;
}

static void write_emulator_blob(libxl__egc *egc,
                                libxl__stream_read_state *stream,
                                libxl__sr_record_buf *rec)
{
    libxl__domain_create_state *dcs = stream->dcs;
    libxl__datacopier_state *dc = &stream->emu_dc;
    libxl__sr_emulator_hdr *emu_hdr;
    STATE_AO_GC(stream->ao);
    char path[256];
    int rc = 0, writefd;

    if (rec->hdr.length < sizeof(*emu_hdr)) {
        rc = ERROR_FAIL;
        LOG(ERROR, "Emulator record too short to contain header");
        goto err;
    }
    emu_hdr = rec->body;

    sprintf(path, LIBXL_DEVICE_MODEL_RESTORE_FILE".%u", dcs->guest_domid);

    assert(stream->emu_carefd == NULL);
    libxl__carefd_begin();
    writefd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    stream->emu_carefd = libxl__carefd_opened(CTX, writefd);

    if (writefd == -1) {
        rc = ERROR_FAIL;
        LOGE(ERROR, "unable to open %s", path);
        goto err;
    }

    FILLZERO(*dc);
    dc->ao         = stream->ao;
    dc->writewhat  = "qemu save file";
    dc->copywhat   = "restore v2 stream";
    dc->writefd    = writefd;
    dc->readfd     = -1;
    dc->maxsz      = -1;
    dc->callback   = write_emulator_done;

    rc = libxl__datacopier_start(dc);
    if (rc)
        goto err;

    libxl__datacopier_prefixdata(egc, dc,
                                 rec->body + sizeof(*emu_hdr),
                                 rec->hdr.length - sizeof(*emu_hdr));
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

static void write_emulator_done(libxl__egc *egc,
                                libxl__datacopier_state *dc,
                                int rc, int onwrite, int errnoval)
{
    libxl__stream_read_state *stream = CONTAINER_OF(dc, *stream, emu_dc);
    STATE_AO_GC(dc->ao);

    libxl__carefd_close(stream->emu_carefd);
    stream->emu_carefd = NULL;

    if (rc)
        goto err;

    stream_continue(egc, stream);
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

/*----- Success/error/cleanup handling. -----*/

static void stream_complete(libxl__egc *egc,
                            libxl__stream_read_state *stream, int rc)
{
    assert(stream->running);

    if (stream->in_checkpoint) {
        assert(rc);

        /*
         * If an error is encountered while in a checkpoint, pass it
         * back to libxc.  The failure will come back around to us via
         * libxl__xc_domain_restore_done()
         */
        checkpoint_done(egc, stream, rc);
        return;
    }

    if (stream->in_checkpoint_state) {
        assert(rc);

        /*
         * If an error is encountered while in a checkpoint, pass it
         * back to libxc.  The failure will come back around to us via
         * 1. normal stream
         *    libxl__xc_domain_restore_done()
         * 2. back_channel stream
         *    libxl__stream_read_abort()
         */
        checkpoint_state_done(egc, stream, rc);
        return;
    }

    stream_done(egc, stream, rc);
}

static void checkpoint_done(libxl__egc *egc,
                            libxl__stream_read_state *stream, int rc)
{
    int ret;

    assert(stream->in_checkpoint);

    if (rc == 0)
        ret = XGR_CHECKPOINT_SUCCESS;
    else if (stream->phase == SRS_PHASE_BUFFERING)
        ret = XGR_CHECKPOINT_FAILOVER;
    else
        ret = XGR_CHECKPOINT_ERROR;

    stream->checkpoint_callback(egc, stream, ret);

    stream->in_checkpoint = false;
    stream->phase = SRS_PHASE_NORMAL;
}

static void stream_done(libxl__egc *egc,
                        libxl__stream_read_state *stream, int rc)
{
    libxl__sr_record_buf *rec, *trec;

    assert(stream->running);
    assert(!stream->in_checkpoint);
    assert(!stream->in_checkpoint_state);
    stream->running = false;

    if (stream->incoming_record)
        free_record(stream->incoming_record);

    if (stream->emu_carefd)
        libxl__carefd_close(stream->emu_carefd);

    /* If we started a conversion helper, we took ownership of its carefd. */
    if (stream->chs.v2_carefd)
        libxl__carefd_close(stream->chs.v2_carefd);

    /* The record queue had better be empty if the stream believes
     * itself to have been successful. */
    assert(LIBXL_STAILQ_EMPTY(&stream->record_queue) || stream->rc);

    LIBXL_STAILQ_FOREACH_SAFE(rec, &stream->record_queue, entry, trec)
        free_record(rec);

    if (!stream->back_channel) {
        /*
         * 1. In stream_done(), stream->running is set to false, so
         *    the stream itself is not in use.
         * 2. Read stream is a back channel stream, this means it is
         *    only used by primary(save side) to read records sent by
         *    secondary(restore side), so it doesn't have restore helper.
         * 3. Back channel stream doesn't support legacy stream, so
         *    there is no conversion helper.
         * So we don't need invoke check_all_finished here
         */
        check_all_finished(egc, stream, rc);
    }
}

void libxl__xc_domain_restore_done(libxl__egc *egc, void *dcs_void,
                                   int rc, int retval, int errnoval)
{
    libxl__domain_create_state *dcs = dcs_void;
    libxl__stream_read_state *stream = &dcs->srs;
    STATE_AO_GC(dcs->ao);

    /* convenience aliases */
    const int checkpointed_stream = dcs->restore_params.checkpointed_stream;

    if (rc)
        goto err;

    if (retval) {
        LOGEV(ERROR, errnoval, "restoring domain");
        rc = ERROR_FAIL;
        goto err;
    }

 err:
    check_all_finished(egc, stream, rc);

    /*
     * This function is the callback associated with the save helper
     * task, not the stream task.  We do not know whether the stream is
     * alive, and check_all_finished() may have torn it down around us.
     * If the stream is not still alive, we must not continue any work.
     */
    if (libxl__stream_read_inuse(stream)) {
        switch (checkpointed_stream) {
        case LIBXL_CHECKPOINTED_STREAM_COLO:
            if (stream->completion_callback) {
                /*
                 * restore, just build the secondary vm, don't close
                 * the stream
                 */
                stream->completion_callback(egc, stream, 0);
            } else {
                /* failover, just close the stream */
                stream_complete(egc, stream, 0);
            }
            break;
        case LIBXL_CHECKPOINTED_STREAM_REMUS:
            /*
             * Failover from primary. Domain state is currently at a
             * consistent checkpoint, complete the stream, and call
             * stream->completion_callback() to resume the guest.
             */
            stream_complete(egc, stream, 0);
            break;
        case LIBXL_CHECKPOINTED_STREAM_NONE:
            /*
             * Libxc has indicated that it is done with the stream.
             * Resume reading libxl records from it.
             */
            stream_continue(egc, stream);
            break;
        }
    }
}

static void conversion_done(libxl__egc *egc,
                            libxl__conversion_helper_state *chs, int rc)
{
    libxl__stream_read_state *stream = CONTAINER_OF(chs, *stream, chs);

    check_all_finished(egc, stream, rc);
}

static void check_all_finished(libxl__egc *egc,
                               libxl__stream_read_state *stream, int rc)
{
    STATE_AO_GC(stream->ao);

    /*
     * In the case of a failure, the _abort()'s below might cancel
     * synchronously on top of us, or asynchronously at a later point.
     *
     * We must avoid the situation where all _abort() cancel
     * synchronously and the completion_callback() gets called twice;
     * once by the first error and once by the final stacked abort(),
     * both of whom will find that all of the tasks have stopped.
     *
     * To avoid this problem, any stacked re-entry into this function is
     * ineligible to fire the completion callback.  The outermost
     * instance will take care of completing, once the stack has
     * unwound.
     */
    if (stream->sync_teardown)
        return;

    if (!stream->rc && rc) {
        /* First reported failure. Tear everything down. */
        stream->rc = rc;
        stream->sync_teardown = true;

        libxl__stream_read_abort(egc, stream, rc);
        libxl__save_helper_abort(egc, &stream->shs);
        libxl__conversion_helper_abort(egc, &stream->chs, rc);

        stream->sync_teardown = false;
    }

    /* Don't fire the callback until all our parallel tasks have stopped. */
    if (libxl__stream_read_inuse(stream) ||
        libxl__save_helper_inuse(&stream->shs) ||
        libxl__conversion_helper_inuse(&stream->chs))
        return;

    if (stream->completion_callback)
        /* back channel stream doesn't have completion_callback() */
        stream->completion_callback(egc, stream, stream->rc);
}

/*----- Checkpoint state handlers -----*/

void libxl__stream_read_checkpoint_state(libxl__egc *egc,
                                         libxl__stream_read_state *stream)
{
    assert(stream->running);
    assert(!stream->in_checkpoint);
    assert(!stream->in_checkpoint_state);
    stream->in_checkpoint_state = true;

    setup_read_record(egc, stream);
}

static void checkpoint_state_done(libxl__egc *egc,
                                  libxl__stream_read_state *stream, int rc)
{
    assert(stream->in_checkpoint_state);
    stream->in_checkpoint_state = false;
    stream->checkpoint_callback(egc, stream, rc);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
