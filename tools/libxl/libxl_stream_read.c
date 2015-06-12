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
 */

/* Success/error/cleanup handling. */
static void stream_complete(libxl__egc *egc,
                            libxl__stream_read_state *stream, int rc);
static void stream_done(libxl__egc *egc,
                        libxl__stream_read_state *stream);

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
    stream->rc = 0;
    stream->running = false;
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
    int rc = 0;

    libxl__stream_read_init(stream);

    stream->running = true;
    stream->phase   = SRS_PHASE_NORMAL;

    dc->ao      = stream->ao;
    dc->readfd  = stream->fd;
    dc->writefd = -1;

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

    case REC_TYPE_XENSTORE_DATA:
        rc = libxl__toolstack_restore(dcs->guest_domid, rec->body,
                                      rec->hdr.length, &dcs->shs);
        if (rc)
            goto err;

        /*
         * libxl__toolstack_restore() is a synchronous function.
         * Request that our caller queues another action for us.
         */
        further_action_needed = true;
        break;

    case REC_TYPE_EMULATOR_CONTEXT:
        write_emulator_blob(egc, stream, rec);
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
    int rc = 0, writefd = -1;

    if (rec->hdr.length < sizeof(*emu_hdr)) {
        rc = ERROR_FAIL;
        LOG(ERROR, "Emulator record too short to contain header");
        goto err;
    }
    emu_hdr = rec->body;

    sprintf(path, XC_DEVICE_MODEL_RESTORE_FILE".%u", dcs->guest_domid);

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
    dc->ao = stream->ao;
    dc->writewhat = "qemu save file";
    dc->writefd = writefd;
    dc->maxsz = -1;
    dc->callback = write_emulator_done;

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

    if (!stream->rc)
        stream->rc = rc;
    stream_done(egc, stream);
}

static void stream_done(libxl__egc *egc,
                        libxl__stream_read_state *stream)
{
    libxl__sr_record_buf *rec, *trec;

    assert(stream->running);
    stream->running = false;

    if (stream->incoming_record)
        free_record(stream->incoming_record);

    if (stream->emu_carefd)
        libxl__carefd_close(stream->emu_carefd);

    /* The record queue had better be empty if the stream believes
     * itself to have been successful. */
    assert(LIBXL_STAILQ_EMPTY(&stream->record_queue) || stream->rc);

    LIBXL_STAILQ_FOREACH_SAFE(rec, &stream->record_queue, entry, trec)
        free_record(rec);

    stream->completion_callback(egc, stream, stream->rc);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
