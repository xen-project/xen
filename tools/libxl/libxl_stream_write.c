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
 * Infrastructure for writing a domain to a libxl migration v2 stream.
 *
 * Entry points from outside:
 *  - libxl__stream_write_start()
 *     - Start writing a stream from the start.
 *  - libxl__stream_write_start_checkpoint()
 *     - Write the records which form a checkpoint into a stream.
 *
 * In normal operation, there are two tasks running at once; this
 * stream processing, and the libxl-save-helper.  check_all_finished()
 * is used to join all the tasks in both success and error cases.
 *
 * Nomenclature for event callbacks:
 *  - $FOO_done(): Completion callback for $FOO
 *  - write_$FOO(): Set up the datacopier to write a $FOO
 *  - $BAR_header(): A $BAR record header only
 *  - $BAR_record(): A complete $BAR record with header and content
 *
 * The main loop for a plain VM writes:
 *  - Stream header
 *  - Libxc record
 *  - (optional) Emulator xenstore record
 *  - if (hvm)
 *      - Emulator context record
 *  - End record
 *
 * For checkpointed stream, there is a second loop which is triggered by a
 * save-helper checkpoint callback.  It writes:
 *  - (optional) Emulator xenstore record
 *  - if (hvm)
 *      - Emulator context record
 *  - Checkpoint end record
 *
 * For back channel stream:
 * - libxl__stream_write_start()
 *    - Set up the stream to running state
 *
 * - Use libxl__stream_write_checkpoint_state to write the record. When the
 *   record is written out, call stream->checkpoint_callback() to return.
 */

/* Success/error/cleanup handling. */
static void stream_success(libxl__egc *egc,
                           libxl__stream_write_state *stream);
static void stream_complete(libxl__egc *egc,
                            libxl__stream_write_state *stream, int rc);
static void stream_done(libxl__egc *egc,
                        libxl__stream_write_state *stream, int rc);
static void checkpoint_done(libxl__egc *egc,
                            libxl__stream_write_state *stream,
                            int rc);
static void check_all_finished(libxl__egc *egc,
                               libxl__stream_write_state *stream, int rc);

/* Event chain for a plain VM. */
static void stream_header_done(libxl__egc *egc,
                               libxl__datacopier_state *dc,
                               int rc, int onwrite, int errnoval);
static void libxc_header_done(libxl__egc *egc,
                              libxl__stream_write_state *stream);
/* libxl__xc_domain_save_done() lives here, event-order wise. */
static void write_emulator_xenstore_record(libxl__egc *egc,
                                           libxl__stream_write_state *stream);
static void emulator_xenstore_record_done(libxl__egc *egc,
                                          libxl__stream_write_state *stream);
static void write_emulator_context_record(libxl__egc *egc,
                                          libxl__stream_write_state *stream);
static void emulator_context_read_done(libxl__egc *egc,
                                       libxl__datacopier_state *dc,
                                       int rc, int onwrite, int errnoval);
static void emulator_context_record_done(libxl__egc *egc,
                                         libxl__stream_write_state *stream);
static void write_end_record(libxl__egc *egc,
                             libxl__stream_write_state *stream);

/* Event chain unique to checkpointed streams. */
static void write_checkpoint_end_record(libxl__egc *egc,
                                        libxl__stream_write_state *stream);
static void checkpoint_end_record_done(libxl__egc *egc,
                                       libxl__stream_write_state *stream);

/* checkpoint state */
static void write_checkpoint_state_done(libxl__egc *egc,
                                        libxl__stream_write_state *stream);
static void checkpoint_state_done(libxl__egc *egc,
                                  libxl__stream_write_state *stream, int rc);

/*----- Helpers -----*/

static void write_done(libxl__egc *egc,
                       libxl__datacopier_state *dc,
                       int rc, int onwrite, int errnoval);

/* Generic helper to set up writing some data to the stream. */
static void setup_generic_write(libxl__egc *egc,
                                libxl__stream_write_state *stream,
                                const char *what,
                                libxl__sr_rec_hdr *hdr,
                                libxl__sr_emulator_hdr *emu_hdr,
                                void *body,
                                sws_record_done_cb cb)
{
    static const uint8_t zero_padding[1U << REC_ALIGN_ORDER] = { 0 };

    libxl__datacopier_state *dc = &stream->dc;
    int rc;

    assert(stream->record_done_callback == NULL);

    dc->writewhat = what;
    dc->used      = 0;
    dc->callback  = write_done;
    rc = libxl__datacopier_start(dc);

    if (rc) {
        stream_complete(egc, stream, rc);
        return;
    }

    size_t padsz = ROUNDUP(hdr->length, REC_ALIGN_ORDER) - hdr->length;
    uint32_t length = hdr->length;

    /* Insert header */
    libxl__datacopier_prefixdata(egc, dc, hdr, sizeof(*hdr));

    /* Optional emulator sub-header */
    if (emu_hdr) {
        assert(length >= sizeof(*emu_hdr));
        libxl__datacopier_prefixdata(egc, dc, emu_hdr, sizeof(*emu_hdr));
        length -= sizeof(*emu_hdr);
    }

    /* Optional body */
    if (body)
        libxl__datacopier_prefixdata(egc, dc, body, length);

    /* Any required padding */
    if (padsz > 0)
        libxl__datacopier_prefixdata(egc, dc,
                                     zero_padding, padsz);
    stream->record_done_callback = cb;
}

/* Helper to set up writing a regular record to the stream. */
static void setup_write(libxl__egc *egc,
                        libxl__stream_write_state *stream,
                        const char *what,
                        libxl__sr_rec_hdr *hdr,
                        void *body,
                        sws_record_done_cb cb)
{
    setup_generic_write(egc, stream, what, hdr, NULL, body, cb);
}

/* Helper to set up writing a record with an emulator prefix to the stream. */
static void setup_emulator_write(libxl__egc *egc,
                                 libxl__stream_write_state *stream,
                                 const char *what,
                                 libxl__sr_rec_hdr *hdr,
                                 libxl__sr_emulator_hdr *emu_hdr,
                                 void *body,
                                 sws_record_done_cb cb)
{
    assert(stream->emu_sub_hdr.id != EMULATOR_UNKNOWN);
    setup_generic_write(egc, stream, what, hdr, emu_hdr, body, cb);
}


static void write_done(libxl__egc *egc,
                       libxl__datacopier_state *dc,
                       int rc, int onwrite, int errnoval)
{
    libxl__stream_write_state *stream = CONTAINER_OF(dc, *stream, dc);
    STATE_AO_GC(stream->ao);
    sws_record_done_cb cb = stream->record_done_callback;

    stream->record_done_callback = NULL;

    if (onwrite || errnoval)
        stream_complete(egc, stream, rc ?: ERROR_FAIL);
    else
        cb(egc, stream);
}

/*----- Entrypoints -----*/

void libxl__stream_write_init(libxl__stream_write_state *stream)
{
    assert(stream->ao);

    stream->shs.ao = stream->ao;
    libxl__save_helper_init(&stream->shs);

    stream->rc = 0;
    stream->running = false;
    stream->in_checkpoint = false;
    stream->sync_teardown = false;
    FILLZERO(stream->dc);
    stream->record_done_callback = NULL;
    FILLZERO(stream->emu_dc);
    stream->emu_carefd = NULL;
    FILLZERO(stream->emu_rec_hdr);
    FILLZERO(stream->emu_sub_hdr);
    stream->emu_body = NULL;
    stream->device_model_version = LIBXL_DEVICE_MODEL_VERSION_UNKNOWN;
}

void libxl__stream_write_start(libxl__egc *egc,
                               libxl__stream_write_state *stream)
{
    libxl__datacopier_state *dc = &stream->dc;
    libxl__domain_save_state *dss = stream->dss;
    STATE_AO_GC(stream->ao);
    struct libxl__sr_hdr hdr;
    int rc = 0;

    libxl__stream_write_init(stream);

    stream->running = true;

    dc->ao        = ao;
    dc->readfd    = -1;
    dc->writewhat = "stream header";
    dc->copywhat  = "save v2 stream";
    dc->writefd   = stream->fd;
    dc->maxsz     = -1;
    dc->callback  = stream_header_done;

    if (stream->back_channel)
        return;

    if (dss->type == LIBXL_DOMAIN_TYPE_HVM) {
        stream->device_model_version =
            libxl__device_model_version_running(gc, dss->domid);
        switch (stream->device_model_version) {
        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
            stream->emu_sub_hdr.id = EMULATOR_QEMU_TRADITIONAL;
            break;

        case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
            stream->emu_sub_hdr.id = EMULATOR_QEMU_UPSTREAM;
            break;

        default:
            rc = ERROR_FAIL;
            LOGD(ERROR, dss->domid, "Unknown emulator for HVM domain");
            goto err;
        }
        stream->emu_sub_hdr.index = 0;
    }

    rc = libxl__datacopier_start(dc);
    if (rc)
        goto err;

    FILLZERO(hdr);
    hdr.ident   = htobe64(RESTORE_STREAM_IDENT);
    hdr.version = htobe32(RESTORE_STREAM_VERSION);
    hdr.options = htobe32(0);

    libxl__datacopier_prefixdata(egc, dc, &hdr, sizeof(hdr));
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

void libxl__stream_write_start_checkpoint(libxl__egc *egc,
                                          libxl__stream_write_state *stream)
{
    assert(stream->running);
    assert(!stream->in_checkpoint);
    assert(!stream->back_channel);
    stream->in_checkpoint = true;

    write_emulator_xenstore_record(egc, stream);
}

void libxl__stream_write_abort(libxl__egc *egc,
                               libxl__stream_write_state *stream, int rc)
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
    libxl__stream_write_state *stream = CONTAINER_OF(dc, *stream, dc);
    STATE_AO_GC(stream->ao);
    struct libxl__sr_rec_hdr rec;

    if (rc || errnoval) {
        stream_complete(egc, stream, rc ?: ERROR_FAIL);
        return;
    }

    FILLZERO(rec);
    rec.type = REC_TYPE_LIBXC_CONTEXT;

    setup_write(egc, stream, "libxc header",
                &rec, NULL, libxc_header_done);
}

static void libxc_header_done(libxl__egc *egc,
                              libxl__stream_write_state *stream)
{
    libxl__xc_domain_save(egc, stream->dss, &stream->shs);
}

void libxl__xc_domain_save_done(libxl__egc *egc, void *dss_void,
                                int rc, int retval, int errnoval)
{
    libxl__domain_save_state *dss = dss_void;
    libxl__stream_write_state *stream = &dss->sws;
    STATE_AO_GC(dss->ao);

    if (rc)
        goto err;

    if (retval) {
        LOGEVD(ERROR, errnoval, dss->domid, "saving domain: %s",
              dss->dsps.guest_responded ?
              "domain responded to suspend request" :
              "domain did not respond to suspend request");
        if (!dss->dsps.guest_responded)
            rc = ERROR_GUEST_TIMEDOUT;
        else if (dss->rc)
            rc = dss->rc;
        else
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
    if (libxl__stream_write_inuse(stream)) {
        if (dss->checkpointed_stream != LIBXL_CHECKPOINTED_STREAM_NONE)
            /*
             * For remus, if libxl__xc_domain_save_done() completes,
             * there was an error sending data to the secondary.
             * Resume the primary ASAP. The caller doesn't care of the
             * return value (Please refer to libxl__remus_teardown())
             */
            stream_complete(egc, stream, 0);
        else
            write_emulator_xenstore_record(egc, stream);
    }
}

static void write_emulator_xenstore_record(libxl__egc *egc,
                                           libxl__stream_write_state *stream)
{
    libxl__domain_save_state *dss = stream->dss;
    STATE_AO_GC(stream->ao);
    struct libxl__sr_rec_hdr rec;
    int rc;
    char *buf = NULL;
    uint32_t len = 0;

    if (dss->type != LIBXL_DOMAIN_TYPE_HVM) {
        emulator_xenstore_record_done(egc, stream);
        return;
    }

    rc = libxl__save_emulator_xenstore_data(dss, &buf, &len);
    if (rc)
        goto err;

    /* No record? - All done. */
    if (len == 0) {
        emulator_xenstore_record_done(egc, stream);
        return;
    }

    FILLZERO(rec);
    rec.type = REC_TYPE_EMULATOR_XENSTORE_DATA;
    rec.length = len + sizeof(stream->emu_sub_hdr);

    setup_emulator_write(egc, stream, "emulator xenstore record",
                         &rec, &stream->emu_sub_hdr, buf,
                         emulator_xenstore_record_done);
    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

static void emulator_xenstore_record_done(libxl__egc *egc,
                                          libxl__stream_write_state *stream)
{
    libxl__domain_save_state *dss = stream->dss;

    if (dss->type == LIBXL_DOMAIN_TYPE_HVM)
        write_emulator_context_record(egc, stream);
    else {
        if (stream->in_checkpoint)
            write_checkpoint_end_record(egc, stream);
        else
            write_end_record(egc, stream);
    }
}

static void write_emulator_context_record(libxl__egc *egc,
                                          libxl__stream_write_state *stream)
{
    libxl__domain_save_state *dss = stream->dss;
    libxl__datacopier_state *dc = &stream->emu_dc;
    STATE_AO_GC(stream->ao);
    struct libxl__sr_rec_hdr *rec = &stream->emu_rec_hdr;
    struct stat st;
    int rc;

    if (dss->type != LIBXL_DOMAIN_TYPE_HVM) {
        emulator_context_record_done(egc, stream);
        return;
    }

    /* Convenience aliases */
    const char *const filename = dss->dsps.dm_savefile;

    libxl__carefd_begin();
    int readfd = open(filename, O_RDONLY);
    stream->emu_carefd = libxl__carefd_opened(CTX, readfd);
    if (readfd == -1) {
        rc = ERROR_FAIL;
        LOGED(ERROR, dss->domid, "unable to open %s", filename);
        goto err;
    }

    if (fstat(readfd, &st)) {
        rc = ERROR_FAIL;
        LOGED(ERROR, dss->domid, "unable to fstat %s", filename);
        goto err;
    }

    if (!S_ISREG(st.st_mode)) {
        rc = ERROR_FAIL;
        LOGD(ERROR, dss->domid, "%s is not a plain file!", filename);
        goto err;
    }

    rec->type = REC_TYPE_EMULATOR_CONTEXT;
    rec->length = st.st_size + sizeof(stream->emu_sub_hdr);
    stream->emu_body = libxl__malloc(NOGC, st.st_size);

    FILLZERO(*dc);
    dc->ao            = stream->ao;
    dc->readwhat      = "qemu save file";
    dc->copywhat      = "save v2 stream";
    dc->readfd        = readfd;
    dc->writefd       = -1;
    dc->maxsz         = -1;
    dc->readbuf       = stream->emu_body;
    dc->bytes_to_read = st.st_size;
    dc->callback      = emulator_context_read_done;

    rc = libxl__datacopier_start(dc);
    if (rc)
        goto err;

    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

static void emulator_context_read_done(libxl__egc *egc,
                                       libxl__datacopier_state *dc,
                                       int rc, int onwrite, int errnoval)
{
    libxl__stream_write_state *stream = CONTAINER_OF(dc, *stream, emu_dc);
    STATE_AO_GC(stream->ao);

    if (rc || onwrite || errnoval) {
        stream_complete(egc, stream, rc ?: ERROR_FAIL);
        return;
    }

    libxl__carefd_close(stream->emu_carefd);
    stream->emu_carefd = NULL;

    setup_emulator_write(egc, stream, "emulator record",
                         &stream->emu_rec_hdr,
                         &stream->emu_sub_hdr,
                         stream->emu_body,
                         emulator_context_record_done);
}

static void emulator_context_record_done(libxl__egc *egc,
                                         libxl__stream_write_state *stream)
{
    free(stream->emu_body);
    stream->emu_body = NULL;

    if (stream->in_checkpoint)
        write_checkpoint_end_record(egc, stream);
    else
        write_end_record(egc, stream);
}

static void write_end_record(libxl__egc *egc,
                             libxl__stream_write_state *stream)
{
    struct libxl__sr_rec_hdr rec;

    FILLZERO(rec);
    rec.type = REC_TYPE_END;

    setup_write(egc, stream, "end record",
                &rec, NULL, stream_success);
}

static void write_checkpoint_end_record(libxl__egc *egc,
                                        libxl__stream_write_state *stream)
{
    struct libxl__sr_rec_hdr rec;

    FILLZERO(rec);
    rec.type = REC_TYPE_CHECKPOINT_END;

    setup_write(egc, stream, "checkpoint end record",
                &rec, NULL, checkpoint_end_record_done);
}

static void checkpoint_end_record_done(libxl__egc *egc,
                                       libxl__stream_write_state *stream)
{
    checkpoint_done(egc, stream, 0);
}

/*----- Success/error/cleanup handling. -----*/

static void stream_success(libxl__egc *egc, libxl__stream_write_state *stream)
{
    stream_complete(egc, stream, 0);
}

static void stream_complete(libxl__egc *egc,
                            libxl__stream_write_state *stream, int rc)
{
    assert(stream->running);

    if (stream->in_checkpoint) {
        assert(rc);

        /*
         * If an error is encountered while in a checkpoint, pass it
         * back to libxc.  The failure will come back around to us via
         * libxl__xc_domain_save_done()
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
         *    libxl__xc_domain_save_done()
         * 2. back_channel stream
         *    libxl__stream_write_abort()
         */
        checkpoint_state_done(egc, stream, rc);
        return;
    }

    stream_done(egc, stream, rc);
}

static void stream_done(libxl__egc *egc,
                        libxl__stream_write_state *stream, int rc)
{
    assert(stream->running);
    assert(!stream->in_checkpoint_state);
    stream->running = false;

    if (stream->emu_carefd)
        libxl__carefd_close(stream->emu_carefd);
    free(stream->emu_body);

    if (!stream->back_channel) {
        /*
         * 1. In stream_done(), stream->running is set to false, so
         *    the stream itself is not in use.
         * 2. Write stream is a back channel stream, this means it
         *    is only used by secondary(restore side) to send records
         *    back, so it doesn't have save helper.
         * So we don't need invoke check_all_finished here
         */
         check_all_finished(egc, stream, rc);
    }
}

static void checkpoint_done(libxl__egc *egc,
                            libxl__stream_write_state *stream,
                            int rc)
{
    assert(stream->in_checkpoint);

    stream->in_checkpoint = false;
    stream->checkpoint_callback(egc, stream, rc);
}

static void check_all_finished(libxl__egc *egc,
                               libxl__stream_write_state *stream,
                               int rc)
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

        libxl__stream_write_abort(egc, stream, rc);
        libxl__save_helper_abort(egc, &stream->shs);

        stream->sync_teardown = false;
    }

    /* Don't fire the callback until all our parallel tasks have stopped. */
    if (libxl__stream_write_inuse(stream) ||
        libxl__save_helper_inuse(&stream->shs))
        return;

    if (stream->completion_callback)
        /* back channel stream doesn't have completion_callback() */
        stream->completion_callback(egc, stream, stream->rc);
}

/*----- checkpoint state -----*/

void libxl__stream_write_checkpoint_state(libxl__egc *egc,
                                          libxl__stream_write_state *stream,
                                          libxl_sr_checkpoint_state *srcs)
{
    struct libxl__sr_rec_hdr rec;

    assert(stream->running);
    assert(!stream->in_checkpoint);
    assert(!stream->in_checkpoint_state);
    stream->in_checkpoint_state = true;

    FILLZERO(rec);
    rec.type = REC_TYPE_CHECKPOINT_STATE;
    rec.length = sizeof(*srcs);

    setup_write(egc, stream, "checkpoint state", &rec,
                srcs, write_checkpoint_state_done);
}

static void write_checkpoint_state_done(libxl__egc *egc,
                                        libxl__stream_write_state *stream)
{
    checkpoint_state_done(egc, stream, 0);
}

static void checkpoint_state_done(libxl__egc *egc,
                                  libxl__stream_write_state *stream, int rc)
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
