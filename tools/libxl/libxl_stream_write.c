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
 *  - Toolstack record
 *  - if (hvm), Qemu record
 *  - End record
 *
 * For checkpointed stream, there is a second loop which is triggered by a
 * save-helper checkpoint callback.  It writes:
 *  - Toolstack record
 *  - if (hvm), Qemu record
 *  - Checkpoint end record
 */

/* Success/error/cleanup handling. */
static void stream_success(libxl__egc *egc,
                           libxl__stream_write_state *stream);
static void stream_complete(libxl__egc *egc,
                            libxl__stream_write_state *stream, int rc);
static void stream_done(libxl__egc *egc,
                        libxl__stream_write_state *stream);
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
static void write_toolstack_record(libxl__egc *egc,
                                   libxl__stream_write_state *stream);
static void toolstack_record_done(libxl__egc *egc,
                                  libxl__stream_write_state *stream);
static void write_emulator_record(libxl__egc *egc,
                                  libxl__stream_write_state *stream);
static void emulator_read_done(libxl__egc *egc,
                               libxl__datacopier_state *dc,
                               int rc, int onwrite, int errnoval);
static void emulator_record_done(libxl__egc *egc,
                                 libxl__stream_write_state *stream);
static void write_end_record(libxl__egc *egc,
                             libxl__stream_write_state *stream);

/* Event chain unique to checkpointed streams. */
static void write_checkpoint_end_record(libxl__egc *egc,
                                        libxl__stream_write_state *stream);
static void checkpoint_end_record_done(libxl__egc *egc,
                                       libxl__stream_write_state *stream);

/*----- Helpers -----*/

static void write_done(libxl__egc *egc,
                       libxl__datacopier_state *dc,
                       int rc, int onwrite, int errnoval);

/* Helper to set up reading some data from the stream. */
static void setup_write(libxl__egc *egc,
                        libxl__stream_write_state *stream,
                        const char *what,
                        libxl__sr_rec_hdr *hdr, void *body,
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

    /* Insert header */
    libxl__datacopier_prefixdata(egc, dc, hdr, sizeof(*hdr));

    /* Optional body */
    if (body)
        libxl__datacopier_prefixdata(egc, dc, body, hdr->length);

    /* Any required padding */
    if (padsz > 0)
        libxl__datacopier_prefixdata(egc, dc,
                                     zero_padding, padsz);
    stream->record_done_callback = cb;
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
    stream->rc = 0;
    stream->running = false;
    stream->in_checkpoint = false;
    FILLZERO(stream->dc);
    stream->record_done_callback = NULL;
    FILLZERO(stream->emu_dc);
    stream->emu_carefd = NULL;
    FILLZERO(stream->emu_rec_hdr);
    stream->emu_body = NULL;
}

void libxl__stream_write_start(libxl__egc *egc,
                               libxl__stream_write_state *stream)
{
    libxl__datacopier_state *dc = &stream->dc;
    STATE_AO_GC(stream->ao);
    struct libxl__sr_hdr hdr;
    int rc = 0;

    libxl__stream_write_init(stream);

    stream->running = true;

    dc->ao        = ao;
    dc->readfd    = -1;
    dc->writewhat = "save/migration stream";
    dc->writefd   = stream->fd;
    dc->maxsz     = -1;
    dc->callback  = stream_header_done;

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
    stream->in_checkpoint = true;

    write_toolstack_record(egc, stream);
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
    libxl__domain_suspend_state *dss = dss_void;
    libxl__stream_write_state *stream = &dss->sws;
    STATE_AO_GC(dss->ao);

    if (rc)
        goto err;

    if (retval) {
        LOGEV(ERROR, errnoval, "saving domain: %s",
              dss->guest_responded ?
              "domain responded to suspend request" :
              "domain did not respond to suspend request");
        if (!dss->guest_responded)
            rc = ERROR_GUEST_TIMEDOUT;
        else if (dss->rc)
            rc = dss->rc;
        else
            rc = ERROR_FAIL;
        goto err;
    }

    write_toolstack_record(egc, stream);

 err:
    check_all_finished(egc, stream, rc);
}

static void write_toolstack_record(libxl__egc *egc,
                                   libxl__stream_write_state *stream)
{
    libxl__domain_suspend_state *dss = stream->dss;
    STATE_AO_GC(stream->ao);
    struct libxl__sr_rec_hdr rec;
    int rc;
    uint8_t *toolstack_buf = NULL; /* We must free this. */
    uint32_t toolstack_len;

    rc = libxl__toolstack_save(dss->domid, &toolstack_buf,
                               &toolstack_len, dss);
    if (rc)
        goto err;

    FILLZERO(rec);
    rec.type = REC_TYPE_XENSTORE_DATA;
    rec.length = toolstack_len;

    setup_write(egc, stream, "toolstack record",
                &rec, toolstack_buf,
                toolstack_record_done);

    free(toolstack_buf);
    return;

 err:
    assert(rc);
    free(toolstack_buf);
    stream_complete(egc, stream, rc);
}

static void toolstack_record_done(libxl__egc *egc,
                                  libxl__stream_write_state *stream)
{
    libxl__domain_suspend_state *dss = stream->dss;

    if (dss->type == LIBXL_DOMAIN_TYPE_HVM)
        write_emulator_record(egc, stream);
    else {
        if (stream->in_checkpoint)
            write_checkpoint_end_record(egc, stream);
        else
            write_end_record(egc, stream);
    }
}

static void write_emulator_record(libxl__egc *egc,
                                  libxl__stream_write_state *stream)
{
    libxl__domain_suspend_state *dss = stream->dss;
    libxl__datacopier_state *dc = &stream->emu_dc;
    STATE_AO_GC(stream->ao);
    struct libxl__sr_rec_hdr *rec = &stream->emu_rec_hdr;
    struct libxl__sr_emulator_hdr *ehdr = NULL;
    struct stat st;
    int rc;

    assert(dss->type == LIBXL_DOMAIN_TYPE_HVM);

    /* Convenience aliases */
    const char *const filename = dss->dm_savefile;
    const uint32_t domid = dss->domid;

    libxl__carefd_begin();
    int readfd = open(filename, O_RDONLY);
    stream->emu_carefd = libxl__carefd_opened(CTX, readfd);
    if (readfd == -1) {
        rc = ERROR_FAIL;
        LOGE(ERROR, "unable to open %s", filename);
        goto err;
    }

    if (fstat(readfd, &st)) {
        rc = ERROR_FAIL;
        LOGE(ERROR, "unable to fstat %s", filename);
        goto err;
    }

    if (!S_ISREG(st.st_mode)) {
        rc = ERROR_FAIL;
        LOG(ERROR, "%s is not a plain file!", filename);
        goto err;
    }

    rec->type = REC_TYPE_EMULATOR_CONTEXT;
    rec->length = st.st_size + sizeof(*ehdr);
    stream->emu_body = ehdr = libxl__malloc(NOGC, rec->length);

    switch(libxl__device_model_version_running(gc, domid)) {
    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL:
        ehdr->id = EMULATOR_QEMU_TRADITIONAL;
        break;

    case LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN:
        ehdr->id = EMULATOR_QEMU_UPSTREAM;
        break;

    default:
        rc = ERROR_FAIL;
        goto err;
    }
    ehdr->index = 0;

    FILLZERO(*dc);
    dc->ao            = stream->ao;
    dc->readwhat      = "qemu save file";
    dc->readfd        = readfd;
    dc->maxsz         = -1;
    dc->readbuf       = stream->emu_body + sizeof(*ehdr);
    dc->bytes_to_read = rec->length - sizeof(*ehdr);
    dc->callback      = emulator_read_done;

    rc = libxl__datacopier_start(dc);
    if (rc)
        goto err;

    return;

 err:
    assert(rc);
    stream_complete(egc, stream, rc);
}

static void emulator_read_done(libxl__egc *egc,
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

    setup_write(egc, stream, "emulator record",
                &stream->emu_rec_hdr, stream->emu_body,
                emulator_record_done);
}

static void emulator_record_done(libxl__egc *egc,
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

    if (!stream->rc)
        stream->rc = rc;
    stream_done(egc, stream);
}

static void stream_done(libxl__egc *egc,
                        libxl__stream_write_state *stream)
{
    assert(stream->running);
    stream->running = false;

    if (stream->emu_carefd)
        libxl__carefd_close(stream->emu_carefd);
    free(stream->emu_body);

    check_all_finished(egc, stream, stream->rc);
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

    if (!stream->rc && rc) {
        /* First reported failure. Tear everything down. */
        stream->rc = rc;

        libxl__stream_write_abort(egc, stream, rc);
        libxl__save_helper_abort(egc, &stream->shs);
    }

    /* Don't fire the callback until all our parallel tasks have stopped. */
    if (libxl__stream_write_inuse(stream) ||
        libxl__save_helper_inuse(&stream->shs))
        return;

    stream->completion_callback(egc, stream, stream->rc);
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
