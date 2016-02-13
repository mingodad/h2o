/*
 * Copyright (c) 2014 DeNA Co., Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "h2o/http2_internal.h"

static const h2o_iovec_t CONNECTION_PREFACE = {H2O_STRLIT("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")};

const h2o_http2_priority_t h2o_http2_default_priority = {
    0, /* exclusive */
    0, /* dependency */
    16 /* weight */
};

const h2o_http2_settings_t H2O_HTTP2_SETTINGS_HOST = {
    4096,     /* header_table_size */
    0,        /* enable_push (clients are never allowed to initiate server push; RFC 7540 Section 8.2) */
    100,      /* max_concurrent_streams */
    16777216, /* initial_window_size */
    16384     /* max_frame_size */
};

static const h2o_iovec_t SETTINGS_HOST_BIN = {
    H2O_STRLIT( "\x00\x00\x0c"     /* frame size */
                "\x04"             /* settings frame */
                "\x00"             /* no flags */
                "\x00\x00\x00\x00" /* stream id */
                "\x00\x03"
                "\x00\x00\x00\x64" /* max_concurrent_streams = 100 */
                "\x00\x04"
                "\x01\x00\x00\x00" /* initial_window_size = 16777216 */
                )};

static __thread h2o_buffer_prototype_t wbuf_buffer_prototype = {{16}, {H2O_HTTP2_DEFAULT_OUTBUF_SIZE}};

static void initiate_graceful_shutdown(h2o_context_t *ctx);
static void close_connection(h2o_http2_conn_t *conn);
static void send_stream_error(h2o_http2_conn_t *conn, uint32_t stream_id, int errnum);
static ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc);
static int do_emit_writereq(h2o_http2_conn_t *conn);
static void on_read(h2o_socket_t *sock, int status);
static void push_path(h2o_req_t *src_req, const char *abspath, size_t abspath_len);

const h2o_protocol_callbacks_t H2O_HTTP2_CALLBACKS = {initiate_graceful_shutdown};


static void enqueue_goaway(h2o_http2_conn_t *conn, int errnum, h2o_iovec_t additional_data)
{
    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        /* http2 spec allows sending GOAWAY more than once (for one reason since errors may arise after sending the first one) */
        h2o_http2_encode_goaway_frame(&conn->_write.buf, conn->pull_stream_ids.max_open, errnum, additional_data);
        conn->request_write();
        conn->state = H2O_HTTP2_CONN_STATE_HALF_CLOSED;
    }
}

static void graceful_shutdown_resend_goaway(h2o_timeout_entry_t *entry)
{
    auto ctx = H2O_STRUCT_FROM_MEMBER(h2o_context_t, http2._graceful_shutdown_timeout, entry);
    h2o_linklist_t *node;

    for (node = ctx->http2._conns.next; node != &ctx->http2._conns; node = node->next) {
        auto conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _conns, node);
        if (conn->state < H2O_HTTP2_CONN_STATE_HALF_CLOSED)
            enqueue_goaway(conn, H2O_HTTP2_ERROR_NONE, {});
    }
}

static void initiate_graceful_shutdown(h2o_context_t *ctx)
{
    /* draft-16 6.8
     * A server that is attempting to gracefully shut down a connection SHOULD send an initial GOAWAY frame with the last stream
     * identifier set to 231-1 and a NO_ERROR code. This signals to the client that a shutdown is imminent and that no further
     * requests can be initiated. After waiting at least one round trip time, the server can send another GOAWAY frame with an
     * updated last stream identifier. This ensures that a connection can be cleanly shut down without losing requests.
     */
    h2o_linklist_t *node;

    /* only doit once */
    if (ctx->http2._graceful_shutdown_timeout.cb != NULL)
        return;
    ctx->http2._graceful_shutdown_timeout.cb = graceful_shutdown_resend_goaway;

    for (node = ctx->http2._conns.next; node != &ctx->http2._conns; node = node->next) {
        auto conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _conns, node);
        if (conn->state < H2O_HTTP2_CONN_STATE_HALF_CLOSED) {
            h2o_http2_encode_goaway_frame(&conn->_write.buf, INT32_MAX, H2O_HTTP2_ERROR_NONE,
                                          (h2o_iovec_t){H2O_STRLIT("graceful shutdown")});
            conn->request_write();
        }
    }
    ctx->one_sec_timeout.link(ctx->loop, &ctx->http2._graceful_shutdown_timeout);
}

static void on_idle_timeout(h2o_timeout_entry_t *entry)
{
    auto conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _timeout_entry, entry);

    enqueue_goaway(conn, H2O_HTTP2_ERROR_NONE, h2o_iovec_t::create(H2O_STRLIT("idle timeout")));
    close_connection(conn);
}

static void update_idle_timeout(h2o_http2_conn_t *conn)
{
    conn->_timeout_entry.unlink();

    if (conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed == 0) {
        assert(conn->_pending_reqs.is_empty());
        conn->_timeout_entry.cb = on_idle_timeout;
        conn->super.ctx->http2.idle_timeout.link(conn->super.ctx->loop, &conn->_timeout_entry);
    }
}

static int can_run_requests(h2o_http2_conn_t *conn)
{
    return conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed <
           conn->super.ctx->globalconf->http2.max_concurrent_requests_per_connection;
}

static void run_pending_requests(h2o_http2_conn_t *conn)
{
    while (!conn->_pending_reqs.is_empty() && can_run_requests(conn)) {
        /* fetch and detach a pending stream */
        auto stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.link, conn->_pending_reqs.next);
        stream->_refs.link.unlink();
        /* handle it */
        conn->set_state(stream, H2O_HTTP2_STREAM_STATE_SEND_HEADERS);
        if (!conn->is_push(stream->stream_id) && conn->pull_stream_ids.max_processed < stream->stream_id)
            conn->pull_stream_ids.max_processed = stream->stream_id;
        stream->req.process();
    }
}

static void execute_or_enqueue_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    assert(stream->state < H2O_HTTP2_STREAM_STATE_REQ_PENDING);

    if (stream->_req_body != NULL && stream->_expected_content_length != SIZE_MAX &&
        stream->_req_body->size != stream->_expected_content_length) {
        send_stream_error(conn, stream->stream_id, H2O_HTTP2_ERROR_PROTOCOL);
        conn->stream_reset(stream);
        return;
    }

    conn->set_state(stream, H2O_HTTP2_STREAM_STATE_REQ_PENDING);

    /* TODO schedule the pending reqs using the scheduler */
    conn->_pending_reqs.insert(&stream->_refs.link);

    run_pending_requests(conn);
    update_idle_timeout(conn);
}

void h2o_http2_conn_register_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter;
    int r;

    if (!conn->is_push(stream->stream_id) && conn->pull_stream_ids.max_open < stream->stream_id)
        conn->pull_stream_ids.max_open = stream->stream_id;

    iter = kh_put(h2o_http2_stream_t, conn->streams, stream->stream_id, &r);
    assert(iter != kh_end(conn->streams));
    kh_val(conn->streams, iter) = stream;
}

void h2o_http2_conn_unregister_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter = kh_get(h2o_http2_stream_t, conn->streams, stream->stream_id);
    assert(iter != kh_end(conn->streams));
    kh_del(h2o_http2_stream_t, conn->streams, iter);

    assert(h2o_http2_scheduler_is_open(&stream->_refs.scheduler));
    h2o_http2_scheduler_close(&stream->_refs.scheduler);

    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_IDLE:
    case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
        assert(!stream->_refs.link.is_linked());
        break;
    case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        assert(stream->_refs.link.is_linked());
        stream->_refs.link.unlink();
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        if (stream->_refs.link.is_linked())
            stream->_refs.link.unlink();
        break;
    }
    if (stream->state != H2O_HTTP2_STREAM_STATE_END_STREAM)
        conn->set_state(stream, H2O_HTTP2_STREAM_STATE_END_STREAM);

    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        run_pending_requests(conn);
        update_idle_timeout(conn);
    }
}

static void close_connection_now(h2o_http2_conn_t *conn)
{
    h2o_http2_stream_t *stream;

    assert(!conn->_write.timeout_entry.is_linked());

    kh_foreach_value(conn->streams, stream, { h2o_http2_stream_close(conn, stream); });
    assert(conn->num_streams.pull.open == 0);
    assert(conn->num_streams.pull.half_closed == 0);
    assert(conn->num_streams.pull.send_body == 0);
    assert(conn->num_streams.push.half_closed == 0);
    assert(conn->num_streams.push.send_body == 0);
    assert(conn->num_streams.priority.open == 0);
    kh_destroy(h2o_http2_stream_t, conn->streams);
    assert(conn->_http1_req_input == NULL);
    h2o_hpack_dispose_header_table(&conn->_input_header_table);
    h2o_hpack_dispose_header_table(&conn->_output_header_table);
    assert(conn->_pending_reqs.is_empty());
    conn->_timeout_entry.unlink();
    h2o_buffer_dispose(&conn->_write.buf);
    if (conn->_write.buf_in_flight != NULL)
        h2o_buffer_dispose(&conn->_write.buf_in_flight);
    h2o_http2_scheduler_dispose(&conn->scheduler);
    assert(conn->_write.streams_to_proceed.is_empty());
    assert(!conn->_write.timeout_entry.is_linked());
    if (conn->_headers_unparsed != NULL)
        h2o_buffer_dispose(&conn->_headers_unparsed);
    if (conn->casper != NULL)
        h2o_http2_casper_t::destroy(conn->casper);
    conn->_conns.unlink();

    if (conn->sock != NULL)
        h2o_socket_t::close(conn->sock);
    h2o_mem_free(conn);
}

void close_connection(h2o_http2_conn_t *conn)
{
    conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;

    if (conn->_write.buf_in_flight != NULL || conn->_write.timeout_entry.is_linked()) {
        /* there is a pending write, let on_write_complete actually close the connection */
    } else {
        close_connection_now(conn);
    }
}

void send_stream_error(h2o_http2_conn_t *conn, uint32_t stream_id, int errnum)
{
    assert(stream_id != 0);
    assert(conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING);

    h2o_http2_encode_rst_stream_frame(&conn->_write.buf, stream_id, -errnum);
    conn->request_write();
}

static int update_stream_output_window(h2o_http2_stream_t *stream, ssize_t delta)
{
    ssize_t cur = stream->output_window.get();
    if (stream->output_window.update(delta) != 0)
        return -1;
    if (cur <= 0 && stream->output_window.get() > 0 && stream->has_pending_data()) {
        assert(!stream->_refs.link.is_linked());
        h2o_http2_scheduler_activate(&stream->_refs.scheduler);
    }
    return 0;
}

static int handle_incoming_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const uint8_t *src, size_t len,
                                   const char **err_desc)
{
    int ret, header_exists_map;

    assert(stream->state == H2O_HTTP2_STREAM_STATE_RECV_HEADERS);

    header_exists_map = 0;
    if ((ret = h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table, src, len, &header_exists_map,
                                       &stream->_expected_content_length, err_desc)) != 0)
        return ret;

#define EXPECTED_MAP  \
    (H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS \
            | H2O_HPACK_PARSE_HEADERS_PATH_EXISTS \
            | H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS)
    if ((header_exists_map & EXPECTED_MAP) != EXPECTED_MAP) {
        ret = H2O_HTTP2_ERROR_PROTOCOL;
        goto SendRSTStream;
    }
#undef EXPECTED_MAP

    /* handle the request */
    if (conn->num_streams.pull.open > H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams) {
        ret = H2O_HTTP2_ERROR_REFUSED_STREAM;
        goto SendRSTStream;
    }

    if (stream->_req_body == NULL) {
        execute_or_enqueue_request(conn, stream);
    } else {
        conn->set_state(stream, H2O_HTTP2_STREAM_STATE_RECV_BODY);
    }
    return 0;

SendRSTStream:
    send_stream_error(conn, stream->stream_id, ret);
    conn->stream_reset(stream);
    return 0;
}

static int handle_trailing_headers(h2o_http2_conn_t *conn,
        h2o_http2_stream_t *stream, const uint8_t *src, size_t len,
                                   const char **err_desc)
{
    size_t dummy_content_length;
    int ret;

    assert(stream->state == H2O_HTTP2_STREAM_STATE_RECV_BODY);

    if ((ret = h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table,
            src, len, NULL, &dummy_content_length, err_desc)) != 0)
        return ret;

    execute_or_enqueue_request(conn, stream);
    return 0;
}

static ssize_t expect_continuation_of_headers(h2o_http2_conn_t *conn,
        const uint8_t *src, size_t len, const char **err_desc)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    h2o_http2_stream_t *stream;
    int hret;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &H2O_HTTP2_SETTINGS_HOST, err_desc)) < 0)
        return ret;
    if (frame.type != H2O_HTTP2_FRAME_TYPE_CONTINUATION) {
        *err_desc = "expected CONTINUATION frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    if ((stream = conn->get_stream(frame.stream_id)) == NULL ||
        !(stream->state == H2O_HTTP2_STREAM_STATE_RECV_HEADERS ||
            stream->state == H2O_HTTP2_STREAM_STATE_RECV_BODY)) {
        *err_desc = "unexpected stream id in CONTINUATION frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    h2o_buffer_append(&conn->_headers_unparsed, frame.payload, frame.length);

    if (conn->_headers_unparsed->size <= H2O_MAX_REQLEN) {
        if ((frame.flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
            conn->_read_expect = expect_default;
            if (stream->state == H2O_HTTP2_STREAM_STATE_RECV_HEADERS) {
                hret = handle_incoming_request(conn, stream, (const uint8_t *)conn->_headers_unparsed->bytes,
                                               conn->_headers_unparsed->size, err_desc);
            } else {
                hret = handle_trailing_headers(conn, stream, (const uint8_t *)conn->_headers_unparsed->bytes,
                                               conn->_headers_unparsed->size, err_desc);
            }
            if (hret != 0)
                ret = hret;
            h2o_buffer_dispose(&conn->_headers_unparsed);
            conn->_headers_unparsed = NULL;
        }
    } else {
        /* request is too large (TODO log) */
        send_stream_error(conn, stream->stream_id, H2O_HTTP2_ERROR_REFUSED_STREAM);
        conn->stream_reset(stream);
    }

    return ret;
}

static void update_input_window(h2o_http2_conn_t *conn, uint32_t stream_id,
        h2o_http2_window_t *window, size_t consumed)
{
    window->consume(consumed);
    if (window->get() * 2 < H2O_HTTP2_SETTINGS_HOST.initial_window_size) {
        int32_t delta = (int32_t)(H2O_HTTP2_SETTINGS_HOST.initial_window_size -
                window->get());
        h2o_http2_encode_window_update_frame(&conn->_write.buf, stream_id, delta);
        conn->request_write();
        window->update(delta);
    }
}

static void set_priority(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream,
        const h2o_http2_priority_t *priority, int scheduler_is_open)
{
    h2o_http2_scheduler_node_t *parent_sched;

    /* determine the parent */
    if (priority->dependency != 0) {
        auto parent_stream = conn->get_stream(priority->dependency);
        if (parent_stream != NULL) {
            parent_sched = &parent_stream->_refs.scheduler.node;
        } else {
            /* A dependency on a stream that is not currently in the tree - such as a stream in the "idle" state - results in that
             * stream being given a default priority. (RFC 7540 5.3.1)
             * It is possible for a stream to become closed while prioritization information that creates a dependency on that
             * stream is in transit. If a stream identified in a dependency has no associated priority information, then the
             * dependent stream is instead assigned a default priority. (RFC 7540 5.3.4)
             */
            parent_sched = &conn->scheduler;
            priority = &h2o_http2_default_priority;
        }
    } else {
        parent_sched = &conn->scheduler;
    }

    /* setup the scheduler */
    if (!scheduler_is_open) {
        h2o_http2_scheduler_open(&stream->_refs.scheduler, parent_sched,
                priority->weight, priority->exclusive);
    } else {
        h2o_http2_scheduler_rebind(&stream->_refs.scheduler, parent_sched,
                priority->weight, priority->exclusive);
    }
}

static int handle_data_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame,
        const char **err_desc)
{
    h2o_http2_data_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_data_payload(&payload, frame, err_desc)) != 0)
        return ret;

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    stream = conn->get_stream(frame->stream_id);

    /* save the input in the request body buffer, or send error (and close the stream) */
    if (stream == NULL) {
        if (frame->stream_id <= conn->pull_stream_ids.max_open) {
            send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        } else {
            *err_desc = "invalid DATA frame";
            return H2O_HTTP2_ERROR_PROTOCOL;
        }
    } else if (stream->state != H2O_HTTP2_STREAM_STATE_RECV_BODY) {
        send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
        conn->stream_reset(stream);
        stream = NULL;
    } else if (stream->_req_body->size + payload.length > conn->super.ctx->globalconf->max_request_entity_size) {
        send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_REFUSED_STREAM);
        conn->stream_reset(stream);
        stream = NULL;
    } else {
        h2o_iovec_t buf = h2o_buffer_reserve(&stream->_req_body, payload.length);
        if (buf.base != NULL) {
            h2o_buffer_append(&stream->_req_body, payload.data, payload.length);
            /* handle request if request body is complete */
            if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) != 0) {
                stream->req.entity.init(stream->_req_body->bytes, stream->_req_body->size);
                execute_or_enqueue_request(conn, stream);
                stream = NULL; /* no need to send window update for this stream */
            }
        } else {
            /* memory allocation failed */
            send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_STREAM_CLOSED);
            conn->stream_reset(stream);
            stream = NULL;
        }
    }

    /* consume buffer (and set window_update) */
    update_input_window(conn, 0, &conn->_input_window, frame->length);
    if (stream != NULL)
        update_input_window(conn, stream->stream_id, &stream->input_window, frame->length);

    return 0;
}

static int handle_headers_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_headers_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    /* decode */
    if ((ret = h2o_http2_decode_headers_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if ((frame->stream_id & 1) == 0) {
        *err_desc = "invalid stream id in HEADERS frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }
    if (!(conn->pull_stream_ids.max_open < frame->stream_id)) {
        if ((stream = conn->get_stream(frame->stream_id)) != NULL &&
            stream->state == H2O_HTTP2_STREAM_STATE_RECV_BODY) {
            /* is a trailer */
            if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) == 0) {
                *err_desc = "trailing HEADERS frame MUST have END_STREAM flag set";
                return H2O_HTTP2_ERROR_PROTOCOL;
            }
            stream->req.entity.init(stream->_req_body->bytes, stream->_req_body->size);
            if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) == 0)
                goto PREPARE_FOR_CONTINUATION;
            return handle_trailing_headers(conn, stream, payload.headers, payload.headers_len, err_desc);
        }
        *err_desc = "invalid stream id in HEADERS frame";
        return H2O_HTTP2_ERROR_STREAM_CLOSED;
    }
    if (frame->stream_id == payload.priority.dependency) {
        *err_desc = "stream cannot depend on itself";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if (conn->state >= H2O_HTTP2_CONN_STATE_HALF_CLOSED)
        return 0;

    /* open or determine the stream and prepare */
    if ((stream = conn->get_stream(frame->stream_id)) != NULL) {
        if ((frame->flags & H2O_HTTP2_FRAME_FLAG_PRIORITY) != 0)
            set_priority(conn, stream, &payload.priority, 1);
    } else {
        stream = h2o_http2_stream_open(conn, frame->stream_id, NULL);
        set_priority(conn, stream, &payload.priority, 0);
    }
    conn->prepare_for_request(stream);

    /* setup container for request body if it is expected to arrive */
    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_STREAM) == 0)
        h2o_buffer_init(&stream->_req_body, &h2o_socket_buffer_prototype);

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0) {
        /* request is complete, handle it */
        return handle_incoming_request(conn, stream, payload.headers, payload.headers_len, err_desc);
    }

PREPARE_FOR_CONTINUATION:
    /* request is not complete, store in buffer */
    conn->_read_expect = expect_continuation_of_headers;
    h2o_buffer_init(&conn->_headers_unparsed, &h2o_socket_buffer_prototype);
    h2o_buffer_append(&conn->_headers_unparsed, payload.headers, payload.headers_len);
    return 0;
}

static int handle_priority_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_priority_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_priority_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (frame->stream_id == payload.dependency) {
        *err_desc = "stream cannot depend on itself";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if ((stream = conn->get_stream(frame->stream_id)) != NULL) {
        /* ignore priority changes to pushed streams with weight=257, since that is where we are trying to be smarter than the web
         * browsers
         */
        if (h2o_http2_scheduler_get_weight(&stream->_refs.scheduler) != 257)
            set_priority(conn, stream, &payload, 1);
    } else {
        if (conn->num_streams.priority.open >= conn->super.ctx->globalconf->http2.max_streams_for_priority) {
            *err_desc = "too many streams in idle/closed state";
            /* RFC 7540 10.5: An endpoint MAY treat activity that is suspicious as a connection error (Section 5.4.1) of type
             * ENHANCE_YOUR_CALM.
             */
            return H2O_HTTP2_ERROR_ENHANCE_YOUR_CALM;
        }
        stream = h2o_http2_stream_open(conn, frame->stream_id, NULL);
        set_priority(conn, stream, &payload, 0);
    }

    return 0;
}

static void resume_send(h2o_http2_conn_t *conn)
{
    if (conn->get_buffer_window() <= 0)
        return;
#if 0 /* TODO reenable this check for performance? */
    if (conn->scheduler.list.size == 0)
        return;
#endif
    conn->request_gathered_write();
}

static int handle_settings_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    if (frame->stream_id != 0) {
        *err_desc = "invalid stream id in SETTINGS frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_ACK) != 0) {
        if (frame->length != 0) {
            *err_desc = "invalid SETTINGS frame (+ACK)";
            return H2O_HTTP2_ERROR_FRAME_SIZE;
        }
    } else {
        uint32_t prev_initial_window_size = conn->peer_settings.initial_window_size;
        /* FIXME handle SETTINGS_HEADER_TABLE_SIZE */
        int ret = h2o_http2_update_peer_settings(&conn->peer_settings, frame->payload, frame->length, err_desc);
        if (ret != 0)
            return ret;
        { /* schedule ack */
            h2o_iovec_t header_buf = h2o_buffer_reserve_resize(&conn->_write.buf, H2O_HTTP2_FRAME_HEADER_SIZE);
            h2o_http2_encode_frame_header((uint8_t *)header_buf.base, 0, H2O_HTTP2_FRAME_TYPE_SETTINGS, H2O_HTTP2_FRAME_FLAG_ACK, 0);
            conn->request_write();
        }
        /* apply the change to window size (to all the streams but not the connection, see 6.9.2 of draft-15) */
        if (prev_initial_window_size != conn->peer_settings.initial_window_size) {
            ssize_t delta = conn->peer_settings.initial_window_size - prev_initial_window_size;
            h2o_http2_stream_t *stream;
            kh_foreach_value(conn->streams, stream, { update_stream_output_window(stream, delta); });
            resume_send(conn);
        }
    }

    return 0;
}

static int handle_window_update_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_window_update_payload_t payload;
    int ret, err_is_stream_level;

    if ((ret = h2o_http2_decode_window_update_payload(&payload, frame, err_desc, &err_is_stream_level)) != 0) {
        if (err_is_stream_level) {
            h2o_http2_stream_t *stream = conn->get_stream(frame->stream_id);
            if (stream != NULL)
                conn->stream_reset(stream);
            send_stream_error(conn, frame->stream_id, ret);
            return 0;
        } else {
            return ret;
        }
    }

    if (frame->stream_id == 0) {
        if (conn->_write.window.update(payload.window_size_increment) != 0) {
            *err_desc = "flow control window overflow";
            return H2O_HTTP2_ERROR_FLOW_CONTROL;
        }
    } else if (!conn->is_idle_stream_id(frame->stream_id)) {
        h2o_http2_stream_t *stream = conn->get_stream(frame->stream_id);
        if (stream != NULL) {
            if (update_stream_output_window(stream, payload.window_size_increment) != 0) {
                conn->stream_reset(stream);
                send_stream_error(conn, frame->stream_id, H2O_HTTP2_ERROR_FLOW_CONTROL);
                return 0;
            }
        }
    } else {
        *err_desc = "invalid stream id in WINDOW_UPDATE frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    resume_send(conn);

    return 0;
}

static int handle_goaway_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_goaway_payload_t payload;
    int ret;

    if ((ret = h2o_http2_decode_goaway_payload(&payload, frame, err_desc)) != 0)
        return ret;

    /* nothing to do, since we do not open new streams by ourselves */
    return 0;
}

static int handle_ping_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_ping_payload_t payload;
    int ret;

    if ((ret = h2o_http2_decode_ping_payload(&payload, frame, err_desc)) != 0)
        return ret;

    h2o_http2_encode_ping_frame(&conn->_write.buf, 1, payload.data);
    conn->request_write();

    return 0;
}

static int handle_rst_stream_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    h2o_http2_rst_stream_payload_t payload;
    h2o_http2_stream_t *stream;
    int ret;

    if ((ret = h2o_http2_decode_rst_stream_payload(&payload, frame, err_desc)) != 0)
        return ret;
    if (conn->is_idle_stream_id(frame->stream_id)) {
        *err_desc = "unexpected stream id in RST_STREAM frame";
        return H2O_HTTP2_ERROR_PROTOCOL;
    }

    stream = conn->get_stream(frame->stream_id);
    if (stream != NULL) {
        /* reset the stream */
        conn->stream_reset(stream);
    }
    /* TODO log */

    return 0;
}

static int handle_push_promise_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received PUSH_PROMISE frame";
    return H2O_HTTP2_ERROR_PROTOCOL;
}

static int handle_invalid_continuation_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc)
{
    *err_desc = "received invalid CONTINUATION frame";
    return H2O_HTTP2_ERROR_PROTOCOL;
}

ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    static int (*FRAME_HANDLERS[])(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame, const char **err_desc) = {
        handle_data_frame,                /* DATA */
        handle_headers_frame,             /* HEADERS */
        handle_priority_frame,            /* PRIORITY */
        handle_rst_stream_frame,          /* RST_STREAM */
        handle_settings_frame,            /* SETTINGS */
        handle_push_promise_frame,        /* PUSH_PROMISE */
        handle_ping_frame,                /* PING */
        handle_goaway_frame,              /* GOAWAY */
        handle_window_update_frame,       /* WINDOW_UPDATE */
        handle_invalid_continuation_frame /* CONTINUATION */
    };

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &H2O_HTTP2_SETTINGS_HOST, err_desc)) < 0)
        return ret;

    if (frame.type < sizeof(FRAME_HANDLERS) / sizeof(FRAME_HANDLERS[0])) {
        int hret = FRAME_HANDLERS[frame.type](conn, &frame, err_desc);
        if (hret != 0)
            ret = hret;
    } else {
        fprintf(stderr, "skipping frame (type:%d)\n", frame.type);
    }

    return ret;
}

static ssize_t expect_preface(h2o_http2_conn_t *conn, const uint8_t *src, size_t len, const char **err_desc)
{
    if (len < CONNECTION_PREFACE.len) {
        return H2O_HTTP2_ERROR_INCOMPLETE;
    }
    if (memcmp(src, CONNECTION_PREFACE.base, CONNECTION_PREFACE.len) != 0) {
        return H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY;
    }

    { /* send SETTINGS */
        h2o_buffer_append(&conn->_write.buf, SETTINGS_HOST_BIN.base, SETTINGS_HOST_BIN.len);
        conn->request_write();
    }

    conn->_read_expect = expect_default;
    return CONNECTION_PREFACE.len;
}

static void parse_input(h2o_http2_conn_t *conn)
{
    size_t http2_max_concurrent_requests_per_connection = conn->super.ctx->globalconf->http2.max_concurrent_requests_per_connection;
    int perform_early_exit = 0;

    if (conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed != http2_max_concurrent_requests_per_connection)
        perform_early_exit = 1;

    /* handle the input */
    while (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING && conn->sock->input->size != 0) {
        if (perform_early_exit == 1 &&
            conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed == http2_max_concurrent_requests_per_connection)
            goto EarlyExit;
        /* process a frame */
        const char *err_desc = NULL;
        ssize_t ret = conn->_read_expect(conn, (uint8_t *)conn->sock->input->bytes, conn->sock->input->size, &err_desc);
        if (ret == H2O_HTTP2_ERROR_INCOMPLETE) {
            break;
        } else if (ret < 0) {
            if (ret != H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY) {
                enqueue_goaway(conn, (int)ret,
                               err_desc != NULL ? (h2o_iovec_t){(char *)err_desc, strlen(err_desc)} : (h2o_iovec_t){});
            }
            close_connection(conn);
            return;
        }
        /* advance to the next frame */
        h2o_buffer_consume(&conn->sock->input, ret);
    }

    if (!conn->sock->is_reading())
        conn->sock->read_start(on_read);
    return;

EarlyExit:
    if (conn->sock->is_reading())
        conn->sock->read_stop();
}

static void on_read(h2o_socket_t *sock, int status)
{
    auto conn = (h2o_http2_conn_t*)sock->data;

    if (status != 0) {
        conn->sock->read_stop();
        close_connection(conn);
        return;
    }

    update_idle_timeout(conn);
    parse_input(conn);

    /* write immediately, if there is no write in flight and if pending write exists */
    if (conn->_write.timeout_entry.is_linked()) {
        conn->_write.timeout_entry.unlink();
        do_emit_writereq(conn);
    }
}

static void on_upgrade_complete(void *_conn, h2o_socket_t *sock, size_t reqsize)
{
    auto conn = (h2o_http2_conn_t*)_conn;

    if (sock == NULL) {
        close_connection(conn);
        return;
    }

    conn->sock = sock;
    sock->data = conn;
    conn->_http1_req_input = sock->input;
    h2o_buffer_init(&sock->input, &h2o_socket_buffer_prototype);

    /* setup inbound */
    conn->sock->read_start(on_read);

    /* handle the request */
    execute_or_enqueue_request(conn, conn->get_stream(1));

    if (conn->_http1_req_input->size != reqsize) {
        /* FIXME copy the remaining data to conn->_input and call handle_input */
        assert(0);
    }
}

void h2o_http2_conn_register_for_proceed_callback(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    conn->request_write();

    if (stream->has_pending_data() || stream->state >= H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL) {
        if (stream->output_window.get() > 0) {
            assert(!stream->_refs.link.is_linked());
            h2o_http2_scheduler_activate(&stream->_refs.scheduler);
        }
    } else {
        conn->_write.streams_to_proceed.insert(&stream->_refs.link);
    }
}

static void on_write_complete(h2o_socket_t *sock, int status)
{
    auto conn = (h2o_http2_conn_t*)sock->data;

    assert(conn->_write.buf_in_flight != NULL);

    /* close by error if necessary */
    if (status != 0) {
        close_connection_now(conn);
        return;
    }

    /* reset the other memory pool */
    h2o_buffer_dispose(&conn->_write.buf_in_flight);
    assert(conn->_write.buf_in_flight == NULL);

    /* call the proceed callback of the streams that have been flushed (while unlinking them from the list) */
    if (status == 0 && conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING) {
        while (!conn->_write.streams_to_proceed.is_empty()) {
            auto stream =
                H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.link, conn->_write.streams_to_proceed.next);
            assert(!stream->has_pending_data());
            stream->_refs.link.unlink();
            h2o_http2_stream_proceed(conn, stream);
        }
    }

    /* cancel the write callback if scheduled (as the generator may have scheduled a write just before this function gets called) */
    conn->_write.timeout_entry.unlink();

    /* write more, if possible */
    if (do_emit_writereq(conn))
        return;

    /* close the connection if necessary */
    switch (conn->state) {
    case H2O_HTTP2_CONN_STATE_OPEN:
        break;
    case H2O_HTTP2_CONN_STATE_HALF_CLOSED:
        if (conn->num_streams.pull.half_closed + conn->num_streams.push.half_closed != 0)
            break;
        conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;
    /* fall-thru */
    case H2O_HTTP2_CONN_STATE_IS_CLOSING:
        close_connection_now(conn);
        return;
    }

    /* start receiving input if necessary, as well as parse the pending input */
    if (conn->sock->input->size != 0)
        parse_input(conn);
}

static int emit_writereq_of_openref(h2o_http2_scheduler_openref_t *ref, int *still_is_active, void *cb_arg)
{
    auto conn = (h2o_http2_conn_t*)cb_arg;
    auto stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _refs.scheduler, ref);

    assert(stream->has_pending_data() || stream->state >= H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL);

    *still_is_active = 0;

    h2o_http2_stream_send_pending_data(conn, stream);
    if (stream->has_pending_data()) {
        if (stream->output_window.get() <= 0) {
            /* is blocked */
        } else {
            *still_is_active = 1;
        }
    } else {
        conn->_write.streams_to_proceed.insert(&stream->_refs.link);
    }

    return conn->get_buffer_window() > 0 ? 0 : -1;
}

int do_emit_writereq(h2o_http2_conn_t *conn)
{
    assert(conn->_write.buf_in_flight == NULL);

    /* push DATA frames */
    if (conn->state < H2O_HTTP2_CONN_STATE_IS_CLOSING && conn->get_buffer_window() > 0)
        h2o_http2_scheduler_run(&conn->scheduler, emit_writereq_of_openref, conn);

    if (conn->_write.buf->size == 0)
        return 0;

    { /* write */
        h2o_iovec_t buf = {conn->_write.buf->bytes, conn->_write.buf->size};
        conn->sock->write(&buf, 1, on_write_complete);
        conn->_write.buf_in_flight = conn->_write.buf;
        h2o_buffer_init(&conn->_write.buf, &wbuf_buffer_prototype);
    }
    return 1;
}

static void emit_writereq(h2o_timeout_entry_t *entry)
{
    auto conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _write.timeout_entry, entry);

    do_emit_writereq(conn);
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    auto conn = (h2o_http2_conn_t *)_conn;
    return h2o_socket_getsockname(conn->sock, sa);
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    auto conn = (h2o_http2_conn_t *)_conn;
    return conn->sock->getpeername(sa);
}

static h2o_http2_conn_t *create_conn(h2o_context_t *ctx, h2o_hostconf_t **hosts, h2o_socket_t *sock, struct timeval connected_at)
{
    static const h2o_conn_callbacks_t callbacks = {get_sockname, get_peername, push_path};
    auto conn = h2o_mem_alloc_for<h2o_http2_conn_t>();

    /* init the connection */
    h2o_clearmem(conn);
    conn->super.ctx = ctx;
    conn->super.hosts = hosts;
    conn->super.connected_at = connected_at;
    conn->super.callbacks = &callbacks;
    conn->sock = sock;
    conn->peer_settings = H2O_HTTP2_SETTINGS_DEFAULT;
    conn->streams = kh_init(h2o_http2_stream_t);
    h2o_http2_scheduler_init(&conn->scheduler);
    conn->state = H2O_HTTP2_CONN_STATE_OPEN;
    ctx->http2._conns.insert(&conn->_conns);
    conn->_read_expect = expect_preface;
    conn->_input_header_table.hpack_capacity = conn->_input_header_table.hpack_max_capacity =
        H2O_HTTP2_SETTINGS_DEFAULT.header_table_size;
    conn->_input_window.init(&H2O_HTTP2_SETTINGS_DEFAULT);
    conn->_output_header_table.hpack_capacity = H2O_HTTP2_SETTINGS_HOST.header_table_size;
    conn->_pending_reqs.init_anchor();
    h2o_buffer_init(&conn->_write.buf, &wbuf_buffer_prototype);
    conn->_write.streams_to_proceed.init_anchor();
    conn->_write.timeout_entry.cb = emit_writereq;
    conn->_write.window.init(&conn->peer_settings);

    return conn;
}

static void push_path(h2o_req_t *src_req, const char *abspath, size_t abspath_len)
{
    auto conn = (h2o_http2_conn_t *)src_req->conn;
    auto src_stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, req, src_req);

    if (!conn->peer_settings.enable_push || conn->num_streams.push.open >= conn->peer_settings.max_concurrent_streams)
        return;
    if (conn->push_stream_ids.max_open >= 0x7ffffff0)
        return;
    if (!(conn->_pending_reqs.is_empty() && can_run_requests(conn)))
        return;

    /* casper-related code */
    if (src_stream->req.hostconf->http2.casper.capacity_bits != 0 && !conn->is_push(src_stream->stream_id)) {
        size_t header_index;
        switch (src_stream->pull.casper_state) {
        case H2O_HTTP2_STREAM_CASPER_STATE_TBD:
            /* disable casper for this request if intermediary exists */
            if (src_stream->req.headers.find(H2O_TOKEN_X_FORWARDED_FOR, -1) != -1) {
                src_stream->pull.casper_state = H2O_HTTP2_STREAM_CASPER_DISABLED;
                return;
            }
            /* casper enabled for this request */
            if (conn->casper == NULL)
                conn->init_casper(src_stream->req.hostconf->http2.casper.capacity_bits);
            /* consume casper cookie */
            for (header_index = -1;
                 (header_index = src_stream->req.headers.find(H2O_TOKEN_COOKIE, header_index)) != -1;) {
                auto header = src_stream->req.headers[header_index];
                conn->casper->consume_cookie(header.value.base, header.value.len);
            }
            src_stream->pull.casper_state = H2O_HTTP2_STREAM_CASPER_READY;
        case H2O_HTTP2_STREAM_CASPER_READY:
            break;
        case H2O_HTTP2_STREAM_CASPER_DISABLED:
            return;
        }
    }

    /* open the stream */
    conn->push_stream_ids.max_open += 2;
    h2o_http2_stream_t *stream = h2o_http2_stream_open(conn, conn->push_stream_ids.max_open, NULL);
    stream->push.parent_stream_id = src_stream->stream_id;
    h2o_http2_scheduler_open(&stream->_refs.scheduler, &src_stream->_refs.scheduler.node, 16, 0);
    conn->prepare_for_request(stream);

    /* setup request */
    stream->req.input.method = (h2o_iovec_t){H2O_STRLIT("GET")};
    stream->req.input.scheme = src_stream->req.input.scheme;
    stream->req.input.authority.strdup(&stream->req.pool, src_stream->req.input.authority);
    stream->req.input.path.strdup(&stream->req.pool, abspath, abspath_len);
    stream->req.version = 0x200;

    { /* copy headers that may affect the response (of a cacheable response) */
        size_t i;
        for (i = 0; i != src_stream->req.headers.size; ++i) {
            auto src_header = src_stream->req.headers[i];
            if (h2o_iovec_is_token(src_header.name)) {
                auto token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, src_header.name);
                if (token->copy_for_push_request) {
                    stream->req.headers.add(&stream->req.pool, token,
                                   h2o_strdup(&stream->req.pool, src_header.value.base, src_header.value.len));
                }
            }
        }
    }

    execute_or_enqueue_request(conn, stream);

    /* send push-promise ASAP (before the parent stream gets closed), even if execute_or_enqueue_request did not trigger the
     * invocation of send_headers */
    if (!stream->push.promise_sent && stream->state != H2O_HTTP2_STREAM_STATE_END_STREAM)
        conn->send_push_promise(stream);
}

void h2o_http2_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    h2o_http2_conn_t *conn = create_conn(ctx->ctx, ctx->hosts, sock, connected_at);
    sock->data = conn;
    conn->sock->read_start(on_read);
    update_idle_timeout(conn);
    if (sock->input->size != 0)
        on_read(sock, 0);
}

int h2o_http2_handle_upgrade(h2o_req_t *req, struct timeval connected_at)
{
    h2o_http2_conn_t *http2conn = create_conn(req->conn->ctx, req->conn->hosts, NULL, connected_at);
    h2o_http2_stream_t *stream;
    ssize_t connection_index, settings_index;
    h2o_iovec_t settings_decoded;
    const char *err_desc;

    assert(req->version < 0x200); /* from HTTP/1.x */

    /* check that "HTTP2-Settings" is declared in the connection header */
    connection_index = req->headers.find(H2O_TOKEN_CONNECTION, -1);
    assert(connection_index != -1);
    if (!h2o_contains_token(req->headers[connection_index].value.base, req->headers[connection_index].value.len,
                            H2O_STRLIT("http2-settings"), ',')) {
        goto Error;
    }

    /* decode the settings */
    if ((settings_index = req->headers.find(H2O_TOKEN_HTTP2_SETTINGS, -1)) == -1) {
        goto Error;
    }
    if ((settings_decoded = h2o_decode_base64url(&req->pool, req->headers[settings_index].value)).base == NULL) {
        goto Error;
    }
    if (h2o_http2_update_peer_settings(&http2conn->peer_settings, (uint8_t *)settings_decoded.base, settings_decoded.len,
                                       &err_desc) != 0) {
        goto Error;
    }

    /* open the stream, now that the function is guaranteed to succeed */
    stream = h2o_http2_stream_open(http2conn, 1, req);
    h2o_http2_scheduler_open(&stream->_refs.scheduler, &http2conn->scheduler, h2o_http2_default_priority.weight, 0);
    http2conn->prepare_for_request(stream);

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    req->addResponseHeader(H2O_TOKEN_UPGRADE, H2O_STRLIT("h2c"));
    h2o_http1_upgrade(req, (h2o_iovec_t *)&SETTINGS_HOST_BIN, 1, on_upgrade_complete, http2conn);

    return 0;
Error:
    h2o_mem_free(http2conn);
    return -1;
}
