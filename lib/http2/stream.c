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
#include "h2o.h"
#include "h2o/http2.h"
#include "h2o/http2_internal.h"

static void finalostream_start_pull(h2o_ostream_t *self, h2o_ostream_pull_cb cb);
static void finalostream_send(h2o_ostream_t *self, h2o_req_t *req,
        h2o_iovec_t *bufs, size_t bufcnt, int is_final);

static size_t sz_min(size_t x, size_t y)
{
    return x < y ? x : y;
}

h2o_http2_stream_t *h2o_http2_stream_open(h2o_http2_conn_t *conn, uint32_t stream_id, h2o_req_t *src_req,
                                          const h2o_http2_priority_t *received_priority)
{
    auto stream = h2o_mem_calloc_for<h2o_http2_stream_t>();

    /* init properties (other than req) */
    //memset(stream, 0, offsetof(h2o_http2_stream_t, req));
    stream->stream_id = stream_id;
    stream->_ostr_final.do_send = finalostream_send;
    stream->_ostr_final.start_pull = finalostream_start_pull;
    stream->state = H2O_HTTP2_STREAM_STATE_IDLE;
    stream->output_window.init(&conn->peer_settings);
    stream->input_window.init(&H2O_HTTP2_SETTINGS_HOST);
    stream->received_priority = *received_priority;
    stream->_expected_content_length = SIZE_MAX;

    /* init request */
    h2o_req_t::init(&stream->req, &conn->super, src_req);
    stream->req.version = 0x200;
    if (src_req != NULL)
        h2o_clearmem(&stream->req.upgrade);
    stream->req._ostr_top = &stream->_ostr_final;

    h2o_http2_conn_register_stream(conn, stream);

    ++conn->num_streams.priority.open;
    stream->_num_streams_slot = &conn->num_streams.priority;

    return stream;
}

void h2o_http2_stream_close(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    h2o_http2_conn_unregister_stream(conn, stream);
    if (stream->_req_body != NULL)
        h2o_buffer_dispose(&stream->_req_body);
    h2o_req_t::dispose(&stream->req);
    if (stream->stream_id == 1 && conn->_http1_req_input != NULL)
        h2o_buffer_dispose(&conn->_http1_req_input);
    h2o_mem_free(stream);
}

void h2o_http2_conn_t::stream_reset(h2o_http2_stream_t *stream)
{
    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_IDLE:
    case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
    case H2O_HTTP2_STREAM_STATE_RECV_BODY:
    case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        h2o_http2_stream_close(this, stream);
        break;
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
    case H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
        this->set_state(stream, H2O_HTTP2_STREAM_STATE_END_STREAM);
    /* continues */
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        /* clear all the queued bufs, and close the connection in the callback */
        stream->_data.size = 0;
        if (stream->_refs.link.is_linked()) {
            /* will be closed in the callback */
        } else {
            h2o_http2_stream_close(this, stream);
        }
        break;
    }
}

static size_t calc_max_payload_size(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    ssize_t conn_max, stream_max;

    if ((conn_max = conn->get_buffer_window()) <= 0)
        return 0;
    if ((stream_max = stream->output_window.get()) <= 0)
        return 0;
    return sz_min(sz_min(conn_max, stream_max), conn->peer_settings.max_frame_size);
}

static void encode_data_header_and_consume_window(h2o_http2_conn_t *conn,
        h2o_http2_stream_t *stream, uint8_t *header, size_t length, int eos)
{
    assert(header != NULL);
    h2o_http2_encode_frame_header(header, length, H2O_HTTP2_FRAME_TYPE_DATA,
            eos ? H2O_HTTP2_FRAME_FLAG_END_STREAM : 0, stream->stream_id);
    conn->_write.window.consume(length);
    stream->output_window.consume(length);
}

static int send_data_pull(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    size_t max_payload_size;
    h2o_iovec_t cbuf;
    int is_final = 0;

    if ((max_payload_size = calc_max_payload_size(conn, stream)) == 0)
        goto Exit;
    /* reserve buffer */
    h2o_buffer_reserve(&conn->_write.buf, H2O_HTTP2_FRAME_HEADER_SIZE + max_payload_size);
    /* obtain content */
    cbuf.base = conn->_write.buf->bytes + conn->_write.buf->size + H2O_HTTP2_FRAME_HEADER_SIZE;
    cbuf.len = max_payload_size;
    is_final = stream->req.pull(stream->_pull_cb, &cbuf);
    /* write the header */
    encode_data_header_and_consume_window(conn, stream,
            (uint8_t*)(conn->_write.buf->bytes + conn->_write.buf->size), cbuf.len,
                                          is_final);
    /* adjust the write buf size */
    conn->_write.buf->size += H2O_HTTP2_FRAME_HEADER_SIZE + cbuf.len;

Exit:
    return is_final;
}

static h2o_iovec_t *send_data_push(h2o_http2_conn_t *conn,
        h2o_http2_stream_t *stream, h2o_iovec_t *bufs, size_t bufcnt,
        int is_final)
{
    h2o_iovec_t dst;
    size_t max_payload_size;

    if ((max_payload_size = calc_max_payload_size(conn, stream)) == 0)
        goto Exit;

    /* reserve buffer and point dst to the payload */
    dst.base =
        h2o_buffer_reserve(&conn->_write.buf, H2O_HTTP2_FRAME_HEADER_SIZE +
            max_payload_size).base + H2O_HTTP2_FRAME_HEADER_SIZE;
    dst.len = max_payload_size;

    /* emit data */
    while (bufcnt != 0) {
        if (bufs->len != 0)
            break;
        ++bufs;
        --bufcnt;
    }
    while (bufcnt != 0) {
        size_t fill_size = sz_min(dst.len, bufs->len);
        memcpy(dst.base, bufs->base, fill_size);
        dst.base += fill_size;
        dst.len -= fill_size;
        bufs->base += fill_size;
        bufs->len -= fill_size;
        while (bufs->len == 0) {
            ++bufs;
            --bufcnt;
            if (bufcnt == 0)
                break;
        }
        if (dst.len == 0)
            break;
    }

    /* commit the DATA frame if we have actually emitted payload */
    if (dst.len != max_payload_size || is_final) {
        size_t payload_len = max_payload_size - dst.len;
        encode_data_header_and_consume_window(conn, stream,
                (uint8_t *)conn->_write.buf->bytes + conn->_write.buf->size,
                payload_len, is_final && bufcnt == 0);
        conn->_write.buf->size += H2O_HTTP2_FRAME_HEADER_SIZE + payload_len;
    }

Exit:
    return bufs;
}

static int is_blocking_asset(h2o_req_t *req)
{
    if (req->res.mime_attr == NULL)
        req->fill_mime_attributes();
    return req->res.mime_attr->priority == H2O_MIME_ATTRIBUTE_PRIORITY_HIGHEST;
}

static int send_headers(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    h2o_timestamp_t ts;
    h2o_iovec_t cookie;

    stream->req.get_timestamp(&ts);

    /* cancel push with an error response */
    if (conn->is_push(stream->stream_id)) {
        if (400 <= stream->req.res.status)
            goto CancelPush;
    }

    /* CASPER */
    if (conn->casper != NULL) {
        /* update casper if necessary */
        if (stream->req.hostconf->http2.casper.track_all_types || is_blocking_asset(&stream->req)) {
            ssize_t etag_index = stream->req.headers.find(H2O_TOKEN_ETAG, -1);
            h2o_iovec_t etag = etag_index != -1 ? stream->req.headers[etag_index].value : h2o_iovec_t({});
            if (conn->casper->lookup(stream->req.path.base, stream->req.path.len, etag.base, etag.len, 1)) {
                /* cancel if the pushed resource is already marked as cached */
                if (conn->is_push(stream->stream_id))
                    goto CancelPush;
            }
        }
        /* browsers might ignore push responses, or they may process the responses in a different order than they were pushed.
         * Therefore H2O tries to include casper cookie only in the last stream that may be received by the client, or when the
         * value become stable; see also: https://github.com/h2o/h2o/issues/421
         */
        if (conn->is_push(stream->stream_id)) {
            if (!(conn->num_streams.pull.open == 0 && (conn->num_streams.push.half_closed - conn->num_streams.push.send_body) == 1))
                goto SkipCookie;
        } else {
            if (conn->num_streams.push.half_closed - conn->num_streams.push.send_body != 0)
                goto SkipCookie;
        }
        cookie = conn->casper->get_cookie();
        stream->req.res.headers.add(&stream->req.pool, H2O_TOKEN_SET_COOKIE, cookie.base, cookie.len);
    SkipCookie:
        ;
    }

    if (conn->is_push(stream->stream_id)) {
        /* for push, send the push promise */
        if (!stream->push.promise_sent)
            conn->send_push_promise(stream);
        /* send ASAP if it is a blocking asset (even in case of Firefox we can't wait 1RTT for it to reprioritize the asset) */
        if (is_blocking_asset(&stream->req))
            h2o_http2_scheduler_rebind(&stream->_refs.scheduler, &conn->scheduler, 257, 0);
    } else {
        /* raise the priority of asset files that block rendering to highest if the user-agent is _not_ using dependency-based
         * prioritization (e.g. that of Firefox)
         */
        if (conn->num_streams.priority.open == 0 && stream->req.hostconf->http2.reprioritize_blocking_assets &&
            h2o_http2_scheduler_get_parent(&stream->_refs.scheduler) == &conn->scheduler && is_blocking_asset(&stream->req))
            h2o_http2_scheduler_rebind(&stream->_refs.scheduler, &conn->scheduler, 257, 0);
    }

    /* send HEADERS, as well as start sending body */
    if (conn->is_push(stream->stream_id))
        stream->req.res.headers.add(&stream->req.pool, H2O_STRLIT("x-http2-push"), 0, H2O_STRLIT("pushed"));
    h2o_hpack_flatten_response(&conn->_write.buf, &conn->_output_header_table, stream->stream_id,
                               conn->peer_settings.max_frame_size, &stream->req.res, &ts, &conn->super.ctx->globalconf->server_name,
                               stream->req.res.content_length);
    conn->request_write();
    conn->set_state(stream, H2O_HTTP2_STREAM_STATE_SEND_BODY);

    return 0;

CancelPush:
    stream->req.res.headers.add(&stream->req.pool, H2O_STRLIT("x-http2-push"), 0, H2O_STRLIT("cancelled"));
    conn->set_state(stream, H2O_HTTP2_STREAM_STATE_END_STREAM);
    conn->_write.streams_to_proceed.insert(&stream->_refs.link);
    if (stream->push.promise_sent) {
        h2o_http2_encode_rst_stream_frame(&conn->_write.buf, stream->stream_id, H2O_HTTP2_ERROR_INTERNAL);
        conn->request_write();
    }
    return -1;
}

void finalostream_start_pull(h2o_ostream_t *self, h2o_ostream_pull_cb cb)
{
    auto stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _ostr_final, self);
    auto conn = (h2o_http2_conn_t *)stream->req.conn;

    assert(stream->req._ostr_top == &stream->_ostr_final);
    assert(stream->state == H2O_HTTP2_STREAM_STATE_SEND_HEADERS);

    /* register the pull callback */
    stream->_pull_cb = cb;

    /* send headers */
    if (send_headers(conn, stream) != 0)
        return;

    /* set dummy data in the send buffer */
    stream->_data.reserve_more(&stream->req.pool, 1);
    stream->_data.entries[0].base = (char*)"<pull interface>";
    stream->_data.entries[0].len = 1;
    stream->_data.size = 1;

    h2o_http2_conn_register_for_proceed_callback(conn, stream);
}

void finalostream_send(h2o_ostream_t *self, h2o_req_t *req, h2o_iovec_t *bufs, size_t bufcnt, int is_final)
{
    auto stream = H2O_STRUCT_FROM_MEMBER(h2o_http2_stream_t, _ostr_final, self);
    auto conn = (h2o_http2_conn_t *)stream->req.conn;

    assert(stream->_data.size == 0);

    /* send headers */
    switch (stream->state) {
    case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
        if (send_headers(conn, stream) != 0)
            return;
    /* fallthru */
    case H2O_HTTP2_STREAM_STATE_SEND_BODY:
        if (is_final)
            conn->set_state(stream, H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL);
        break;
    case H2O_HTTP2_STREAM_STATE_END_STREAM:
        /* might get set by h2o_http2_stream_reset */
        return;
    default:
        assert(!"cannot be in a receiving state");
    }

    /* save the contents in queue */
    if (bufcnt != 0) {
        stream->_data.assign_elements(&req->pool, bufs, bufcnt);
    }

    h2o_http2_conn_register_for_proceed_callback(conn, stream);
}

void h2o_http2_stream_send_pending_data(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    if (stream->output_window.get() <= 0)
        return;

    if (stream->_pull_cb != NULL) {
        /* pull mode */
        assert(stream->state != H2O_HTTP2_STREAM_STATE_END_STREAM);
        if (send_data_pull(conn, stream)) {
            /* sent all data */
            stream->_data.size = 0;
            conn->set_state(stream, H2O_HTTP2_STREAM_STATE_END_STREAM);
        }
    } else {
        /* push mode */
        h2o_iovec_t *nextbuf = send_data_push(conn, stream, stream->_data.entries, stream->_data.size,
                                              stream->state >= H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL);
        if (nextbuf == stream->_data.entries + stream->_data.size) {
            /* sent all data */
            stream->_data.size = 0;
            if (stream->state == H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL)
                conn->set_state(stream, H2O_HTTP2_STREAM_STATE_END_STREAM);
        } else if (nextbuf != stream->_data.entries) {
            /* adjust the buffer */
            size_t newsize = stream->_data.size - (nextbuf - stream->_data.entries);
            memmove(stream->_data.entries, nextbuf, sizeof(h2o_iovec_t) * newsize);
            stream->_data.size = newsize;
        }
    }
}

void h2o_http2_stream_proceed(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    if (stream->state == H2O_HTTP2_STREAM_STATE_END_STREAM) {
        h2o_http2_stream_close(conn, stream);
    } else {
        stream->req.proceed_response();
    }
}
