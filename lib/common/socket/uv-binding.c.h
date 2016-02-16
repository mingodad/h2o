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

struct h2o_uv_socket_t {
    h2o_socket_t super;
    struct {
        uv_stream_t *stream;
        uv_close_cb close_cb;
    } uv;
    union {
        uv_connect_t _creq;
        uv_write_t _wreq;
    };
};

static void schedule_timer(h2o_timeout_t *timeout);

static void alloc_inbuf_tcp(uv_handle_t *handle, size_t suggested_size, uv_buf_t *_buf)
{
    auto sock = (h2o_uv_socket_t *)handle->data;

    h2o_iovec_t buf = h2o_buffer_reserve(&sock->super.input, 4096);
    memcpy(_buf, &buf, sizeof(buf));
}

static void alloc_inbuf_ssl(uv_handle_t *handle, size_t suggested_size, uv_buf_t *_buf)
{
    auto sock = (h2o_uv_socket_t *)handle->data;

    h2o_iovec_t buf = h2o_buffer_reserve(&sock->super.ssl->input.encrypted, 4096);
    memcpy(_buf, &buf, sizeof(buf));
}

static void on_read_tcp(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    auto sock = (h2o_uv_socket_t *)stream->data;

    if (nread < 0) {
        sock->super.bytes_read = 0;
        sock->super._cb.read(&sock->super, -1);
        return;
    }

    sock->super.input->size += nread;
    sock->super.bytes_read = nread;
    sock->super._cb.read(&sock->super, 0);
}

static void on_read_ssl(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    auto sock = (h2o_uv_socket_t *)stream->data;
    size_t prev_bytes_read = sock->super.input->size;
    int status = -1;

    if (nread > 0) {
        sock->super.ssl->input.encrypted->size += nread;
        if (sock->super.ssl->handshake.cb == NULL)
            status = decode_ssl_input(&sock->super);
        else
            status = 0;
    }
    sock->super.bytes_read = sock->super.input->size - prev_bytes_read;
    sock->super._cb.read(&sock->super, status);
}

static void on_do_write_complete(uv_write_t *wreq, int status)
{
    auto sock = H2O_STRUCT_FROM_MEMBER(struct h2o_uv_socket_t, _wreq, wreq);
    if (sock->super._cb.write != NULL)
        on_write_complete(&sock->super, status);
}

static void free_sock(uv_handle_t *handle)
{
    auto sock = (h2o_uv_socket_t *)handle->data;
    uv_close_cb cb = sock->uv.close_cb;
    free(sock);
    cb(handle);
}

void do_dispose_socket(h2o_socket_t *_sock)
{
    auto sock = (h2o_uv_socket_t *)_sock;
    uv_close((uv_handle_t *)sock->uv.stream, free_sock);
}

void do_read_start(h2o_socket_t *_sock)
{
    auto sock = (h2o_uv_socket_t *)_sock;

    if (sock->super.ssl == NULL)
        uv_read_start(sock->uv.stream, alloc_inbuf_tcp, on_read_tcp);
    else
        uv_read_start(sock->uv.stream, alloc_inbuf_ssl, on_read_ssl);
}

void do_read_stop(h2o_socket_t *_sock)
{
    auto sock = (h2o_uv_socket_t *)_sock;
    uv_read_stop(sock->uv.stream);
}

void do_write(h2o_socket_t *_sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    auto sock = (h2o_uv_socket_t *)_sock;

    assert(sock->super._cb.write == NULL);
    sock->super._cb.write = cb;

    uv_write(&sock->_wreq, sock->uv.stream, (uv_buf_t *)bufs, (int)bufcnt, on_do_write_complete);
}

static h2o_uv_socket_t *create_socket(h2o_loop_t *loop)
{
    auto tcp = h2o_mem_alloc_for<uv_tcp_t>();

    if (uv_tcp_init(loop, tcp) != 0) {
        h2o_mem_free(tcp);
        return NULL;
    }
    return (h2o_uv_socket_t *)h2o_uv_socket_create((uv_stream_t*)tcp, (uv_close_cb)h2o_mem_free);
}

int do_export(h2o_socket_t *_sock, h2o_socket_export_t *info)
{
    auto sock = (h2o_uv_socket_t *)_sock;
    uv_os_fd_t fd;

    if (uv_fileno((uv_handle_t *)sock->uv.stream, &fd) != 0)
        return -1;
    /* FIXME: consider how to overcome the epoll(2) problem; man says,
     * "even after a file descriptor that is part of an epoll set has been closed,
     * events may be reported for that file descriptor if other file descriptors
     * referring to the same underlying file description remain open"
     */
    if ((info->fd = dup(fd)) == -1)
        return -1;
    return 0;
}

h2o_socket_t *do_import(h2o_loop_t *loop, h2o_socket_export_t *info)
{
    auto sock = (h2o_uv_socket_t *)create_socket(loop);

    if (sock == NULL)
        return NULL;
    if (uv_tcp_open((uv_tcp_t *)sock->uv.stream, info->fd) != 0) {
        h2o_socket_t::close(&sock->super);
        return NULL;
    }

    return &sock->super;
}

h2o_socket_t *h2o_uv_socket_create(uv_stream_t *stream, uv_close_cb close_cb)
{
    auto sock = h2o_mem_calloc_for<h2o_uv_socket_t>();

    h2o_buffer_init(&sock->super.input, &h2o_socket_buffer_prototype);
    sock->uv.stream = stream;
    sock->uv.close_cb = close_cb;
    stream->data = sock;
    return &sock->super;
}

static void on_connect(uv_connect_t *conn, int status)
{
    auto sock = H2O_STRUCT_FROM_MEMBER(struct h2o_uv_socket_t, _creq, conn);
    h2o_socket_cb cb = sock->super._cb.write;
    sock->super._cb.write = NULL;
    cb(&sock->super, status);
}

h2o_loop_t *h2o_socket_get_loop(h2o_socket_t *_sock)
{
    auto sock = (h2o_uv_socket_t *)_sock;
    return sock->uv.stream->loop;
}

h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb)
{
    auto sock = (h2o_uv_socket_t *)create_socket(loop);

    if (sock == NULL)
        return NULL;
    if (uv_tcp_connect(&sock->_creq, (uv_tcp_t *)sock->uv.stream, addr, on_connect) != 0) {
        h2o_socket_t::close(&sock->super);
        return NULL;
    }
    sock->super._cb.write = cb;
    return &sock->super;
}

socklen_t h2o_socket_getsockname(h2o_socket_t *_sock, struct sockaddr *sa)
{
    auto sock = (h2o_uv_socket_t *)_sock;
    int len = sizeof(struct sockaddr_storage);
    if (uv_tcp_getsockname((uv_tcp_t *)sock->uv.stream, sa, &len) != 0)
        return 0;
    return (socklen_t)len;
}

socklen_t get_peername_uncached(h2o_socket_t *_sock, struct sockaddr *sa)
{
    auto sock = (h2o_uv_socket_t *)_sock;
    int len = sizeof(struct sockaddr_storage);
    if (uv_tcp_getpeername((uv_tcp_t *)sock->uv.stream, sa, &len) != 0)
        return 0;
    return (socklen_t)len;
}

static void on_timeout(uv_timer_t *timer)
{
    auto timeout = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _backend.timer, timer);

    timeout->run(timer->loop, h2o_now(timer->loop));
    if (!timeout->_entries.is_empty())
        schedule_timer(timeout);
}

void schedule_timer(h2o_timeout_t *timeout)
{
    auto entry = H2O_STRUCT_FROM_MEMBER(h2o_timeout_entry_t, _link, timeout->_entries.next);
    uv_timer_start(&timeout->_backend.timer, on_timeout,
                   entry->registered_at + timeout->timeout - h2o_now(timeout->_backend.timer.loop), 0);
}

void h2o_timeout__do_init(h2o_loop_t *loop, h2o_timeout_t *timeout)
{
    uv_timer_init(loop, &timeout->_backend.timer);
}

void h2o_timeout__do_dispose(h2o_loop_t *loop, h2o_timeout_t *timeout)
{
    uv_close((uv_handle_t *)&timeout->_backend.timer, NULL);
}

void h2o_timeout__do_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    /* register the timer if the entry just being added is the only entry */
    if (timeout->_entries.next == &entry->_link)
        schedule_timer(timeout);
}

void h2o_timeout__do_post_callback(h2o_loop_t *loop)
{
    /* nothing to do */
}
