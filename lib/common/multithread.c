/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd., Kazuho Oku, Tatsuhiko Kubo,
 *                         Chul-Woong Yang
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
#include <assert.h>
#include <pthread.h>
#include "cloexec.h"
#include "h2o/multithread.h"

struct h2o_multithread_queue_t {
#if H2O_USE_LIBUV
    uv_async_t async;
#else
    struct {
        int write;
        h2o_socket_t *read;
    } async;
#endif
    pthread_mutex_t mutex;
    struct {
        h2o_linklist_t active;
        h2o_linklist_t inactive;
    } receivers;
};

static void queue_cb(h2o_multithread_queue_t *queue)
{
    pthread_mutex_lock(&queue->mutex);

    while (!queue->receivers.active.is_empty()) {
        auto receiver =
            H2O_STRUCT_FROM_MEMBER(h2o_multithread_receiver_t, _link, queue->receivers.active.next);
        /* detach all the messages from the receiver */
        h2o_linklist_t messages;
        messages.init_anchor();
        messages.insert_list(&receiver->_messages);
        /* relink the receiver to the inactive list */
        receiver->_link.unlink();
        queue->receivers.inactive.insert(&receiver->_link);

        /* dispatch the messages */
        pthread_mutex_unlock(&queue->mutex);
        receiver->cb(receiver, &messages);
        assert(messages.is_empty());
        pthread_mutex_lock(&queue->mutex);
    }

    pthread_mutex_unlock(&queue->mutex);
}

#if H2O_USE_LIBUV
#else

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static void on_read(h2o_socket_t *sock, int status)
{
    if (status != 0) {
        fprintf(stderr, "pipe error\n");
        abort();
    }

    h2o_buffer_consume_all(&sock->input);
    queue_cb((h2o_multithread_queue_t*)sock->data);
}

static void init_async(h2o_multithread_queue_t *queue, h2o_loop_t *loop)
{
    int fds[2];

    if (cloexec_pipe(fds) != 0) {
        perror("pipe");
        abort();
    }
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
    queue->async.write = fds[1];
    queue->async.read = h2o_evloop_socket_create(loop, fds[0], 0);
    queue->async.read->data = queue;
    queue->async.read->read_start(on_read);
}

#endif

h2o_multithread_queue_t *h2o_multithread_create_queue(h2o_loop_t *loop)
{
    auto queue = h2o_mem_alloc_for<h2o_multithread_queue_t>();
    *queue = {};

#if H2O_USE_LIBUV
    uv_async_init(loop, &queue->async, (void *)queue_cb);
#else
    init_async(queue, loop);
#endif
    pthread_mutex_init(&queue->mutex, NULL);
    queue->receivers.active.init_anchor();
    queue->receivers.inactive.init_anchor();

    return queue;
}

void h2o_multithread_destroy_queue(h2o_multithread_queue_t *queue)
{
    assert(queue->receivers.active.is_empty());
    assert(queue->receivers.inactive.is_empty());
#if H2O_USE_LIBUV
    uv_close((uv_handle_t *)&queue->async, (void *)free);
#else
    queue->async.read->read_stop();
    h2o_socket_t::close(queue->async.read);
    close(queue->async.write);
#endif
    pthread_mutex_destroy(&queue->mutex);
}

void h2o_multithread_register_receiver(h2o_multithread_queue_t *queue, h2o_multithread_receiver_t *receiver,
                                       h2o_multithread_receiver_cb cb)
{
    receiver->queue = queue;
    receiver->_link = {};
    receiver->_messages.init_anchor();
    receiver->cb = cb;

    pthread_mutex_lock(&queue->mutex);
    queue->receivers.inactive.insert(&receiver->_link);
    pthread_mutex_unlock(&queue->mutex);
}

void h2o_multithread_unregister_receiver(h2o_multithread_queue_t *queue, h2o_multithread_receiver_t *receiver)
{
    assert(queue == receiver->queue);
    assert(receiver->_messages.is_empty());
    pthread_mutex_lock(&queue->mutex);
    receiver->_link.unlink();
    pthread_mutex_unlock(&queue->mutex);
}

void h2o_multithread_receiver_t::send_message(h2o_multithread_message_t *message)
{
    int do_send = 0;

    assert(!message->link.is_linked());

    pthread_mutex_lock(&this->queue->mutex);
    if (this->_messages.is_empty()) {
        this->_link.unlink();
        this->queue->receivers.active.insert(&this->_link);
        do_send = 1;
    }
    this->_messages.insert(&message->link);
    pthread_mutex_unlock(&this->queue->mutex);

    if (do_send) {
#if H2O_USE_LIBUV
        uv_async_send(&this->queue->async);
#else
        while (write(this->queue->async.write, "", 1) == -1 && errno == EINTR)
            ;
#endif
    }
}

void h2o_multithread_create_thread(pthread_t *tid, const pthread_attr_t *attr, void *(*func)(void *), void *arg)
{
    if (pthread_create(tid, attr, func, arg) != 0) {
        perror("pthread_create");
        abort();
    }
}
