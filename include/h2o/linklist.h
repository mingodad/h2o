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
#ifndef h2o__linklist_h
#define h2o__linklist_h

#if defined( __cplusplus) && !defined(__c_as_cpp)
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>

/**
 * linklist
 * The structure is used to represent both nodes and the head of the list.
 * Nodes should be zero-filled upon initialization.
 * Heads should be initialized by calling h2o_linklist_init_anchor.
 */
struct h2o_linklist_t {
    h2o_linklist_t *next;
    h2o_linklist_t *prev;

    /**
     * initializes the anchor (i.e. head) of a linked list
     */
    void init_anchor()
    {
        next = prev = this;
    }
    /**
     * tests if the list is empty
     */
    int is_empty()
    {
        return next == this;
    }
    /**
     * tests if the node is linked to a list
     */
    int is_linked()
    {
        return next != NULL;
    }
    /**
     * unlinks a node from the linked list
     */
    void unlink()
    {
        next->prev = prev;
        prev->next = next;
        next = prev = NULL;
    }
    /**
     * inserts a node to the linked list
     * @param pos insert position; the node will be inserted before pos
     * @param node the node to be inserted
     */
    void insert(h2o_linklist_t *node)
    {
        assert(!node->is_linked());

        node->prev = prev;
        node->next = this;
        node->prev->next = node;
        node->next->prev = node;
    }
    /**
     * inserts all the elements of list before pos (list becomes empty)
     */
    void insert_list(h2o_linklist_t *list)
    {
        if (list->is_empty())
            return;
        list->next->prev = prev;
        list->prev->next = this;
        prev->next = list->next;
        prev = list->prev;
        list->init_anchor();
    }
};

#if defined( __cplusplus) && !defined(__c_as_cpp)
}
#endif

#endif
