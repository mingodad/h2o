/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Justin Zhu
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
#ifndef h2o__memory_h
#define h2o__memory_h

#ifdef __sun__
#include <alloca.h>
#endif
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined( __cplusplus) && !defined(__c_as_cpp)
extern "C" {
#endif

#define H2O_STRUCT_FROM_MEMBER(s, m, p) ((s *)((char *)(p)-offsetof(s, m)))

#if __GNUC__ >= 3
#define H2O_LIKELY(x) __builtin_expect(!!(x), 1)
#define H2O_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define H2O_LIKELY(x) (x)
#define H2O_UNLIKELY(x) (x)
#endif

#ifdef __GNUC__
#define H2O_GNUC_VERSION ((__GNUC__ << 16) | (__GNUC_MINOR__ << 8) | __GNUC_PATCHLEVEL__)
#else
#define H2O_GNUC_VERSION 0
#endif

#if __STDC_VERSION__ >= 201112L
#define H2O_NORETURN _Noreturn
#elif defined(__clang__) || defined(__GNUC__) && H2O_GNUC_VERSION >= 0x20500
// noreturn was not defined before gcc 2.5
#define H2O_NORETURN __attribute__((noreturn))
#else
#define H2O_NORETURN
#endif

#if !defined(__clang__) && defined(__GNUC__) && H2O_GNUC_VERSION >= 0x40900
// returns_nonnull was seemingly not defined before gcc 4.9 (exists in 4.9.1 but not in 4.8.2)
#define H2O_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define H2O_RETURNS_NONNULL
#endif

/**
 * prints an error message and aborts
 */
H2O_NORETURN void h2o_fatal(const char *msg);

template <typename T>
void h2o_clearmem(T *p)
{
    memset(p, 0, sizeof(*p));
}

/**
 * wrapper of malloc; allocates given size of memory or dies if impossible
 */
H2O_RETURNS_NONNULL inline void *h2o_mem_alloc(size_t sz)
{
    void *p = malloc(sz);
    if (p == NULL)
        h2o_fatal("no memory");
    return p;
}

H2O_RETURNS_NONNULL inline void *h2o_mem_calloc(size_t num, size_t sz)
{
    void *p = calloc(num, sz);
    if (p == NULL)
        h2o_fatal("no memory");
    return p;
}

#define h2o_mem_alloca(sz) alloca(sz)
#define h2o_mem_alloca_free(p)
//#define h2o_mem_alloca(sz) h2o_mem_alloc(sz)
//#define h2o_mem_alloca_free(p) h2o_mem_free(p)
/*
Trying to inline alloca wrapper causes segfaults
inline void *h2o_mem_alloca(size_t sz)
{
    return alloca(sz);
}
*/

inline void h2o_mem_free(void *ptr)
{
    free(ptr);
}

template <typename T>
T *h2o_mem_alloc_for(size_t num_elements=1)
{
    return (T*)h2o_mem_alloc(sizeof(T) * num_elements);
}

template <typename T>
T *h2o_mem_calloc_for(size_t num_elements=1)
{
    return (T*)h2o_mem_calloc(num_elements, sizeof(T));
}

/**
 * warpper of realloc; reallocs the given chunk or dies if impossible
 */
inline void *h2o_mem_realloc(void *oldp, size_t sz)
{
    void *newp = realloc(oldp, sz);
    if (newp == NULL) {
        h2o_fatal("no memory");
        return oldp;
    }
    return newp;
}

template <typename T>
inline T *h2o_mem_realloc_for(T *oldp, size_t sz)
{
    return (T*)h2o_mem_realloc(oldp, sz);
}

struct h2o_base_struct_t
{
    void * operator new(size_t size)
    {
        return h2o_mem_calloc(1, size);
    }

    void operator delete(void *ptr)
    {
        h2o_mem_free(ptr);
    }
};

struct h2o_buffer_prototype_t;

/**
 * tests if target chunk (target_len bytes long) is equal to test chunk (test_len bytes long)
 */
inline int h2o_memis(const void *_target, size_t target_len, const void *_test, size_t test_len)
{
    const char *target = (const char *)_target, *test = (const char *)_test;
    if (target_len != test_len)
        return 0;
    if (target_len == 0)
        return 1;
    if (target[0] != test[0])
        return 0;
    return memcmp(target + 1, test + 1, test_len - 1) == 0;
}

//calculate string length at compile time
//caution because it can silently go runtime
size_t constexpr cexStrLength(const char* str)
{
    return *str ? 1 + cexStrLength(str + 1) : 0;
}

struct h2o_iovec_t;
struct h2o_mem_pool_t;
void h2o_strdup_to(h2o_iovec_t *dest, h2o_mem_pool_t *pool, const char *s, size_t slen);

/**
 * buffer structure compatible with iovec
 */
struct h2o_iovec_t {
    char *base;
    size_t len;

    void init(const void *pbase, size_t plen)
    {
        /* intentionally declared to take a "const void*" since it may contain any type of data and since _some_ buffers are constant */
        base = (char *)pbase;
        len = plen;
    }
    static h2o_iovec_t create(const void *pbase, size_t plen)
    {
        h2o_iovec_t tmp;
        /* intentionally declared to take a "const void*" since it may contain any type of data and since _some_ buffers are constant */
        tmp.base = (char *)pbase;
        tmp.len = plen;
        return tmp;
    }

    void init_cex(const char pbase[])
    {
        init(pbase, cexStrLength(pbase));
    }
    void strdup(h2o_mem_pool_t *pool, const char *s, size_t len)
    {
        h2o_strdup_to(this, pool, s, len);
    }
    void strdup(h2o_mem_pool_t *pool, const h2o_iovec_t &src)
    {
        h2o_strdup_to(this, pool, src.base, src.len);
    }
    void strdup(const h2o_iovec_t &src)
    {
        h2o_strdup_to(this, nullptr, src.base, src.len);
    }
    int isEq(const h2o_iovec_t &_test) const
    {
        return h2o_memis(this->base, this->len, _test.base, _test.len);
    }
    int isEq(const h2o_iovec_t *_test) const
    {
        return h2o_memis(this->base, this->len, _test->base, _test->len);
    }
    int isEq(const void *_test, size_t _test_len) const
    {
        return h2o_memis(this->base, this->len, _test, _test_len);
    }
    int isEq(const char *_test) const
    {
        return h2o_memis(this->base, this->len, _test, strlen(_test));
    }
#if 0
    //this can leak memory without a pool
    h2o_iovec_t append(h2o_mem_pool_t *pool, h2o_iovec_t src)
    {
        h2o_iovec_t tmp = {NULL, this->len + src.len};
        /* allocate memory */
        if (pool != NULL)
            tmp.base = pool->alloc(tmp.len + 1);
        else
            tmp.base = h2o_mem_alloc(tmp.len + 1);

        /* concatenate */
        memcpy(tmp.base, this->base, this->len);
        memcpy(tmp.base + this->len, src.base, src.len);
        tnp.base[tmp.len] = '\0';
        this->base = tmp.base;
        this->len = tmp.len;
        return *this;
    }
#endif
};

struct h2o_mem_recycle_chunk_t {
    struct h2o_mem_recycle_chunk_t *next;
};

struct h2o_mem_recycle_t {
    size_t max;
    size_t cnt;
    struct h2o_mem_recycle_chunk_t *_link;

    /**
     * allocates memory using the reusing allocator
     */
    void *alloc(size_t sz);
    template <typename T>
    T *alloc_for(size_t num_elements=1)
    {
        return (T*)alloc(sizeof(T) * num_elements);
    }

    /**
     * returns the memory to the reusing allocator
     */
    void free(void *p);
};

typedef void (*mem_pool_dispose_cb_t)(void *);

struct h2o_mem_pool_shared_entry_t {
    size_t refcnt;
    mem_pool_dispose_cb_t dispose;
    char bytes[1];
};

struct h2o_mem_pool_chunk_t {
    h2o_mem_pool_chunk_t *next;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[4096 - sizeof(void *) * 2];
};

struct h2o_mem_pool_direct_t {
    h2o_mem_pool_direct_t *next;
    size_t _dummy; /* align to 2*sizeof(void*) */
    char bytes[1];
};

struct h2o_mem_pool_shared_ref_t {
    h2o_mem_pool_shared_ref_t *next;
    h2o_mem_pool_shared_entry_t *entry;
};

/**
 * the memory pool
 */
struct h2o_mem_pool_t {
    h2o_mem_pool_chunk_t *chunks;
    size_t chunk_offset;
    h2o_mem_pool_shared_ref_t *shared_refs;
    h2o_mem_pool_direct_t *directs;

    ~h2o_mem_pool_t(){clear();}

    /**
     * initializes the memory pool.
     */
    void init();

    /**
     * clears the memory pool.
     * Applications may dispose the pool after calling the function or reuse it without calling h2o_mem_init_pool.
     */
    void clear();

    /**
     * allocates given size of memory from the memory pool, or dies if impossible
     */
    void *alloc(size_t sz);
    template <typename T>
    T *alloc_for(size_t num_elements=1)
    {
        return (T*)alloc(sizeof(T) * num_elements);
    }

    /**
     * allocates a ref-counted chunk of given size from the memory pool, or dies if impossible.
     * The ref-count of the returned chunk is 1 regardless of whether or not the chunk is linked to a pool.
     * @param pool pool to which the allocated chunk should be linked (or NULL to allocate an orphan chunk)
     */
    void *alloc_shared(size_t sz, mem_pool_dispose_cb_t dispose);
    template <typename T>
    T *alloc_shared_for(size_t num_elements, mem_pool_dispose_cb_t dispose)
    {
        return (T*)alloc_shared(sizeof(T) * num_elements, dispose);
    }

    /**
     * links a ref-counted chunk to a memory pool.
     * The ref-count of the chunk will be decremented when the pool is cleared.
     * It is permitted to link a chunk more than once to a single pool.
     */
    void link_shared(void *p);
};

/**
 * buffer used to store incoming / outgoing octets
 */
struct h2o_buffer_t {
    /**
     * capacity of the buffer (or minimum initial capacity in case of a prototype (i.e. bytes == NULL))
     */
    size_t capacity;
    /**
     * amount of the data available
     */
    size_t size;
    /**
     * pointer to the start of the data (or NULL if is pointing to a prototype)
     */
    char *bytes;
    /**
     * prototype (or NULL if the instance is part of the prototype (i.e. bytes == NULL))
     */
    h2o_buffer_prototype_t *_prototype;
    /**
     * file descriptor (if not -1, used to store the buffer)
     */
    int _fd;
    char _buf[1];

    //h2o_buffer_t():capacity(0),size(0),bytes(nullptr),_prototype(nullptr),_fd(-1){};
    //h2o_buffer_t():capacity(0),size(0),bytes(nullptr),_prototype(nullptr),_fd(-1){};
    //h2o_buffer_t(size_t initial_capacity):capacity(0),size(0),bytes(nullptr),_prototype(bp),_fd(-1){};
};

struct h2o_buffer_mmap_settings_t {
    size_t threshold;
    char fn_template[FILENAME_MAX];
};

struct h2o_buffer_prototype_t {
    h2o_mem_recycle_t allocator;
    h2o_buffer_t _initial_buf;
    h2o_buffer_mmap_settings_t *mmap_settings;
};


template <typename T>
struct H2O_VECTOR {
    T *entries;
    size_t size;
    size_t capacity;

    H2O_VECTOR():entries(nullptr), size(0), capacity(0){}

    T& operator[] (size_t idx) {
        assert(idx < this->size);
        return this->entries[idx];
    }

    void clear_free()
    {
        if(this->entries)
        {
            h2o_mem_free(this->entries);
            this->entries = nullptr;
            this->size = this->capacity = 0;
        }
    }

    /**
     * grows the vector so that it could store at least new_capacity elements of given size (or dies if impossible).
     * @param pool memory pool that the vector is using
     * @param vector the vector
     * @param element_size size of the elements stored in the vector
     * @param new_capacity the capacity of the buffer after the function returns
     */
    void reserve(h2o_mem_pool_t *pool, size_t new_capacity)//__attribute__((nonnull (1, 2)))
    {
        if (this->capacity < new_capacity) {
            T *new_entries;
            if (this->capacity == 0)
                this->capacity = 4;
            while (this->capacity < new_capacity)
                this->capacity *= 2;
            if (pool != NULL) {
                new_entries = pool->alloc_for<T>(this->capacity);
                memcpy(new_entries, this->entries, sizeof(T) * this->size);
            } else {
                //memory leak ?
                new_entries = h2o_mem_realloc_for<T>(this->entries, sizeof(T) * this->capacity);
            }
            this->entries = new_entries;
        }
    }

    void reserve_more(h2o_mem_pool_t *pool, size_t more_size)
    {
        reserve(pool, this->size + more_size);
    }

    T *append_new(h2o_mem_pool_t *pool)
    {
        reserve_more(pool, 1);
        return this->entries + this->size++;
    }

    void push_back(h2o_mem_pool_t *pool, T element)
    {
        reserve_more(pool, 1);
        this->entries[this->size++] = element;
    }

    void push_front(h2o_mem_pool_t *pool, T element)
    {
        reserve_more(pool, 1);
        memmove(this->entries + 1, this->entries, sizeof(T) * this->size);
        ++this->size;
        this->entries[0] = element;
    }

    void assign(h2o_mem_pool_t *pool, H2O_VECTOR<T> *vector_src)
    {
        reserve(pool, vector_src->size);
        memcpy(this->entries, vector_src->entries, vector_src->size * sizeof(T));
        this->size = vector_src->size;
    }

    void assign_elements(h2o_mem_pool_t *pool, T *elements, size_t num_elements)
    {
        reserve(pool, num_elements);
        memcpy(this->entries, elements, num_elements * sizeof(T));
        this->size = num_elements;
    }
};

extern void *(*h2o_mem__set_secure)(void *, int, size_t);

/**
 *
 */
void h2o_buffer__do_free(h2o_buffer_t *buffer);
/**
 * allocates a buffer.
 * @param inbuf - pointer to a pointer pointing to the structure (set *inbuf to NULL to allocate a new buffer)
 * @param min_guarantee minimum number of bytes to reserve
 * @return buffer to which the next data should be stored
 * @note When called against a new buffer, the function returns a buffer twice the size of requested guarantee.  The function uses
 * exponential backoff for already-allocated buffers.
 */
h2o_iovec_t h2o_buffer_reserve(h2o_buffer_t **inbuf, size_t min_guarantee);
/**
 * throws away given size of the data from the buffer.
 * @param delta number of octets to be drained from the buffer
 */
void h2o_buffer_consume(h2o_buffer_t **inbuf, size_t delta);
inline void h2o_buffer_consume_all(h2o_buffer_t **inbuf)
{
    h2o_buffer_consume(inbuf, (*inbuf)->size);
}

void h2o_buffer__dispose_linked(void *p);

/**
 * secure memset
 */
inline void *h2o_mem_set_secure(void *b, int c, size_t len)
{
    return h2o_mem__set_secure(b, c, len);
}

inline void h2o_mem_free_secure(void *b, size_t len)
{
    h2o_mem_free(h2o_mem__set_secure(b, 0, len));
}
inline void h2o_mem_free_secure(h2o_iovec_t &iov)
{
    h2o_mem_free(h2o_mem__set_secure(iov.base, 0, iov.len));
}

/**
 * swaps contents of memory
 */
void h2o_mem_swap(void *x, void *y, size_t len);

/**
 * emits hexdump of given buffer to fp
 */
void h2o_dump_memory(FILE *fp, const char *buf, size_t len);

/**
 * appends an element to a NULL-terminated list allocated using malloc
 */
void h2o_append_to_null_terminated_list(void ***list, void *element);

/* inline defs */

/**
 * allocates a ref-counted chunk of given size from the memory pool, or dies if impossible.
 * The ref-count of the returned chunk is 1 regardless of whether or not the chunk is linked to a pool.
 * @param pool pool to which the allocated chunk should be linked (or NULL to allocate an orphan chunk)
 */
inline void *h2o_mem_alloc_shared(size_t sz, mem_pool_dispose_cb_t dispose)
{
    auto entry = (h2o_mem_pool_shared_entry_t *)h2o_mem_alloc(offsetof(h2o_mem_pool_shared_entry_t, bytes) + sz);
    entry->refcnt = 1;
    entry->dispose = dispose;
    return entry->bytes;
}
template <typename T>
T *h2o_mem_alloc_shared_for(size_t num_elements, mem_pool_dispose_cb_t dispose)
{
    return (T*)h2o_mem_alloc_shared(sizeof(T) * num_elements, dispose);
}


/**
 * increments the reference count of a ref-counted chunk.
 */
inline void h2o_mem_addref_shared(void *p)
{
    auto entry = H2O_STRUCT_FROM_MEMBER(h2o_mem_pool_shared_entry_t, bytes, p);
    assert(entry->refcnt != 0);
    ++entry->refcnt;
}

/**
 * decrements the reference count of a ref-counted chunk.
 * The chunk gets freed when the ref-count reaches zero.
 */
inline int h2o_mem_release_shared(void *p)
{
    auto entry = H2O_STRUCT_FROM_MEMBER(h2o_mem_pool_shared_entry_t, bytes, p);
    if (--entry->refcnt == 0) {
        if (entry->dispose != NULL)
            entry->dispose(entry->bytes);
        h2o_mem_free(entry);
        return 1;
    }
    return 0;
}

/**
 * initialize the buffer using given prototype.
 */
inline void h2o_buffer_init(h2o_buffer_t **buffer, h2o_buffer_prototype_t *prototype)
{
    *buffer = &prototype->_initial_buf;
}

/**
 * disposes of the buffer
 */
inline void h2o_buffer_dispose(h2o_buffer_t **_buffer)
{
    h2o_buffer_t *buffer = *_buffer;
    *_buffer = NULL;
    if (buffer->bytes != NULL)
        h2o_buffer__do_free(buffer);
}

/**
 * resets the buffer prototype
 */
inline void h2o_buffer_set_prototype(h2o_buffer_t **buffer, h2o_buffer_prototype_t *prototype)
{
    if ((*buffer)->_prototype != NULL)
        (*buffer)->_prototype = prototype;
    else
        *buffer = &prototype->_initial_buf;
}

/**
 * registers a buffer to memory pool, so that it would be freed when the pool is flushed.  Note that the buffer cannot be resized
 * after it is linked.
 */
inline void h2o_buffer_link_to_pool(h2o_buffer_t *buffer, h2o_mem_pool_t *pool)
{
    h2o_buffer_t **slot = (h2o_buffer_t **)pool->alloc_shared(sizeof(*slot), h2o_buffer__dispose_linked);
    *slot = buffer;
}

inline void h2o_buffer_append(h2o_buffer_t **buffer, const void *src, size_t len)
{
    h2o_buffer_reserve(buffer, len);
    memcpy((*buffer)->bytes + (*buffer)->size, src, len);
    (*buffer)->size += len;
}

inline h2o_iovec_t h2o_buffer_reserve_resize(h2o_buffer_t **buffer, size_t len)
{
    h2o_iovec_t t = h2o_buffer_reserve(buffer, len);
    (*buffer)->size += len;
    return t;
}

#define h2o_phr_header_name_cmp(phr_header_name1, phr_header_name2) \
    h2o_memis(phr_header_name1.name, phr_header_name1.name_len, phr_header_name2.name, phr_header_name2.name_len)
#define h2o_phr_header_name_is_literal(_target, literal) h2o_memis(_target.name, _target.name_len, H2O_STRLIT(literal))
#define h2o_phr_header_value_is_literal(_target, literal) h2o_memis(_target.value, _target.value_len, H2O_STRLIT(literal))

#if defined( __cplusplus) && !defined(__c_as_cpp)
}
#endif

#endif
