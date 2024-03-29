/*
 * mm-explicit.c - The best malloc package EVAR!
 *
 * TODO (bug): Uh..this is an implicit list???
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;

/** The layout of each unallocated block*/
typedef struct {
    size_t header;
    void *prev;
    void *next;
} free_block_t;

/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

static free_block_t *head_block = NULL;
static free_block_t *tail_block = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Set's a block's header&footer with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
    size_t *footer = (size_t *) ((void *) block + size);
    footer[-1] = block->header;
}

void add_node(free_block_t *node) {
    node->next = head_block;
    node->prev = NULL;
    if (tail_block == NULL) {
        tail_block = node;
    }
    else {
        ((free_block_t *) node->next) -> prev = node;
    }
    head_block = node;
}

void remove_node(free_block_t *node) {
    if (head_block == NULL)
    {
        return;
    }
    if (head_block == tail_block) {
        head_block = NULL;
        tail_block = NULL;
    }
    else if (node == head_block) {
        head_block = node->next;
        head_block->prev = NULL;
    }
    else if (node == tail_block) {
        tail_block = node->prev;
        tail_block->next = NULL;
    }
    else {
        ((free_block_t *) node->prev)->next = node->next;
        ((free_block_t *) node->next)->prev = node->prev;
    }
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    free_block_t *block = head_block;
    // Traverse the blocks in the heap using the implicit list
    while (block != NULL) {
        // If the block is free and large enough for the allocation, return it
        if (size <= get_size((block_t *) block)) {
            return (block_t *) block;
        }
        block = block->next;
    }
    return NULL;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;
    head_block = NULL;
    tail_block = NULL;
    return true;
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    size = round_up(sizeof(block_t) + size + sizeof(size_t), ALIGNMENT);
    if (size < 2 * ALIGNMENT) {
        size = 2 * ALIGNMENT;
    }
    block_t *block = find_fit(size);
    if (block != NULL && !is_allocated(block)) {
        remove_node((free_block_t *) block);
        if (get_size(block) >= size + 2 * ALIGNMENT) {
            // Split the block
            block_t *new_block = (void *) block + size;
            set_header(new_block, get_size(block) - size, false);
            set_header(block, size, true);
            if (block == mm_heap_last) {
                mm_heap_last = new_block;
            }
            add_node((free_block_t *) new_block);
        }
        else {
            // Use the whole block without splitting
            set_header(block, get_size(block), true);
        }
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;

    // Initialize the block with the allocated size
    set_header(block, size, true);
    return block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }
    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    set_header(block, get_size(block), false);
    bool is_merged = false;
    if (block != mm_heap_first) {
        size_t left_footer = ((size_t *) block)[-1];
        block_t *left_block = (void *) block - (left_footer & ~1);
        if (!(left_footer & 1)) {
            is_merged = true;
            set_header(left_block, get_size(left_block) + get_size(block), false);
            if (block == mm_heap_last) {
                mm_heap_last = left_block;
            }
            block = left_block;
        }
    }
    if (block != mm_heap_last) {
        block_t *right_block = (void *) block + get_size(block);
        if (!is_allocated(right_block)) {
            remove_node((free_block_t *) right_block);
            set_header(block, get_size(block) + get_size(right_block), false);
            if (right_block == mm_heap_last) {
                mm_heap_last = block;
            }
        }
    }
    if (!is_merged) {
        add_node((free_block_t *) block);
    }
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (old_ptr == NULL) {
        return mm_malloc(size);
    }
    else if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }
    else{
        block_t *old_block = block_from_payload(old_ptr);
        size_t min = size;
        if (get_size(old_block) - sizeof(size_t) < min){
            min = get_size(old_block) - sizeof(size_t);
        }
        void *new_ptr = mm_malloc(size);
        memcpy(new_ptr, old_ptr, size);
        mm_free(old_ptr);
        return new_ptr;
    }
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    size_t total_size = nmemb * size;
    void *ptr = mm_malloc(total_size);
    if (ptr != NULL) {
        memset(ptr, 0, total_size);
    }
    return ptr;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
    free_block_t *block = head_block;
    while (block != NULL) {
        size_t footer = ((size_t *) block)[-1];
        if ((!(footer & 1) && is_allocated((block_t *) (block))) ||
            ((footer & 1) && !is_allocated((block_t *) block))) {
            printf("mismatch bw header and footer allocation states\n");
        }
        block = block->next;
    }
}
