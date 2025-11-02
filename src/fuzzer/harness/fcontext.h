#pragma once
// Forward declarations for Boost fcontext (C ABI)
typedef void* fcontext_t;

typedef struct {
    fcontext_t fctx;
    void* data;
} transfer_t;

// These are implemented by Boost assembly
extern fcontext_t make_fcontext(void* sp, size_t size, void (*fn)(transfer_t));
extern transfer_t jump_fcontext(fcontext_t const to, void* vp);
extern transfer_t ontop_fcontext(fcontext_t const to, void* vp, transfer_t (*fn)(transfer_t));