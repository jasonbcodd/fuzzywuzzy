#pragma once

#include "fcontext.h"
#include "socket.h"

#define STDIN_BUF_SIZE 1048576

#define BUF_SIZE 8192
#define NUM_MMAPS 32
#define NUM_SIGNALS 32
#define NUM_REGIONS 16

#define MMAP_BASE 0x20000000

struct mmap_data {
    void *addr;
    size_t len;
};

struct memory_region {
    void *base;
    size_t size;

    void *saved_data;
};

struct fuzzywuzzy_args {
    int argc;
    char **argv;
};

struct control_data {
    struct memory_region writable[NUM_REGIONS];
    size_t writable_index;
    void *writable_saved_base;
    void *writable_saved_curr;

    void *signals[NUM_SIGNALS];

    size_t mmap_index;
    struct mmap_data mmaps[NUM_MMAPS];

    int (*original_main_fn)(int, char **, char **);

    char buf[BUF_SIZE];
    void *stack;
    struct fuzzer_socket_t sock;

    fcontext_t main_context;
    fcontext_t context;
    int last_exit_code;
    char stdin_buf[STDIN_BUF_SIZE];
    bool do_coverage;
    struct fuzzywuzzy_args args;
};

int fuzzywuzzy_main(int argc, char **argv, char **environ);
void fuzzywuzzy_read_mmap();

void fuzzywuzzy_log_libc_call(const char *func_name, void *return_addr);


void fuzzywuzzy_reset(int exit_code);
