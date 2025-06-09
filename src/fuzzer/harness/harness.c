#define _GNU_SOURCE
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <malloc.h>
#include <ucontext.h>
#include <setjmp.h>

#include "harness.h"
#include "socket.h"
#include "hooks.h"

#define unlikely(expr) __builtin_expect(!!(expr), 0)
#define likely(expr) __builtin_expect(!!(expr), 1)

const char *heap_str = "[heap]";
const char *harness_str = "harness.so";

//do not use realloc or free ANYWHERE
__attribute__ ((noinline)) void fuzzywuzzy_restore();
void fuzzywuzzy_pre_reset(int exit_code);
void fuzzywuzzy_post_reset(int exit_code);

struct control_data fuzzywuzzy_ctrl = {};

/**
 * Injected main function, this should only be passed to __libc_start_main, never called directly
 * @param argc target argc
 * @param argv target argv
 * @param environ target environ
 * @return *does not return*
 */
[[noreturn]] int fuzzywuzzy_main(int argc, char **argv, char **environ) {
    if (!fuzzywuzzy_ctrl.dummy_malloc) {

        fuzzywuzzy_preload_hooks();
        setvbuf(stdin, fuzzywuzzy_ctrl.stdin_buf, _IOFBF, STDIN_BUF_SIZE);
        fcntl(STDIN_FILENO, F_SETPIPE_SZ, STDIN_BUF_SIZE);
        fuzzywuzzy_restore();
        fuzzywuzzy_ctrl.context.uc_mcontext.gregs[8] = (greg_t) &fuzzywuzzy_ctrl;
        fuzzywuzzy_init_socket(&fuzzywuzzy_ctrl.sock);
        // we need to do a malloc to initialise the heap, and this needs to be the last item on the heap
        fuzzywuzzy_ctrl.dummy_malloc = REAL(malloc)(0x8); //lolxd
        fuzzywuzzy_read_mmap();
    }

    for (size_t i = 0; i < fuzzywuzzy_ctrl.writable[i].size; i++) {
        REAL(memcpy)(fuzzywuzzy_ctrl.writable[i].saved_data, fuzzywuzzy_ctrl.writable[i].base, fuzzywuzzy_ctrl.writable[i].size);
    }

    bool first_run = true;
    setjmp(fuzzywuzzy_ctrl.reset_point);

    if (likely(!first_run)) {
        fuzzywuzzy_post_reset(fuzzywuzzy_ctrl.last_exit_code);
        first_run = false;
    }

    // this code will be run on every execution of the program
    fuzzywuzzy_log_start();
    int exit_code = fuzzywuzzy_ctrl.original_main_fn(argc, argv, environ);
    fuzzywuzzy_reset(exit_code);
    unreachable();
}

/**
 * Logs a call to libc to the current socket connection.
 */
void fuzzywuzzy_log_libc_call(const char *func_name, void *return_addr) {
    struct fuzzer_msg_t msg = {.msg_type = MSG_LIBC_CALL, .data = {.libc_call = {"", return_addr}}};
    REAL(strncpy)(msg.data.libc_call.func_name, func_name, MAX_FUNCTION_NAME_LENGTH);
    fuzzywuzzy_write_message(&fuzzywuzzy_ctrl.sock, &msg);
}

/**
 * Logs a start to the current socket connection.
 */
void fuzzywuzzy_log_start() {
    struct fuzzer_msg_t msg = {.msg_type = MSG_TARGET_START, .data = {}};
    fuzzywuzzy_write_message(&fuzzywuzzy_ctrl.sock, &msg);
    fuzzywuzzy_expect_ack(&fuzzywuzzy_ctrl.sock);
}

/**
 * Logs a reset to the current socket connection.
 */
void fuzzywuzzy_log_reset(int exit_code) {
    struct fuzzer_msg_t msg = {.msg_type = MSG_TARGET_RESET, .data = {.target_reset = {exit_code}}};
    fuzzywuzzy_write_message(&fuzzywuzzy_ctrl.sock, &msg);
    fuzzywuzzy_expect_ack(&fuzzywuzzy_ctrl.sock);
}

[[noreturn]] void fuzzywuzzy_reset(int exit_code) {
    fuzzywuzzy_pre_reset(exit_code);
    setcontext(&fuzzywuzzy_ctrl.context);
    unreachable();
}

void fuzzywuzzy_pre_reset(int exit_code) {
    fuzzywuzzy_ctrl.last_exit_code = exit_code;

    // Resets signal handlers.
    for (int i = 0; i < NUM_SIGNALS; i++) {
        if (fuzzywuzzy_ctrl.signals[i]) {
            fuzzywuzzy_ctrl.signals[i] = nullptr;
            REAL(signal)(i, SIG_DFL);
        }
    }

    // Unmaps memory regions.
    for (int i = 0; i < fuzzywuzzy_ctrl.mmap_index; i++) {
        if (fuzzywuzzy_ctrl.mmaps[i].addr != NULL) {
            REAL(munmap)(fuzzywuzzy_ctrl.mmaps[i].addr, fuzzywuzzy_ctrl.mmaps[i].len);
        }
    }

    fuzzywuzzy_ctrl.mmap_index = 0;
}

/**
 * Performs operations to reset program state other than memory restoration.
 */
void fuzzywuzzy_post_reset(int exit_code) {
    // Flush stdin stream.
    ungetc(0, stdin);
    __fpurge(stdin);

    // Logs reset event to socket connection.
    fuzzywuzzy_log_reset(exit_code);
}

/**
 * Restore program state to be equivalent to program start. Should be used via setcontext and only called as a function for setup.
 */
__attribute__ ((noinline)) void fuzzywuzzy_restore() {
    getcontext(&fuzzywuzzy_ctrl.context);
    if (unlikely(fuzzywuzzy_ctrl.dummy_malloc == nullptr)) {
        return;
    }

    for (size_t i = 0; i < fuzzywuzzy_ctrl.writable[i].size; i++) {
        REAL(memcpy)(fuzzywuzzy_ctrl.writable[i].base, fuzzywuzzy_ctrl.writable[i].saved_data, fuzzywuzzy_ctrl.writable[i].size);
    }

    longjmp(fuzzywuzzy_ctrl.reset_point, 0);

    unreachable();
}

typedef enum parse_state {
    PARSE_STATE_ADDRS,
    PARSE_STATE_PROT,
    PARSE_STATE_NAME,
    PARSE_STATE_OFFSET,
    PARSE_STATE_DEVICE,
    PARSE_STATE_INODE,
    PARSE_STATE_DONE,
} parse_state_t;

/**
 * Read memory regions from mmap
 * Ensure malloc has been called at least once before calling this function
 */
void fuzzywuzzy_read_mmap() {
    int fd = REAL(open)("/proc/self/maps", O_RDONLY);

    void *base = NULL;
    void *top = NULL;
    char prot[5] = {0};
    size_t offset = 0;
    int name_start = 0;
    int name_end = 0;
    size_t heap_save_index = 0;
    void *last_heap_addr = NULL;
    size_t last_heap_size = 0;
    size_t total_size = 0;


    char *buf = fuzzywuzzy_ctrl.buf;

    REAL(read)(fd, buf, BUF_SIZE); //TODO: BUFFERED READ


    parse_state_t state = PARSE_STATE_ADDRS;
    int marker = 0;
    for (int i = 0; buf[i] != 0; i++) {
        switch (state) {
            case PARSE_STATE_ADDRS:
                if (buf[i] == '-') {
                    buf[i] = 0;
                    base = (void *) (REAL(strtoul)(&buf[marker], NULL, 16));
                    buf[i] = '-';
                    marker = i + 1;
                } else if (buf[i] == ' ') {
                    buf[i] = 0;
                    top = (void *) (REAL(strtoul)(&buf[marker], NULL, 16));
                    buf[i] = ' ';
                    marker = i + 1;
                    state = PARSE_STATE_PROT;
                }
                break;
            case PARSE_STATE_PROT:
                if (buf[i] == ' ') {
                    state = PARSE_STATE_OFFSET;
                    marker = i + 1;
                } else {
                    prot[i - marker] = buf[i];
                }
                break;
            case PARSE_STATE_OFFSET:
                if (buf[i] == ' ') {
                    buf[i] = 0;
                    offset = REAL(strtoul)(&buf[marker], NULL, 16);
                    buf[i] = ' ';
                    state = PARSE_STATE_DEVICE;
                    marker = i + 1;
                }
                break;
            case PARSE_STATE_DEVICE:
                if (buf[i] == ' ') {
                    marker = i + 1;
                    state = PARSE_STATE_INODE;
                }
                break;
            case PARSE_STATE_INODE:
                if (buf[i] == ' ') {
                    marker = i + 1;
                    state = PARSE_STATE_NAME;
                }
                break;
            case PARSE_STATE_NAME:
                if (name_start == 0 && buf[i] == '\n') {
                    //no name
                    name_start = i - 1;
                    name_end = i - 1;
                    state = PARSE_STATE_DONE;
                    break;
                }
                if (name_start == 0 && buf[i] != ' ') {
                    name_start = i;
                } if (buf[i] == '\n') {
                    name_end = i - 1;
                    state = PARSE_STATE_DONE;
                }
                break;
            case PARSE_STATE_DONE:
                break;
        }

        if (state == PARSE_STATE_DONE) {
            bool should_save = true;
            bool is_own_mem = true;
            for (int j = 0; j <= 9; j++) {
                if (buf[name_end - j] != harness_str[9 - j]) {
                    is_own_mem = false;
                    break;
                }
            }
            if (is_own_mem) {
                should_save = false;
            }

            if (prot[1] != 'w') {
                should_save = false;
            }


            if (should_save) {
                if (REAL(strncmp)(&buf[name_start], heap_str, 6) == 0) {
                    heap_save_index = fuzzywuzzy_ctrl.writable_index;
                    void *new_top = (void*)fuzzywuzzy_ctrl.dummy_malloc + REAL(malloc_usable_size)((void*)fuzzywuzzy_ctrl.dummy_malloc) + 0x8;
                    if (new_top < top) {
                        top = new_top;
                    }
                    // size is slightly bigger, just to ensure we capture the next pointer
                }
                fuzzywuzzy_ctrl.writable[fuzzywuzzy_ctrl.writable_index] =
                        (struct memory_region) {base, top,top - base, NULL};

                total_size += fuzzywuzzy_ctrl.writable[fuzzywuzzy_ctrl.writable_index].top - fuzzywuzzy_ctrl.writable[fuzzywuzzy_ctrl.writable_index].base;
                fuzzywuzzy_ctrl.writable_index++;
            }

            state = PARSE_STATE_ADDRS;
            name_start = 0;
            marker = i + 1;
        }
    }

    fuzzywuzzy_ctrl.writable_saved_base = REAL(mmap)((void*)MMAP_BASE, total_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    fuzzywuzzy_ctrl.writable_saved_curr = fuzzywuzzy_ctrl.writable_saved_base;
    for (int i = 0; i < fuzzywuzzy_ctrl.writable_index; i++) {
        fuzzywuzzy_ctrl.writable[i].saved_data = fuzzywuzzy_ctrl.writable_saved_curr;
        fuzzywuzzy_ctrl.writable_saved_curr += fuzzywuzzy_ctrl.writable[i].size;
    }

    REAL(close)(fd);
}


