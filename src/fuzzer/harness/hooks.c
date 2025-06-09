#include "hooks.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stddef.h>
#include <ucontext.h>

#include "harness.h"

#define X_WRAPPER(FN_SIG, ...) WRAPPER(FN_SIG, __VA_ARGS__)
#define X_WRAPPERNOARG(FN_SIG) WRAPPERNOARG(FN_SIG)
#define X_DEF(...)
#include "hooks.def.h"
#undef X_DEF
#undef X_WRAPPERNOARG
#undef X_WRAPPER

extern struct control_data fuzzywuzzy_ctrl;

void (*(*fuzzywuzzy_real_signal)(int, void (*func)(int)))(int);
int *(*fuzzywuzzy_real___libc_start_main)(int (*main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void),
                                                 void (*fini)(void), void (*rtld_fini)(void), void(*stack_end));

#define X_WRAPPER(FN_SIG, ...) DEF(FN_SIG, __VA_ARGS__);
#define X_WRAPPERNOARG(FN_SIG) DEF(FN_SIG);
#define X_DEF(FN_SIG, ...) DEF(FN_SIG, __VA_ARGS__);
#include "hooks.def.h"
#undef X_DEF
#undef X_WRAPPERNOARG
#undef X_WRAPPER

void fuzzywuzzy_preload_hooks(void) {
#define X_WRAPPER(FN_SIG, ...) LOAD(EXTRACT_NAME(FN_SIG));
#define X_WRAPPERNOARG(FN_SIG) LOAD(EXTRACT_NAME(FN_SIG));
#define X_DEF(FN_SIG, ...) LOAD(EXTRACT_NAME(FN_SIG));
#include "hooks.def.h"
#undef X_DEF
#undef X_WRAPPERNOARG
#undef X_WRAPPER

    LOAD(signal);
}

void assert(int x) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    if (x) {
        fuzzywuzzy_reset(1);
    } else {
        return;
    }
}

_Noreturn void abort() {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    fuzzywuzzy_reset(-6);

    unreachable();
}

_Noreturn void exit(int status) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    fuzzywuzzy_reset(status);

    unreachable();
}

void __stack_chk_fail() {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    return REAL(__stack_chk_fail)();
}


void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    void *res = REAL(mmap)(addr, length, prot, flags, fd, offset);

    fuzzywuzzy_ctrl.mmaps[fuzzywuzzy_ctrl.mmap_index++] = (struct mmap_data){res, length};

    return res;
}

int munmap(void *addr, size_t length) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    int res = REAL(munmap)(addr, length);

    for (int i = 0; i < fuzzywuzzy_ctrl.mmap_index; i++) {
        if (fuzzywuzzy_ctrl.mmaps[i].addr == addr) {
            fuzzywuzzy_ctrl.mmaps[i].addr = NULL;
            if (i == fuzzywuzzy_ctrl.mmap_index - 1) {
                fuzzywuzzy_ctrl.mmap_index -= 1;
            }
            break;
        }
    }

    return res;
}

void (*signal(int sig, void (*func)(int)))(int) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    fuzzywuzzy_ctrl.signals[sig] = func;

    return REAL(signal)(sig, func);
}

int *__libc_start_main(int (*main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void),
                       void (*rtld_fini)(void), void(*stack_end)) {
    if (fuzzywuzzy_ctrl.original_main_fn != NULL) {
        LOAD(puts);
        LOAD(abort);
        REAL(puts)("WARNING: LIBC START MAIN CALLED TWICE, THIS WILL BREAK THE HARNESS");
        REAL(abort)();
    }

    fuzzywuzzy_ctrl.original_main_fn = main;

    LOAD(__libc_start_main);
    return REAL(__libc_start_main)(fuzzywuzzy_main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

int fprintf(FILE *f, const char *format, ...) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    va_list list;
    va_start(list, format);
    int res = REAL(vfprintf)(f, format, list);
    va_end(list);
    return res;
}

int printf(const char *format, ...) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    va_list list;
    va_start(list, format);
    int res = REAL(vprintf)(format, list);
    va_end(list);
    return res;
}

int sprintf(char *s, const char *format, ...) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    va_list list;
    va_start(list, format);
    int res = REAL(vsprintf)(s, format, list);
    va_end(list);
    return res;
}

int snprintf(char *s, size_t n, const char *format, ...) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    va_list list;
    va_start(list, format);
    int res = REAL(vsnprintf)(s, n, format, list);
    va_end(list);
    return res;
}


int scanf(const char *format, ...) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    va_list list;
    va_start(list, format);
    int res = REAL(vscanf)(format, list);
    va_end(list);
    return res;
}

int sscanf(const char *s, const char *format, ...) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    va_list list;
    va_start(list, format);
    int res = REAL(vsscanf)(s, format, list);
    va_end(list);
    return res;
}

int fscanf(FILE *f, const char *format, ...) {
    void *ra = __builtin_return_address(0);
    fuzzywuzzy_log_libc_call(__func__, ra);

    va_list list;
    va_start(list, format);
    int res = REAL(vfscanf)(f, format, list);
    va_end(list);
    return res;
}

