#include "socket.h"

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "hooks.h"

#undef DISABLE_SOCKET

void fuzzywuzzy_init_socket(struct fuzzer_socket_t *sock) {
#ifdef DISABLE_SOCKET
    return;
#endif
    char *path = REAL(getenv)(SOCKET_PATH_ENVVAR);
    if (path == NULL) {
        REAL(puts)("you forgot to connect the socket");
        REAL(abort)();
    }

    struct sockaddr_un remote;
    remote.sun_family = AF_UNIX;
    REAL(strcpy)(remote.sun_path, path);

    int sock_fd = REAL(socket)(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        REAL(abort)();
    }

    size_t remote_len = sizeof(remote.sun_family) + REAL(strlen)(remote.sun_path) + 2;
    int result = REAL(connect)(sock_fd, (struct sockaddr *)&remote, remote_len);
    if (result < 0) {
        REAL(abort)();
    }

    sock->conn_fd = sock_fd;
}

/**
 * Reads a message from the fuzzer.
 * @param sock socket info
 * @param msg message buffer
 * @return status (negative for error, 0 on success)
 */
int fuzzywuzzy_read_message(struct fuzzer_socket_t *sock, struct fuzzer_msg_t *msg) {
#ifdef DISABLE_SOCKET
    return 0;
#endif
    REAL(memset)(msg, 0, sizeof(struct fuzzer_msg_t));

    REAL(read)(sock->conn_fd, &msg->msg_type, 1);
    switch (msg->msg_type) {
        case MSG_ACK:
            break;
        // Harness -> Fuzzer only.
        case MSG_TARGET_START:
        case MSG_TARGET_RESET:
        case MSG_LIBC_CALL:
            // Unexpected message type.
            return -1;
        default:
            // Unknown message type.
            return -2;
    }

    return 0;
}

/**
 * Writes a message to the fuzzer.
 * @param sock socket info
 * @param msg message
 * @return status (negative for error, 0 on success)
 */
int fuzzywuzzy_write_message(struct fuzzer_socket_t *sock, struct fuzzer_msg_t *msg) {
#ifdef DISABLE_SOCKET
    return 0;
#endif
    int data_size = 0;

    switch (msg->msg_type) {
        case MSG_TARGET_START:
            data_size = sizeof(struct fuzzer_msg_target_start_t);
            break;
        case MSG_TARGET_RESET:
            data_size = sizeof(struct fuzzer_msg_target_reset_t);
            break;
        case MSG_LIBC_CALL:
            data_size = sizeof(struct fuzzer_msg_libc_call_t);
            break;
        case MSG_TIMESTAMP:
            data_size = sizeof(struct fuzzer_msg_timestamp_t);
            break;
        // Fuzzer -> Harness only.
        case MSG_ACK:
            // Unexpected message type.
            return -1;
        default:
            // Unknown message type.
            return -2;
    }

    REAL(write)(sock->conn_fd, &msg->msg_type, 1);
    if (data_size) {
        REAL(write)(sock->conn_fd, &msg->data, data_size);
    }

    return 0;
}

/**
 * Waits for and reads a message from the current socket connection and aborts if it is not a MSG_ACK.
 */
void fuzzywuzzy_expect_ack(struct fuzzer_socket_t *sock) {
#ifdef DISABLE_SOCKET
    return;
#endif
    struct fuzzer_msg_t msg = {0};
    fuzzywuzzy_read_message(sock, &msg);

    if (msg.msg_type != MSG_ACK) {
        REAL(abort)();
    }
}

void fuzzywuzzy_close_socket(struct fuzzer_socket_t *sock) {
#ifdef DISABLE_SOCKET
    return;
#endif
    REAL(close)(sock->conn_fd);
}