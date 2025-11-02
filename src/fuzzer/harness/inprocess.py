import io
import os
import socket
import threading
import time
from pathlib import Path
from subprocess import DEVNULL, PIPE, Popen
from typing import Optional, TypedDict

import enum

from .base import BaseHarness, BinaryBits, HarnessResult

class Msg(enum.IntEnum):
    MSG_ACK = 0x01
    MSG_TARGET_START = 0x02
    MSG_TARGET_RESET = 0x03
    MSG_LIBC_CALL = 0x04
    MSG_TIMESTAMP = 0x05

BUF_MAX_SIZE = 1048576


class FuzzerMessage(TypedDict):
    msg_type: int
    data: dict[str, int]


class InProcessHarness(BaseHarness):
    TIMEOUT = 1
    SOCKET_TIMEOUT = 0.1

    process: Popen
    connection: socket.socket
    open: bool
    debug: bool

    def __init__(self, binary_path: Path, bits: BinaryBits, do_coverage: bool = False, debug: bool = False):
        self.binary_path = binary_path
        self.open = False
        self.debug = debug
        self.bits = bits
        self.do_coverage=do_coverage
        self.start()

    def run(self, input: bytes) -> HarnessResult:
        if len(input) > BUF_MAX_SIZE:
            return HarnessResult(duration=0, exit_code=0, events=[])
        if not self.open:
            self.start()

        assert self.process.stdin is not None

        self._await_start()

        start = time.time()

        self.process.stdin.write(input)
        self.process.stdin.flush()
        self.process.stdin.close()

        self._send_ack()

        events = []

        while True:
            if time.time() - start > self.TIMEOUT:
                duration = time.time() - start
                self.kill()
                return HarnessResult(duration=duration, exit_code=None, events=events)

            exit_code = self.process.poll()
            if exit_code is not None:
                self.kill()

                if exit_code >= 0:
                    raise HarnessException("the harness crashed...")

                duration = time.time() - start

                return HarnessResult(duration=0, exit_code=exit_code, events=events)

            msg = self._read_message()

            if msg is None:
                continue

            if msg["msg_type"] == Msg.MSG_TARGET_RESET:
                duration = time.time() - start

                self.process.stdin = open(f"/proc/{self.process.pid}/fd/0", "wb")
                #self._send_ack()

                exit_code = msg["data"]["exit_code"]
                events.append(("exit", exit_code))

                return HarnessResult(duration=duration, exit_code=exit_code, events=events)
            elif msg["msg_type"] == Msg.MSG_LIBC_CALL:
                # self._send_ack()
                events.append(
                    (
                        "libc_call",
                        msg["data"]["func_name"].decode(),  # type: ignore
                        msg["data"]["return_addr"],
                    )
                )
            elif msg["msg_type"] == Msg.MSG_TIMESTAMP:
                pass
            else:
                raise UnexpectedMessageTypeException(
                    f"received unexpected message type {msg['msg_type']} during target execution"
                )

    def set_debug(self, debug: bool):
        self.debug = debug

    def start(self):
        socket_path = (
            f"/tmp/fuzzywuzzy_{self.binary_path.name}_{threading.get_ident()}.socket"
        )
        if os.path.exists(socket_path):
            os.remove(socket_path)

        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(socket_path)
        self.server.listen(1)
        #self.server.setblocking(False)

        if self.bits == BinaryBits.BITS_32:
            build_dir = "build32"
        elif self.bits == BinaryBits.BITS_64:
            build_dir = "build64"

        harness_path = str((Path(__file__).parent.parent.parent.parent / build_dir / "libharness.so").resolve())

        env = {
            "LD_PRELOAD": harness_path,
            "FUZZYWUZZY_SOCKET_PATH": socket_path,
        }

        if self.do_coverage:
            env["FUZZYWUZZY_COVERAGE"] = ""

        self.process = Popen(
            self.binary_path.absolute(),
            stdin=PIPE,
            stdout=None if self.debug else DEVNULL,
            stderr=None if self.debug else DEVNULL,
            env=env
        )

        self.connection, _ = self.server.accept()
        self.connection.settimeout(self.SOCKET_TIMEOUT)

        self.open = True

    def kill(self):
        self.process.kill()
        self.server.close()
        self.connection.close()
        self.open = False

    def restart(self):
        self.kill()
        self.start()

    def _read_bytes(self, bytes: int):
        return self.connection.recv(bytes)

    def _read_sized_int(self, bytes: int):
        b = self.connection.recv(bytes)
        if len(b) != bytes:
            return None
        return int.from_bytes(b, byteorder="little")

    def _read_int(self):
        return self._read_sized_int(4)

    def _read_size_t(self):
        if self.bits == BinaryBits.BITS_64:
            return self._read_sized_int(8)
        return self._read_sized_int(4)

    def _read_uint8_t(self):
        return self._read_sized_int(1)

    def _read_message(self) -> Optional[FuzzerMessage]:
        try:
            msg_type = self._read_uint8_t()
        except socket.timeout:
            msg_type = None
        data = {}

        if msg_type is None:
            return None

        if msg_type in [Msg.MSG_ACK]:
            raise UnexpectedMessageTypeException(
                f"did not expect to receive message type {msg_type}"
            )
        elif msg_type in [Msg.MSG_TARGET_START]:
            pass
        elif msg_type == Msg.MSG_TARGET_RESET:
            data["exit_code"] = self._read_int()
        elif msg_type == Msg.MSG_LIBC_CALL:
            data["func_name"] = self._read_bytes(32).rstrip(b"\0")
            data["return_addr"] = self._read_size_t()
        elif msg_type == Msg.MSG_TIMESTAMP:
            data["what"] = self._read_bytes(16).rstrip(b"\0")
            data["timestamp"] = self._read_sized_int(8)
        else:
            raise UnknownMessageTypeException(
                f"received unexpected message type {msg_type}"
            )

        if self.debug:
            print("received:", {"msg_type": Msg(msg_type).name, "data": data})
        return FuzzerMessage(msg_type=msg_type, data=data)

    def _await_start(self):
        msg = self._read_message()
        while msg is None:
            self.restart()
            msg = self._read_message()
        assert (
            msg["msg_type"] == Msg.MSG_TARGET_START
        ), f"received msg type {hex(msg['msg_type'])}, was expecting {hex(Msg.MSG_TARGET_START)}"

    def _send_ack(self):
        if self.debug:
            print("sent:", {"msg_type": Msg.MSG_ACK, "data": {}})
        self.connection.send(Msg.MSG_ACK.to_bytes(1, byteorder="little"))


class HarnessException(Exception):
    pass


class UnexpectedMessageTypeException(HarnessException):
    pass


class UnknownMessageTypeException(HarnessException):
    pass
