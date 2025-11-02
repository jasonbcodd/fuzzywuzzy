from abc import ABC, abstractmethod
import enum
from pathlib import Path
from typing import Optional, TypedDict

class HarnessResult(TypedDict):
    duration: float
    exit_code: Optional[int]
    events: list[tuple]


class BinaryBits(enum.Enum):
    BITS_32 = 0
    BITS_64 = 1

class BaseHarness(ABC):
    TIMEOUT = 1

    @abstractmethod
    def __init__(self, binary_path: Path, bits: BinaryBits, do_coverage: bool = False, debug: bool = False):
        pass

    @abstractmethod
    def run(self, input: bytes) -> HarnessResult:
        pass

    def set_debug(self, debug: bool):
        pass
