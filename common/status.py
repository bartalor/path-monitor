from enum import StrEnum


class Status(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    SENDFAIL = "sendfail"
    TRACE = "trace"
