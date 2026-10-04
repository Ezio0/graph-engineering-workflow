"""Suspend-inclusive OS samples, not caller-issued measurement authority.

Only the repository's consent-gated transaction observer may persist samples as
trusted observations. These local clock primitives do not grant task authority.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import time
import uuid


class ClockUnavailable(ValueError):
    """Stable code; never include an OS identity or rejected value."""


def ticks_to_ns(ticks: int, numerator: int, denominator: int) -> int:
    if any(type(x) is not int for x in (ticks, numerator, denominator)) or not (
        0 <= ticks < 2**64 and 0 < numerator < 2**32 and 0 < denominator < 2**32
    ):
        raise ClockUnavailable('LEARNING_CLOCK_INVALID')
    result = ticks * numerator // denominator
    if result >= 2**63:
        raise ClockUnavailable('LEARNING_CLOCK_OVERFLOW')
    return result


def domain_digest(installation: str, repository: str, boot: str, namespace: str) -> str:
    if any(type(value) is not str or not value for value in (installation, repository, boot, namespace)):
        raise ClockUnavailable('LEARNING_CLOCK_DOMAIN')
    body = json.dumps([installation,repository,boot,namespace],ensure_ascii=True,separators=(',',':')).encode()
    return 'sha256:' + hashlib.sha256(body).hexdigest()


def _valid_sample(sample: object) -> bool:
    if type(sample) is not dict or set(sample) != {'clock_kind','clock_domain_digest','ticks_ns'}:
        return False
    digest = sample['clock_domain_digest']
    return (sample['clock_kind'] in ('darwin-continuous-v1','linux-boottime-v1')
        and type(sample['ticks_ns']) is int and 0 <= sample['ticks_ns'] < 2**63
        and type(digest) is str and len(digest) == 71 and digest.startswith('sha256:')
        and all(c in '0123456789abcdef' for c in digest[7:]))


def clock_duration_ns(start: object, end: object) -> int | None:
    """Pure arithmetic for already verified records; never confers provenance."""
    if not _valid_sample(start) or not _valid_sample(end):
        return None
    if start['clock_kind'] != end['clock_kind'] or start['clock_domain_digest'] != end['clock_domain_digest']:
        return None
    delta = end['ticks_ns'] - start['ticks_ns']
    return delta if delta >= 0 else None


class _Timebase(ctypes.Structure):
    _fields_ = [('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]


def _darwin_boot(lib: ctypes.CDLL) -> str:
    size = ctypes.c_size_t(0)
    fn = lib.sysctlbyname
    fn.argtypes = [ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
    fn.restype = ctypes.c_int
    name = b'kern.bootsessionuuid'
    if fn(name,None,ctypes.byref(size),None,0) != 0 or not 0 < size.value <= 128:
        raise ClockUnavailable('LEARNING_CLOCK_DOMAIN')
    buffer = ctypes.create_string_buffer(size.value)
    if fn(name,buffer,ctypes.byref(size),None,0) != 0:
        raise ClockUnavailable('LEARNING_CLOCK_DOMAIN')
    return str(uuid.UUID(buffer.value.decode('ascii')))


def _linux_domain() -> tuple[str,str]:
    with open('/proc/sys/kernel/random/boot_id','rb') as stream:
        raw = stream.read(129)
    if len(raw) > 128:
        raise ClockUnavailable('LEARNING_CLOCK_DOMAIN')
    boot = str(uuid.UUID(raw.decode('ascii').strip()))
    descriptor = os.open('/proc/self/ns/time',os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        namespace = f'{metadata.st_dev}:{metadata.st_ino}'
    finally:
        os.close(descriptor)
    return boot,namespace


class NativeLearningClock:
    """Installation/repository IDs must come from the verified transaction owner."""
    def __init__(self, installation: str, repository: str) -> None:
        if any(type(v) is not str or not v for v in (installation,repository)):
            raise ClockUnavailable('LEARNING_CLOCK_DOMAIN')
        self._installation = installation
        self._repository = repository

    def sample(self) -> dict[str,object]:
        try:
            system = platform.system()
            if system == 'Darwin':
                lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
                before = _darwin_boot(lib)
                base = _Timebase()
                lib.mach_timebase_info.argtypes = [ctypes.POINTER(_Timebase)]
                lib.mach_timebase_info.restype = ctypes.c_int
                if lib.mach_timebase_info(ctypes.byref(base)) != 0:
                    raise ClockUnavailable('LEARNING_CLOCK_UNAVAILABLE')
                lib.mach_continuous_time.argtypes = []
                lib.mach_continuous_time.restype = ctypes.c_uint64
                ticks = ticks_to_ns(lib.mach_continuous_time(),base.numer,base.denom)
                after = _darwin_boot(lib)
                namespace = 'darwin-system'
                kind = 'darwin-continuous-v1'
            elif system == 'Linux':
                before,namespace = _linux_domain()
                ticks = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                after,after_namespace = _linux_domain()
                if namespace != after_namespace:
                    raise ClockUnavailable('LEARNING_CLOCK_DOMAIN')
                kind = 'linux-boottime-v1'
            else:
                raise ClockUnavailable('LEARNING_CLOCK_UNAVAILABLE')
            if before != after or type(ticks) is not int or not 0 <= ticks < 2**63:
                raise ClockUnavailable('LEARNING_CLOCK_DOMAIN')
            # Clock kind/version is bound independently as well as in the domain.
            digest = domain_digest(self._installation,self._repository,before,kind+':'+namespace)
            return {'clock_kind':kind,'clock_domain_digest':digest,'ticks_ns':ticks}
        except (OSError,ValueError,AttributeError,UnicodeError,OverflowError):
            raise ClockUnavailable('LEARNING_CLOCK_UNAVAILABLE') from None
