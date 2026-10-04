"""Optional native macOS system sleep/wake observer; no Apple imports on Linux."""
from __future__ import annotations

import ctypes as C
import threading

from .logger import get_logger

log = get_logger("xproxy.power")
CAN_SLEEP = 0xE0000270
WILL_SLEEP = 0xE0000280
HAS_POWERED_ON = 0xE0000300


class PowerMonitor:
    def __init__(self, platform: str, callback):
        self.platform = platform
        self.callback = callback
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.platform != "macos" or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="xproxy-power", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _handle(self, message: int, argument, acknowledge) -> None:
        # CAN_SLEEP is only a query, not evidence that the Mac will sleep.
        try:
            if message == WILL_SLEEP:
                self.callback("sleep")
            elif message == HAS_POWERED_ON:
                self.callback("wake")
        except Exception:
            log.exception("power notification callback failed")
        finally:
            if message in (CAN_SLEEP, WILL_SLEEP):
                acknowledge(argument)  # Never veto or delay system sleep.

    def _run(self) -> None:
        try:
            self._observe()
        except Exception:
            log.exception("macOS sleep observer unavailable; observation-gap detection remains active")

    def _observe(self) -> None:
        io = C.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
        cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        callback_type = C.CFUNCTYPE(None, C.c_void_p, C.c_uint32, C.c_uint32, C.c_void_p)
        io.IORegisterForSystemPower.argtypes = [C.c_void_p, C.POINTER(C.c_void_p), callback_type,
                                                C.POINTER(C.c_uint32)]
        io.IORegisterForSystemPower.restype = C.c_uint32
        io.IOAllowPowerChange.argtypes = [C.c_uint32, C.c_long]
        io.IOAllowPowerChange.restype = C.c_int
        io.IONotificationPortGetRunLoopSource.argtypes = [C.c_void_p]
        io.IONotificationPortGetRunLoopSource.restype = C.c_void_p
        io.IODeregisterForSystemPower.argtypes = [C.POINTER(C.c_uint32)]
        io.IOServiceClose.argtypes = [C.c_uint32]
        io.IONotificationPortDestroy.argtypes = [C.c_void_p]
        cf.CFRunLoopGetCurrent.restype = C.c_void_p
        cf.CFRunLoopAddSource.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
        cf.CFRunLoopRemoveSource.argtypes = [C.c_void_p, C.c_void_p, C.c_void_p]
        cf.CFRunLoopRunInMode.argtypes = [C.c_void_p, C.c_double, C.c_bool]
        cf.CFRunLoopRunInMode.restype = C.c_int32
        mode = C.c_void_p.in_dll(cf, 'kCFRunLoopDefaultMode')
        port, notifier = C.c_void_p(), C.c_uint32()
        root = 0
        source = None
        loop = cf.CFRunLoopGetCurrent()

        @callback_type
        def callback(_refcon, _service, message, argument):
            self._handle(message, argument or 0, lambda arg: io.IOAllowPowerChange(root, arg))

        try:
            root = io.IORegisterForSystemPower(None, C.byref(port), callback, C.byref(notifier))
            if not root:
                raise OSError('IORegisterForSystemPower failed')
            source = io.IONotificationPortGetRunLoopSource(port)
            if not source:
                raise OSError('power notification run-loop source unavailable')
            cf.CFRunLoopAddSource(loop, source, mode)
            log.info("macOS sleep/wake observer started")
            while not self._stop.is_set():
                cf.CFRunLoopRunInMode(mode, 0.5, False)
        finally:
            if source:
                cf.CFRunLoopRemoveSource(loop, source, mode)
            if notifier.value:
                io.IODeregisterForSystemPower(C.byref(notifier))
            if root:
                io.IOServiceClose(root)
            if port.value:
                io.IONotificationPortDestroy(port)
