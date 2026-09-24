# -*- coding: utf-8 -*-
#
# test_close_race.py
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

# pylint: disable=missing-docstring, protected-access

"""
F-11784: close(), shutdown() and unwrap() could shut down and free the
WOLFSSL session while another thread was still inside a native call on it.
The session must stay alive until the last native call using it returns.
"""

import socket
import threading

import pytest
import wolfssl

_SESSION = wolfssl._ffi.cast("WOLFSSL *", 0x1000)


def _addr(ptr):
    return int(wolfssl._ffi.cast("uintptr_t", ptr))


class _SessionLib(object):
    """Stand-in for wolfssl._lib. The native function named `blocking` waits
    until released. Records session calls made while another is running.
    Only pointer values are kept so the fake never holds the session."""
    CRL_ENABLED = 1

    def __init__(self, blocking=None):
        self.blocking = blocking
        self.entered = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.active = 0
        self.calls = []
        self.overlapping = []
        self.freed = []

    def _call(self, name, ssl, ret):
        with self.lock:
            self.calls.append((name, _addr(ssl)))
            if self.active:
                self.overlapping.append(name)
            self.active += 1
        try:
            if name == self.blocking:
                self.entered.set()
                self.release.wait(10)
            return ret
        finally:
            with self.lock:
                self.active -= 1

    def wolfSSL_new(self, ctx):
        return _SESSION

    def wolfSSL_set_fd(self, ssl, fd):
        return 1

    def wolfSSL_free(self, ssl):
        self.freed.append(_addr(ssl))
        return self._call("wolfSSL_free", ssl, None)

    def wolfSSL_shutdown(self, ssl):
        return self._call("wolfSSL_shutdown", ssl, 1)

    def wolfSSL_read(self, ssl, data, length):
        return self._call("wolfSSL_read", ssl, 0)

    def wolfSSL_write(self, ssl, data, length):
        return self._call("wolfSSL_write", ssl, length)

    def wolfSSL_get_error(self, ssl, ret):
        return self._call("wolfSSL_get_error", ssl, 0)

    def wolfSSL_connect(self, ssl):
        return self._call("wolfSSL_connect", ssl, 1)

    def wolfSSL_pending(self, ssl):
        return self._call("wolfSSL_pending", ssl, 0)

    def wolfSSL_get_version(self, ssl):
        return self._call("wolfSSL_get_version", ssl,
                          wolfssl._ffi.new("char[]", b"TLSv1.2"))

    def wolfSSL_get_peer_certificate(self, ssl):
        return self._call("wolfSSL_get_peer_certificate", ssl,
                          wolfssl._ffi.NULL)

    def wolfSSL_UseSNI(self, ssl, sni_type, data, size):
        return self._call("wolfSSL_UseSNI", ssl, 1)

    def wolfSSL_EnableCRL(self, ssl, options):
        return self._call("wolfSSL_EnableCRL", ssl, 1)

    def wolfSSL_LoadCRLFile(self, ssl, path, filetype):
        return self._call("wolfSSL_LoadCRLFile", ssl, 1)

    def wolfSSL_dtls_create_peer(self, port, ip):
        return object()

    def wolfSSL_dtls_set_peer(self, ssl, peer, size):
        return self._call("wolfSSL_dtls_set_peer", ssl, 1)

    def wolfSSL_dtls_free_peer(self, peer):
        return 1


class _Ctx(object):
    protocol = wolfssl.PROTOCOL_TLSv1_2
    native_object = object()
    check_hostname = False


# operation name -> (native call it makes, how to run it)
_OPS = {
    "read": ("wolfSSL_read", lambda s: s.read(16)),
    "recv_into": ("wolfSSL_read", lambda s: s.recv_into(bytearray(16))),
    "write": ("wolfSSL_write", lambda s: s.write(b"data")),
    "do_handshake": ("wolfSSL_connect", lambda s: s.do_handshake()),
    "pending": ("wolfSSL_pending", lambda s: s.pending()),
    "version": ("wolfSSL_get_version", lambda s: s.version()),
    "get_peer_x509": ("wolfSSL_get_peer_certificate",
                      lambda s: s.get_peer_x509()),
    "use_sni": ("wolfSSL_UseSNI", lambda s: s.use_sni("example.com")),
    "enable_crl": ("wolfSSL_EnableCRL", lambda s: s.enable_crl(1)),
    "load_crl_file": ("wolfSSL_LoadCRLFile",
                      lambda s: s.load_crl_file("crl.pem", 1)),
    "add_peer": ("wolfSSL_dtls_set_peer",
                 lambda s: s.add_peer(("127.0.0.1", 11111))),
}

_CLOSERS = {
    "close": lambda s: s.close(),
    "shutdown": lambda s: s.shutdown(socket.SHUT_RDWR),
    "unwrap": lambda s: s.unwrap().close(),
}


@pytest.fixture
def make_socket(monkeypatch):
    raw_socks = []
    ssl_socks = []

    def make(lib):
        monkeypatch.setattr(wolfssl, "_lib", lib)
        raw, peer = socket.socketpair()
        raw_socks.extend([raw, peer])
        sock = wolfssl.SSLSocket(sock=raw, do_handshake_on_connect=False,
                                 _context=_Ctx())
        ssl_socks.append(sock)
        return sock

    yield make

    for sock in ssl_socks:
        # The fake session must never reach the real wolfSSL_free().
        sock.native_object = wolfssl._ffi.NULL
    for raw in raw_socks:
        raw.close()


@pytest.mark.parametrize(
    "op, closer",
    [(op, "close") for op in sorted(_OPS)] +
    [("read", "shutdown"), ("read", "unwrap")])
def test_session_outlives_native_call_in_flight(make_socket, op, closer):
    native, run = _OPS[op]
    lib = _SessionLib(blocking=native)
    sock = make_socket(lib)
    worker = threading.Thread(target=run, args=(sock,))
    worker.daemon = True
    try:
        worker.start()
        assert lib.entered.wait(5)

        closing = threading.Thread(target=_CLOSERS[closer], args=(sock,))
        closing.daemon = True
        closing.start()
        closing.join(5)
        # close() does not wait for the native call to finish.
        assert not closing.is_alive()
        assert lib.freed == []

        lib.release.set()
        worker.join(5)
        assert not worker.is_alive()
        assert "wolfSSL_free" not in lib.overlapping
        assert lib.freed == [_addr(_SESSION)]
    finally:
        lib.release.set()

    with pytest.raises(ValueError):
        sock.read(16)


@pytest.mark.parametrize("op", sorted(_OPS))
def test_operation_after_close_does_not_use_freed_session(make_socket, op):
    lib = _SessionLib()
    sock = make_socket(lib)
    sock.close()
    assert lib.freed == [_addr(_SESSION)]
    del lib.calls[:]

    try:
        _OPS[op][1](sock)
    except (ValueError, wolfssl.SSLError):
        pass
    assert [c for c in lib.calls if c[1] == _addr(_SESSION)] == []
