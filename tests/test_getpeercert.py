# -*- coding: utf-8 -*-
#
# test_getpeercert.py
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

# pylint: disable=missing-docstring, invalid-name, import-error
# pylint: disable=protected-access

import socket
from contextlib import contextmanager
from threading import Thread

import pytest

import wolfssl


# Self-signed EC certificate with a UTF-8 commonName and DNS, IP (v4 and v6),
# email and URI subjectAltNames (the URI also contains non-ASCII).
_UTF8_SAN_CERT = ("certs/utf8-san-cert.pem", "certs/utf8-san-key.pem")
_UTF8_CN = u"wolfSSL Caf\u00e9 \u00dcnic\u00f6de"
_UTF8_URI = u"https://example.com/caf\u00e9"


@contextmanager
def _client_server_session(server_cert="certs/server-cert.pem",
                           server_key="certs/server-key.pem"):
    """
    Establish a real TLS connection to a local server that does NOT request a
    client certificate. Yields (client_socket, server_result); server_result
    is populated (after the block exits) with the server's view of the peer:
    {"x509", "cert"} on success or {"error"} if a call raised.
    """
    result = {}

    server_ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_TLS, server_side=True)
    server_ctx.verify_mode = wolfssl.CERT_NONE
    server_ctx.load_cert_chain(server_cert, server_key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("localhost", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        ssock = server_ctx.wrap_socket(conn, server_side=True)
        try:
            ssock.read(1024)
            # Client sent no certificate: these must not raise.
            result["x509"] = ssock.get_peer_x509()
            result["cert"] = ssock.getpeercert()
            ssock.write(b"ok")
        except Exception as exc:  # pylint: disable=broad-except
            result["error"] = exc
        finally:
            ssock.close()

    server_thread = Thread(target=serve, daemon=True)
    server_thread.start()

    client_ctx = wolfssl.SSLContext(wolfssl.PROTOCOL_TLS)
    client_ctx.verify_mode = wolfssl.CERT_NONE
    client = client_ctx.wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    client.connect(("localhost", port))
    client.write(b"hi")
    try:
        yield client, result
    finally:
        try:
            client.read(1024)
        except Exception:  # pylint: disable=broad-except
            pass
        client.close()
        server_thread.join(timeout=10)
        listener.close()


def test_getpeercert_returns_none_without_peer_cert():
    """
    F-5623: on a valid TLS connection where the peer presented no
    certificate (here, a server that does not request a client cert),
    getpeercert()/get_peer_x509() must return None instead of raising.
    """
    with _client_server_session() as (client, result):
        # The peer (server) always presents a certificate.
        server_cert = client.getpeercert()

    assert "error" not in result, "getpeercert raised: %r" % result.get("error")
    assert result["x509"] is None
    assert result["cert"] is None
    # Positive path: the server's certificate is still returned to the client.
    assert server_cert is not None


def test_wolfsslx509_accepts_session_for_backward_compat():
    """
    WolfSSLX509 historically accepted a WOLFSSL* session and fetched the peer
    certificate itself. That constructor form must keep working alongside the
    new WOLFSSL_X509* form used by get_peer_x509().
    """
    with _client_server_session() as (client, _result):
        from_session = wolfssl.WolfSSLX509(client.native_object)
        from_helper = client.get_peer_x509()

        # Both forms resolve to the same server certificate.
        assert from_session.get_subject_cn() != ""
        assert from_session.get_subject_cn() == from_helper.get_subject_cn()


def test_wolfsslx509_rejects_unexpected_types():
    """
    WolfSSLX509 discriminates WOLFSSL* from WOLFSSL_X509* by cffi type.
    Anything else must raise TypeError instead of being treated as a
    certificate pointer.
    """
    with pytest.raises(TypeError):
        wolfssl.WolfSSLX509(object())
    with pytest.raises(TypeError):
        wolfssl.WolfSSLX509(wolfssl._ffi.new("int *"))


def test_getpeercert_decodes_utf8_certificate_strings():
    """
    F-3235: get_subject_cn()/get_next_altname() decoded certificate strings
    as strict ASCII, so a valid peer certificate with a UTF-8 commonName made
    getpeercert() raise UnicodeDecodeError.
    """
    with _client_server_session(*_UTF8_SAN_CERT) as (client, _result):
        x509 = client.get_peer_x509()
        cn = x509.get_subject_cn()
        altnames = []
        while True:
            name = x509.get_next_altname()
            if name is None:
                break
            altnames.append(name)
        cert = client.getpeercert()

    assert cn == _UTF8_CN
    assert _UTF8_URI in altnames
    assert cert["subject"] == ((("commonName", _UTF8_CN),),)


class _StringLib(object):
    """Stand-in for _lib returning fixed, non-UTF-8 certificate strings."""

    def __init__(self, value):
        self._value = wolfssl._ffi.new("char[]", value)
        self._altname_returned = False

    def wolfSSL_X509_get_subjectCN(self, x509):
        return self._value

    def wolfSSL_X509_get_next_altname(self, x509):
        if self._altname_returned:
            return wolfssl._ffi.NULL
        self._altname_returned = True
        return self._value


def test_invalid_utf8_certificate_strings_do_not_raise(monkeypatch):
    """
    F-3235: a peer must not be able to make certificate inspection raise by
    putting bytes that are not valid UTF-8 (here Latin-1) into its name.
    """
    monkeypatch.setattr(wolfssl, "_lib", _StringLib(b"Caf\xe9"))
    x509 = wolfssl.WolfSSLX509.__new__(wolfssl.WolfSSLX509)
    x509.native_object = wolfssl._ffi.NULL

    assert x509.get_subject_cn() == u"Caf\ufffd"
    assert x509.get_next_altname() == u"Caf\ufffd"
