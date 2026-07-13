# -*- coding: utf-8 -*-
#
# test_client_example.py
#
# Copyright (C) 2006-2020 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

# pylint: disable=missing-docstring, invalid-name, import-error

import os
import socket
import subprocess
import sys

import wolfssl

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))
import client as client_example  # noqa: E402


def _args(argv):
    return client_example.build_arg_parser().parse_args(argv)


def _ctx():
    return wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_2)


def test_verification_enables_hostname_check_by_default():
    """
    F-5621: with cert verification on (the default), the client must also
    verify the peer's hostname and pass server_hostname to wrap_socket.
    """
    args = _args(["-h", "example.com"])
    ctx = _ctx()

    server_hostname = client_example.configure_verification(ctx, args)

    assert ctx.verify_mode == wolfssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert server_hostname == "example.com"


def test_disable_cert_check_skips_hostname():
    args = _args(["-d"])
    ctx = _ctx()
    # Simulate a reused context that previously had hostname checking on:
    # -d must clear it, not leave it dangling against CERT_NONE.
    ctx.verify_mode = wolfssl.CERT_REQUIRED
    ctx.check_hostname = True

    server_hostname = client_example.configure_verification(ctx, args)

    assert ctx.verify_mode == wolfssl.CERT_NONE
    assert ctx.check_hostname is False
    assert server_hostname is None


def test_hostname_check_can_be_opted_out():
    """An explicit opt-out is provided for test certificates."""
    args = _args(["-n"])
    ctx = _ctx()
    # Reused context with hostname checking previously enabled: -n must
    # actively turn it back off.
    ctx.verify_mode = wolfssl.CERT_REQUIRED
    ctx.check_hostname = True

    server_hostname = client_example.configure_verification(ctx, args)

    assert ctx.verify_mode == wolfssl.CERT_REQUIRED
    assert ctx.check_hostname is False
    assert server_hostname is None


def test_ip_literal_host_skips_hostname_check():
    """
    The default host (127.0.0.1) is an IP literal. wolfSSL's
    check_domain_name() never matches iPAddress SANs, so the example must
    not hostname-check IP literals; certificate verification stays on.
    """
    args = _args([])
    ctx = _ctx()
    ctx.verify_mode = wolfssl.CERT_REQUIRED
    ctx.check_hostname = True

    server_hostname = client_example.configure_verification(ctx, args)

    assert args.h == "127.0.0.1"
    assert ctx.verify_mode == wolfssl.CERT_REQUIRED
    assert ctx.check_hostname is False
    assert server_hostname is None


def test_ipv6_literal_host_skips_hostname_check():
    args = _args(["-h", "::1"])
    ctx = _ctx()

    server_hostname = client_example.configure_verification(ctx, args)

    assert ctx.verify_mode == wolfssl.CERT_REQUIRED
    assert ctx.check_hostname is False
    assert server_hostname is None


def _free_port():
    sock = socket.socket()
    sock.bind(("localhost", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_default_invocation_end_to_end():
    """
    `python client.py` with the default host must complete a connection to
    `python server.py` using the bundled certificates: verification is on
    by default and the IP literal host must not trip the hostname check.
    """
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    port = _free_port()

    # The examples must import the same wolfssl as this test process, even
    # when the package is not installed (source-tree runs).
    env = dict(os.environ)
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(
        wolfssl.__file__)))
    env["PYTHONPATH"] = os.pathsep.join(
        [pkg_root] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))

    server = subprocess.Popen(
        [sys.executable, "-u", os.path.join("examples", "server.py"),
         "-p", str(port)],
        cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        line = server.stdout.readline().decode()
        assert "Server listening" in line, line

        client = subprocess.run(
            [sys.executable, "-u", os.path.join("examples", "client.py"),
             "-p", str(port)],
            cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=60)

        assert client.returncode == 0, client.stdout.decode()
        assert b"I hear you fa shizzle" in client.stdout
    finally:
        server.kill()
        server.wait()
