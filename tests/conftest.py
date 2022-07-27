# -*- coding: utf-8 -*-
#
# conftest.py
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

# pylint: disable=missing-docstring, redefined-outer-name

import sys
import ssl
import pytest
import wolfssl
from wolfssl._ffi import lib as _lib

@pytest.fixture
def tcp_socket():
    import socket
    from contextlib import closing

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        yield sock


@pytest.fixture(
    params=[ssl, wolfssl] if sys.version_info[:2] == (3, 6) else [wolfssl],
    ids=["ssl", "wolfssl"] if sys.version_info[:2] == (3, 6) else ["wolfssl"])
def ssl_provider(request):
    return request.param


tls_params = ["TLSv1.2", "TLSv1.3", "SSLv23"]

if _lib.OLDTLS_ENABLED:
    tls_params.append("TLSv1.1")


@pytest.fixture(
    params=tls_params)
def ssl_context(ssl_provider, request):
    if request.param == "TLSv1.1":
        return ssl_provider.SSLContext(ssl_provider.PROTOCOL_TLSv1_1)
    if request.param == "TLSv1.2":
        return ssl_provider.SSLContext(ssl_provider.PROTOCOL_TLSv1_2)
    if request.param == "TLSv1.3":
        return ssl_provider.SSLContext(ssl_provider.PROTOCOL_TLSv1_3)
    if request.param == "SSLv23":
        return ssl_provider.SSLContext(ssl_provider.PROTOCOL_SSLv23)
