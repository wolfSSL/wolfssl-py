# -*- coding: utf-8 -*-
#
# test_crl_support.py
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

import pytest
import wolfssl


class _NoCrlLib(object):
    """Stand-in for wolfssl._lib of a wolfSSL built without HAVE_CRL, where
    the CRL functions are not bound."""
    CRL_ENABLED = 0


def _make_socket():
    sock = wolfssl.SSLSocket.__new__(wolfssl.SSLSocket)
    sock.native_object = object()
    sock._release_native_object = lambda: None
    return sock


def test_crl_flag_matches_bindings():
    enabled = bool(wolfssl._lib.CRL_ENABLED)
    assert hasattr(wolfssl._lib, "wolfSSL_EnableCRL") == enabled
    assert hasattr(wolfssl._lib, "wolfSSL_LoadCRLFile") == enabled


def test_crl_methods_raise_without_crl_support(monkeypatch):
    """CRL methods report missing CRL support instead of failing on an
    unbound function (F-12663).
    """
    monkeypatch.setattr(wolfssl, "_lib", _NoCrlLib())
    sock = _make_socket()
    with pytest.raises(NotImplementedError):
        sock.enable_crl(1)
    with pytest.raises(NotImplementedError):
        sock.load_crl_file("crl.pem", 1)
