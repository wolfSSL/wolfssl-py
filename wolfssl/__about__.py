# -*- coding: utf-8 -*-
#
# __about__.py
#
# Copyright (C) 2006-2022 wolfSSL Inc.
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

from wolfssl._version import __version__, __wolfssl_version__

__title__ = "wolfssl"
__summary__ = "Python module that encapsulates wolfSSL's C SSL/TLS library."
__uri__ = "https://github.com/wolfssl/wolfssl-py"

__author__ = "wolfSSL Inc."
__email__ = "info@wolfssl.com"

__license__ = "GPLv2 or Commercial License"
__copyright__ = "Copyright (C) 2006-2022 wolfSSL Inc"

__all__ = [
    "__title__", "__summary__", "__uri__", "__version__",
    "__wolfssl_version__", "__author__", "__email__",
    "__license__", "__copyright__"
]
