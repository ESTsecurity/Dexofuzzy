# Copyright (C) 2019 ESTsecurity
#
# This file is part of Dexofuzzy.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""
Dexofuzzy: Dalvik EXecutable Opcode Fuzzyhash

Dexofuzzy is a similarity digest hash for Android. It extracts Opcode
Sequence from Dex file based on Ssdeep and generates hash that can be
used for similarity comparison of Android App. Dexofuzzy created using
Dex's opcode sequence can find similar apps by comparing hash.

Dexofuzzy API usage:

... hash(dex_binary_data)

    >>> import dexofuzzy
    >>> with open('classes.dex', 'rb') as dex:
    ...     dex_data = dex.read()
    >>> dexofuzzy.hash(dex_data)
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'

... hash_from_file(apk_file or dex_file)

    >>> import dexofuzzy
    >>> dexofuzzy.hash_from_file('Trojan.Android.SmsSpy.apk')
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
    >>> dexofuzzy.hash_from_file('classes.dex')
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'

... compare(dexofuzzy_1, dexofuzzy_2)

    >>> import dexofuzzy
    >>> with open('classes.dex', 'rb') as dex:
    ...     dex_data = dex.read()
    >>> hash1 = dexofuzzy.hash(dex_data)
    >>> hash1
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
    >>> hash2 = dexofuzzy.hash_from_file('classes2.dex')
    >>> hash2
    '48:B2KmUCNc2FuGgy9fbdD7uPrEMc0HZj0/zeGn5:B2+Cap3y9pDHMHZ4/zeG5'
    >>> dexofuzzy.compare(hash1, hash2)
    50

Copyright (C) 2019 ESTsecurity (https://github.com/ESTsecurity/Dexofuzzy)
This project is licensed under the GNU General Public License v2 or later (GPLv2+)
"""

# Internal packages
from .__version__ import __version__, __author__


def compare(dexofuzzy_1, dexofuzzy_2):
    """
    This function computes the match score between two dexofuzzy signatures.
    :param dexofuzzy_1: string
    :param dexofuzzy_2: string
    :return: A value from zero to 100 indicating the match score of the two signatures
    """
    import sys
    if sys.platform == "win32":
        import dexofuzzy.bin as ssdeep
    else:
        import ssdeep

    return ssdeep.compare(dexofuzzy_1, dexofuzzy_2)


def hash(dex_data):
    """
    This function compute the dexofuzzy of a dex binary data.
    :param dex_data: bytes
    :return: The dexofuzzy of the dex binary data
    """

    if not isinstance(dex_data, bytes):
        raise TypeError("must be of bytes type")

    from .core.generator import GenerateDexofuzzy
    generateDexoFuzzy = GenerateDexofuzzy()
    dexofuzzy = generateDexoFuzzy.generate_dexofuzzy(dex_data)

    return dexofuzzy


def hash_from_file(file_path):
    """
    This function compute the dexofuzzy of a apk file of dex file.
    :param file_path: string
    :return: The dexofuzzy of the file
    """

    if not isinstance(file_path, str):
        raise TypeError("must be of string type")

    from .core.generator import GenerateDexofuzzy
    generateDexoFuzzy = GenerateDexofuzzy()
    dexofuzzy = generateDexoFuzzy.generate_dexofuzzy(file_path)

    return dexofuzzy
