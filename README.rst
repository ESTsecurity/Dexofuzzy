Dexofuzzy: Dalvik EXecutable Opcode Fuzzyhash
=============================================

Dexofuzzy is a similarity digest hash for Android. It extracts Opcode Sequence from Dex file based on Ssdeep and generates hash that can be used for similarity comparison of Android App. Dexofuzzy created using Dex's opcode sequence can find similar apps by comparing hash.

.. image:: https://img.shields.io/badge/license-GPLv2%2B-green.svg
    :target: https://github.com/ESTsecurity/Dexofuzzy
    :alt: License

.. image:: https://img.shields.io/badge/pypi-v3.3-blue.svg
    :target: https://github.com/ESTsecurity/Dexofuzzy
    :alt: Latest Version

.. image:: https://img.shields.io/badge/python-3%20%7C%203.4%20%7C%203.5%20%7C%203.6%20%7C%203.7%20%7C%203.8-blue.svg
    :target: https://pypi.python.org/pypi/ssdeep/
    :alt: Python Versions

Requirements
------------

Dexofuzzy requires the following modules:

* ssdeep 3.3 or later

Install
-------

Install on CentOS 6.10, 7.6, 8.0
................................
.. code-block:: console

    $ yum install epel-release
    $ yum install libffi-devel ssdeep ssdeep-devel python3-pip python3-devel libtool 
    $ pip3 install dexofuzzy

Install on Debian 8.11, 9.9, 10.0
.................................

.. code-block:: console

    $ apt-get install libffi-dev libfuzzy-dev python3-pip
    $ pip3 install dexofuzzy

Install on Linux Mint 3, 18.3, 19.1
...................................

.. code-block:: console

    $ apt-get install libffi-dev libfuzzy-dev python3-pip python3-dev
    $ pip3 install setuptools wheel 
    $ pip3 install dexofuzzy

Install on Ubuntu 14.04 LTS, 16.04 LTS, 18.04 LTS
.................................................

.. code-block:: console

    $ apt-get install libffi-dev libfuzzy-dev
    $ pip3 install dexofuzzy

Install on Windows 7, 10
........................

* The ssdeep DLL binaries for Windows are included in ./dexofuzzy/bin/ directory.

  * `intezer/ssdeep-windows <https://github.com/intezer/ssdeep-windows>`__  is included.
  * `MacDue/ssdeep-windows-32_64 <https://github.com/MacDue/ssdeep-windows-32_64>`__  is included.

.. code-block:: console

    $ pip3 install dexofuzzy

Usage
-----

::

   usage: dexofuzzy [-h] [-f SAMPLE_FILENAME] [-d SAMPLE_DIRECTORY] [-m] [-g N]
                    [-s DEXOFUZZY DEXOFUZZY] [-c CSV_FILENAME] [-j JSON_FILENAME]
                    [-l]

   Dexofuzzy - Dalvik EXecutable Opcode Fuzzyhash

   optional arguments:
      -h, --help                     show this help message and exit
      -f SAMPLE_FILENAME, --file SAMPLE_FILENAME
                                     the sample to extract dexofuzzy
      -d SAMPLE_DIRECTORY, --directory SAMPLE_DIRECTORY
                                     the directory of samples to extract dexofuzzy
      -m, --method-fuzzy             extract the fuzzyhash based on method of the sample
                                     (must include the -f or -d option by default)
      -g N, --clustering N           N-gram clustering the dexofuzzy of the sample
                                     (must include the -d option by default)
      -s DEXOFUZZY DEXOFUZZY, --score DEXOFUZZY DEXOFUZZY
                                     score the dexofuzzy of the sample
      -c CSV_FILENAME, --csv CSV_FILENAME
                                     output as CSV format
      -j JSON_FILENAME, --json JSON_FILENAME
                                     output as json format
                                     (include method fuzzy or clustering)
      -l, --error-log                output the error log

Output Format Example
.....................
* *FileName, FileSha256, FileSize, DexoHash, Dexofuzzy*

.. code-block:: console

    $ dexofuzzy -f SAMPLE_FILE
    sample.apk,80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835,42959,94d36ca47485ca4b1d05f136fa4d9473bb2ed3f21b9621e4adce47acbc999c5d,48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q
    Running Time : 0.016620635986328125

* *Method Fuzzy*

.. code-block:: console

    $ dexofuzzy -f SAMPLE_FILE -m 
    80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835,80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835,42959,d89c3b2c2620b77b1c0df7ef66ecde6d70f30b8a3ca15c21ded4b1ce1e319d38,48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q
    [
        "3:mWc0R2gLkcT2AVA:mWc51cTnVA",
        "3:b0RdGMVAn:MA",
        "3:y+6sMlHdNy+BGZn:y+6sMh5En",
        "3:y4CdNy/GZn:y4C+En",
        "3:dcpqn:WEn",
        "3:EN:EN",
        ...
    ]

* *Clustering*

.. code-block:: console

    $ dexofuzzy -d SAMPLE_DIRECTORY -g 7 
    80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835,80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835,42959,d89c3b2c2620b77b1c0df7ef66ecde6d70f30b8a3ca15c21ded4b1ce1e319d38,48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q
    ffe8c426c3a8ade648666bb45f194c1e84fb499b126932997c4d50cdfc4cc8f3,ffe8c426c3a8ade648666bb45f194c1e84fb499b126932997c4d50cdfc4cc8f3,46504,4a7039eefb7a8c292bcbd3e9fa232f4e6b136eedb9a114eb32aa360742b3f28f,48:B2KmUCNc2FuGgy9fbdD7uPrEMc0HZj0/zeGn5:B2+Cap3y9pDHMHZ4/zeG5
    [
        {
            "file_name": "80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835",
            "file_sha256": "80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835",
            "file_size": "42959",
            "dexohash": "d89c3b2c2620b77b1c0df7ef66ecde6d70f30b8a3ca15c21ded4b1ce1e319d38",
            "dexofuzzy": "48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q",
            "clustering": [
                {
                    "file_name": "80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835",
                    "file_sha256": "80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835",
                    "file_size": "42959",
                    "dexohash": "d89c3b2c2620b77b1c0df7ef66ecde6d70f30b8a3ca15c21ded4b1ce1e319d38",
                    "dexofuzzy": "U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY",
                    "signature": "U7uPrEM"
                },
                {
                    "file_name": "ffe8c426c3a8ade648666bb45f194c1e84fb499b126932997c4d50cdfc4cc8f3",
                    "file_sha256": "ffe8c426c3a8ade648666bb45f194c1e84fb499b126932997c4d50cdfc4cc8f3",
                    "file_size": "46504",
                    "dexohash": "4a7039eefb7a8c292bcbd3e9fa232f4e6b136eedb9a114eb32aa360742b3f28f",
                    "dexofuzzy": "B2KmUCNc2FuGgy9fbdD7uPrEMc0HZj0/zeGn5",
                    "signature": "7uPrEMc"
                }
            ]
        },
        {
            ...
        }
    ]    

Python API
..........

To compute a Dexofuzzy of ``dex file``, use ``hash`` function:

* *dexofuzzy(dex_binary_data)*

.. code-block:: pycon

    >>> import dexofuzzy
    >>> with open('classes.dex', 'rb') as dex:
    ...     dex_data = dex.read()
    >>> dexofuzzy.hash(dex_data)
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'

* *dexofuzzy_from_file(apk_file or dex_file)*
 
.. code-block:: pycon

    >>> import dexofuzzy
    >>> dexofuzzy.hash_from_file('sample.apk')
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
    >>> dexofuzzy.hash_from_file('classes.dex')
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'

The ``compare`` function returns the match between 2 hashes, an integer value from 0 (no match) to 100.

* *compare(dexofuzzy_1, dexofuzzy_2)*

.. code-block:: pycon

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

Tested on
---------

* CentOS 6.10, 7.7, 8.0
* Debian 8.11, 9.9, 10.0
* Linux Mint 3, 18.3, 19.1
* Ubuntu 14.04 LTS, 16.04 LTS, 18.04 LTS
* Windows 7, 10

Publication
-----------

* Shinho Lee, Wookhyun Jung, Sangwon Kim, Jihyun Lee, Jun-Seob Kim, `Dexofuzzy: Android Malware Similarity Clustering Method using Opcode Sequence <https://www.virusbulletin.com/uploads/pdf/magazine/2019/201911-Dexofuzzy-Android-Malware-Similarity-Clustering-Method.pdf>`__. Virus Bulletin, October 2019.

License
-------

This project is licensed under the GNU General Public License v2 or later (GPLv2+). Please see  `LICENSE <https://github.com/ESTsecurity/Dexofuzzy/blob/master/LICENSE>`__ located at the project's root for more details.

Copyright (C) 2019 `ESTsecurity <https://www.estsecurity.com/>`__.
