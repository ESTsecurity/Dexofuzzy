# -*- coding: UTF-8 -*-
#
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
'''

'''
# Default packages
import hashlib
import logging
import os
import sys
import zipfile
from contextlib import closing
from traceback import format_exc

# 3rd-party packages

# Internal packages
from dexofuzzy import GenerateDexofuzzy

if sys.platform == "win32":
    import dexofuzzy.bin as ssdeep
else:
    import ssdeep


class Dexofuzzy:
    def __init__(self, args):
        self.args = args

    def log_dexofuzzy(self, message=None, file=None):
        if self.args.error_log:
            self.logger = logging.getLogger(__name__)
            logging.basicConfig(filename="dexofuzzy_error.log",
                                level=logging.INFO,
                                format="%(message)s")
            if file:
                file = os.path.basename(file)
                self.logger.error(message + " : %s" % file)
            else:
                self.logger.error(message)

            self.logger.error("%s" % (format_exc()))

    def get_dexofuzzy_compare(self, dexofuzzy_1, dexofuzzy_2):
        try:
            return ssdeep.compare(dexofuzzy_1, dexofuzzy_2)

        except Exception:
            self.log_dexofuzzy()

    def search_directory(self, sample_dir):
        if os.path.isdir(sample_dir) is False:
            print("The directory not found")

        sample_path = os.path.join(os.getcwd(), sample_dir)
        for root, __, files in os.walk(sample_path):
            for file in files:
                file_path = os.path.join(root, file)
                report = self.__get_dexofuzzy(file_path)

                if report is not None:
                    result = {}
                    result["file_name"] = file
                    result["file_sha256"] = self.__get_sha256(file_path)
                    result["file_size"] = self.__get_file_size(file_path)
                    result["opcode_hash"] = report["opcode_hash"]
                    result["dexofuzzy"] = report["dexofuzzy"]

                    if self.args.method_fuzzy:
                        result["method_fuzzy"] = report["method_fuzzy"]

                    yield result

    def search_file(self, sample_file):
        if os.path.isfile(sample_file) is False:
            print("The file not found")

        report = self.__get_dexofuzzy(sample_file)

        if report is not None:
            result = {}
            result["file_name"] = sample_file
            result["file_sha256"] = self.__get_sha256(sample_file)
            result["file_size"] = self.__get_file_size(sample_file)
            result["opcode_hash"] = report["opcode_hash"]
            result["dexofuzzy"] = report["dexofuzzy"]

            if self.args.method_fuzzy:
                result["method_fuzzy"] = report["method_fuzzy"]

            return result

    def __get_sha256(self, file_path):
        if not os.path.exists(file_path):
            self.log_dexofuzzy(message="The file not found", file=file_path)

        try:
            with open(file_path, "rb") as fd:
                data = fd.read()

            sha256 = hashlib.sha256(data).hexdigest()

            return sha256

        except Exception:
            self.log_dexofuzzy(message="Unable to get sha256", file=file_path)

    def __get_file_size(self, file_path):
        try:
            statinfo = os.stat(file_path)
            file_size = int(statinfo.st_size)

            return str(file_size)

        except Exception:
            self.log_dexofuzzy(
                            message="Unable to get file size", file=file_path)

    def __get_dexofuzzy(self, file_path):
        try:
            opcode_list = self.__extract_dexfile_opcode(file_path)

            if opcode_list:
                opcode_sum = feature = ""
                method_fuzzy_list = []

                for opcode in opcode_list:
                    opcode_sum += opcode
                    method_fuzzy = ssdeep.hash(opcode, encoding="UTF-8")
                    feature += method_fuzzy.split(":")[1]
                    method_fuzzy_list.append(method_fuzzy)

                result = {}
                result["opcode_hash"] = hashlib.sha256(opcode_sum.encode(
                                                        "UTF-8")).hexdigest()
                result["dexofuzzy"] = ssdeep.hash(feature, encoding="UTF-8")

                if self.args.method_fuzzy:
                    result["method_fuzzy"] = method_fuzzy_list

                return result

        except Exception:
            self.log_dexofuzzy(
                        message="Unable to generate dexofuzzy", file=file_path)

    def __extract_dexfile_opcode(self, file_path):
        try:
            filetype = self.__check_file_type(file_path)

            if filetype == "application/zip":
                method_opcode_sequence_list = []

                for dex_data in self.__extract_dexfile(file_path):
                    generateDexofuzzy = GenerateDexofuzzy()
                    opcodes = generateDexofuzzy.extract_opcode(dex_data)
                    method_opcode_sequence_list += opcodes

                return method_opcode_sequence_list

            elif filetype == "application/x-dex":
                with open(file_path, "rb") as fd:
                    dex_data = fd.read()

                method_opcode_sequence_list = []
                generateDexofuzzy = GenerateDexofuzzy()
                opcodes = generateDexofuzzy.extract_opcode(dex_data)
                method_opcode_sequence_list = opcodes

                return method_opcode_sequence_list

            else:
                self.log_dexofuzzy(
                    message="The file format isn't supported", file=file_path)

        except Exception:
            self.log_dexofuzzy(
                message="Unable to extract dexfile opcode", file=file_path)

    def __extract_dexfile(self, file_path):
        try:
            dex_list = []
            with closing(zipfile.ZipFile(file_path)) as ZipData:
                for info in ZipData.infolist():
                    if(info.filename.startswith("classes") and
                       info.filename.endswith(".dex")):
                        dex_list.append(info.filename)

                if not dex_list:
                    self.log_dexofuzzy(
                        message="Could not find dex format in APK file",
                        file=file_path)
                    return

                for dex_name in sorted(dex_list):
                    with ZipData.open(dex_name) as dex:
                        yield dex.read()

        except Exception:
            self.log_dexofuzzy(
                        message="Unable to extract dex file", file=file_path)

    def __check_file_type(self, file_path):
        try:
            with open(file_path, "rb") as fd:
                raw_data = fd.read(8)

            if((raw_data[0:4].find(b'PK\x03\x04') == 0) or
               (raw_data[0:4].find(b'PK\x03\x06') == 0) or
               (raw_data[0:4].find(b'PK\x03\x08') == 0) or
               (raw_data[0:4].find(b'PK\x05\x04') == 0) or
               (raw_data[0:4].find(b'PK\x05\x06') == 0) or
               (raw_data[0:4].find(b'PK\x05\x08') == 0) or
               (raw_data[0:4].find(b'PK\x07\x04') == 0) or
               (raw_data[0:4].find(b'PK\x07\x06') == 0) or
               (raw_data[0:4].find(b'PK\x07\x08') == 0)):

                return "application/zip"

            elif((raw_data[0:8].find(b'dex\n035') == 0) or
                 (raw_data[0:8].find(b'dex\n036') == 0) or
                 (raw_data[0:8].find(b'dex\n037') == 0) or
                 (raw_data[0:8].find(b'dex\n038') == 0)):

                return "application/x-dex"

        except Exception:
            self.log_dexofuzzy(
                        message="Unable to check file type", file=file_path)

    def cluster_dexofuzzy(self, dexofuzzy_list, N):
        try:
            sources = destinations = dexofuzzy_list
            for source in sources:
                source["clustering"] = []
                src_dexofuzzy = source["dexofuzzy"].split(':')[1]
                for destination in destinations:
                    dst_dexofuzzy = destination["dexofuzzy"].split(':')[1]
                    signature = self.__search_n_gram(src_dexofuzzy,
                                                     dst_dexofuzzy, int(N))

                    if signature:
                        clustering = {}
                        clustering["file_name"] = destination["file_name"]
                        clustering["file_sha256"] = destination["file_sha256"]
                        clustering["file_size"] = destination["file_size"]
                        clustering["opcode_hash"] = destination["opcode_hash"]
                        clustering["dexofuzzy"] = dst_dexofuzzy
                        clustering["signature"] = signature
                        source["clustering"].append(clustering)

            return sources

        except Exception:
            self.log_dexofuzzy(message="Unable to cluster dexofuzzy")

    def __search_n_gram(self, dexofuzzy_1, dexofuzzy_2, N):
        try:
            for i in range(len(dexofuzzy_1)):
                if len(dexofuzzy_1[i:i+N]) == N:
                    if dexofuzzy_1[i:i+N] in dexofuzzy_2:
                        return dexofuzzy_1[i:i+N]

        except Exception:
            self.log_dexofuzzy(message="Unable to search n-gram")
