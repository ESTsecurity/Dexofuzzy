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
import argparse
import csv
import hashlib
import inspect
import json
import logging
import os
import sys
import time
from traceback import format_exc

# Internal packages
from dexofuzzy.core.generator import GenerateDexofuzzy

if sys.platform == "win32":
    import dexofuzzy.bin as ssdeep
else:
    import ssdeep


class Command:
    def __init__(self):
        self.args = None

    def console(self):
        parser = argparse.ArgumentParser(
                prog="dexofuzzy",
                description=("Dexofuzzy - Dalvik EXecutable Opcode Fuzzyhash"),
                add_help=True)

        parser.add_argument(
                    "-f", "--file", metavar='SAMPLE_FILENAME',
                    help="the sample to extract dexofuzzy")
        parser.add_argument(
                    "-d", "--directory", metavar='SAMPLE_DIRECTORY',
                    help="the directory of samples to extract dexofuzzy")

        parser.add_argument(
                    "-m", "--method-fuzzy", action="store_true",
                    help="extract the fuzzyhash based on method of the sample "
                    + "(must include the -f or -d option by default)")
        parser.add_argument(
                    "-g", "--clustering", metavar='N', type=int,
                    help="N-gram clustering the dexofuzzy of the sample "
                    + "(must include the -d option by default)")

        parser.add_argument(
                    "-s", "--score", metavar='DEXOFUZZY', nargs=2,
                    help="score the dexofuzzy of the sample")

        parser.add_argument(
                    "-c", "--csv", metavar='CSV_FILENAME',
                    help="output as CSV format")
        parser.add_argument(
                    "-j", "--json", metavar='JSON_FILENAME',
                    help="output as json format " +
                    "(include method fuzzy or clustering)")
        parser.add_argument(
                    "-l", "--error-log", action="store_true",
                    help="output the error log")

        if len(sys.argv) == 1:
            parser.print_help()
            return

        self.args = parser.parse_args()
        dexofuzzy_list = []

        start = time.time()

        if self.args.score:
            print(self.__get_dexofuzzy_compare(self.args.score[0],
                                               self.args.score[1]))

        if self.args.directory:
            for result in self.__search_directory(self.args.directory):
                if result is not None:
                    print("{},{},{},{},{}".format(
                                    result["file_name"], result["file_sha256"],
                                    result["file_size"], result["dexohash"],
                                    result["dexofuzzy"]))

                    if self.args.method_fuzzy:
                        print(json.dumps(result["method_fuzzy"], indent=4))

                    dexofuzzy_list.append(result)

        if self.args.file:
            result = self.__search_file(self.args.file)
            if result is not None:
                print("{},{},{},{},{}".format(
                                    result["file_name"], result["file_sha256"],
                                    result["file_size"], result["dexohash"],
                                    result["dexofuzzy"]))

                if self.args.method_fuzzy:
                    print(json.dumps(result["method_fuzzy"], indent=4))

                dexofuzzy_list.append(result)

        if self.args.clustering:
            dexofuzzy_list = self.__cluster_dexofuzzy(dexofuzzy_list,
                                                      self.args.clustering)
            print(json.dumps(dexofuzzy_list, indent=4))

        if self.args.csv:
            try:
                with open(self.args.csv, "w", newline="") as fd:
                    fieldnames = ["file_name", "file_sha256", "file_size",
                                  "dexohash", "dexofuzzy"]

                    writer = csv.DictWriter(fd, fieldnames=fieldnames)
                    writer.writeheader()
                    for output in dexofuzzy_list:
                        row = {}
                        row["file_name"] = output["file_name"]
                        row["file_sha256"] = output["file_sha256"]
                        row["file_size"] = output["file_size"]
                        row["dexohash"] = output["dexohash"]
                        row["dexofuzzy"] = output["dexofuzzy"]
                        writer.writerow(row)

            except Exception:
                print("{} : {}".format((inspect.stack()[0][3], format_exc())))
                return False

        if self.args.json:
            try:
                with open(self.args.json, "w") as fd:
                    json.dump(dexofuzzy_list, fd, indent=4)

            except Exception:
                print("{} : {}".format((inspect.stack()[0][3], format_exc())))
                return False

        end = time.time()
        print("Running Time : {}".format(str((end - start))))

    def __log_dexofuzzy(self, message=None, file=None):
        if self.args.error_log:
            self.logger = logging.getLogger(__name__)
            logging.basicConfig(filename="dexofuzzy_error.log",
                                level=logging.INFO,
                                format="%(message)s")

            if file:
                file = os.path.basename(file)
                self.logger.error(message + " : {}".format(file))

            else:
                self.logger.error(message)

            self.logger.error("{}".format(format_exc()))

    def __get_dexofuzzy_compare(self, dexofuzzy_1, dexofuzzy_2):
        try:
            return ssdeep.compare(dexofuzzy_1, dexofuzzy_2)

        except Exception:
            self.__log_dexofuzzy()

    def __search_directory(self, sample_dir):
        if os.path.isdir(sample_dir) is False:
            print("The directory not found")

        sample_path = os.path.join(os.getcwd(), sample_dir)
        for root, _, files in os.walk(sample_path):
            for file in files:
                file_path = os.path.join(root, file)
                report = self.__get_dexofuzzy(file_path)

                if report is not None:
                    result = {}
                    result["file_name"] = file
                    result["file_sha256"] = self.__get_sha256(file_path)
                    result["file_size"] = self.__get_file_size(file_path)
                    result["dexohash"] = report["dexohash"]
                    result["dexofuzzy"] = report["dexofuzzy"]

                    if self.args.method_fuzzy:
                        result["method_fuzzy"] = report["method_fuzzy"]

                    yield result

    def __search_file(self, sample_file):
        if os.path.isfile(sample_file) is False:
            print("The file not found")

        report = self.__get_dexofuzzy(sample_file)

        if report is not None:
            result = {}
            result["file_name"] = sample_file
            result["file_sha256"] = self.__get_sha256(sample_file)
            result["file_size"] = self.__get_file_size(sample_file)
            result["dexohash"] = report["dexohash"]
            result["dexofuzzy"] = report["dexofuzzy"]

            if self.args.method_fuzzy:
                result["method_fuzzy"] = report["method_fuzzy"]

            return result

    def __get_sha256(self, file_path):
        if not os.path.exists(file_path):
            self.__log_dexofuzzy(message="The file not found", file=file_path)

        try:
            with open(file_path, "rb") as fd:
                data = fd.read()

            sha256 = hashlib.sha256(data).hexdigest()

            return sha256

        except Exception:
            self.__log_dexofuzzy(message="Unable to get sha256",
                                 file=file_path)

    def __get_file_size(self, file_path):
        try:
            statinfo = os.stat(file_path)
            file_size = int(statinfo.st_size)

            return str(file_size)

        except Exception:
            self.__log_dexofuzzy(
                            message="Unable to get file size", file=file_path)

    def __get_dexofuzzy(self, file_path):
        try:
            generateDexofuzzy = GenerateDexofuzzy()
            opcode_list = generateDexofuzzy.extract_dexfile_opcode(file_path)

            if opcode_list:
                opcode_sum = feature = ""
                method_fuzzy_list = []

                for opcode in opcode_list:
                    opcode_sum += opcode
                    method_fuzzy = ssdeep.hash(opcode, encoding="UTF-8")
                    feature += method_fuzzy.split(":")[1]
                    method_fuzzy_list.append(method_fuzzy)

                result = {}
                result["dexohash"] = hashlib.sha256(opcode_sum.encode(
                                                        "UTF-8")).hexdigest()
                result["dexofuzzy"] = ssdeep.hash(feature, encoding="UTF-8")

                if self.args.method_fuzzy:
                    result["method_fuzzy"] = method_fuzzy_list

                return result

        except Exception:
            self.__log_dexofuzzy(
                        message="Unable to generate dexofuzzy", file=file_path)

    def __cluster_dexofuzzy(self, dexofuzzy_list, N):
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
                        clustering["dexohash"] = destination["dexohash"]
                        clustering["dexofuzzy"] = dst_dexofuzzy
                        clustering["signature"] = signature
                        source["clustering"].append(clustering)

            return sources

        except Exception:
            self.__log_dexofuzzy(message="Unable to cluster dexofuzzy")

    def __search_n_gram(self, dexofuzzy_1, dexofuzzy_2, N):
        try:
            for i in range(len(dexofuzzy_1)):
                if len(dexofuzzy_1[i:i+N]) == N:
                    if dexofuzzy_1[i:i+N] in dexofuzzy_2:
                        return dexofuzzy_1[i:i+N]

        except Exception:
            self.__log_dexofuzzy(message="Unable to search n-gram")
