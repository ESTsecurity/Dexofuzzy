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
import argparse
import csv
import inspect
import json
import sys
import time
from traceback import format_exc

# 3rd-party packages

# Internal packages
from dexofuzzy import Dexofuzzy, __version__


def main():
    parser = argparse.ArgumentParser(
            prog="dexofuzzy",
            description=("Dexofuzzy - Dalvik EXecutable Opcode Fuzzyhash v%s"
                         % __version__),
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
                    + "(default use the -f or -d option)")
    parser.add_argument(
                    "-g", "--clustering", metavar='N', type=int,
                    help="N-gram cluster the dexofuzzy of the sample "
                    + "(default use the -d option)")

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

    args = parser.parse_args()
    dexofuzzy = Dexofuzzy(args)
    dexofuzzy_list = []

    start = time.time()

    if args.score:
        print(dexofuzzy.get_dexofuzzy_compare(args.score[0], args.score[1]))

    if args.directory:
        for result in dexofuzzy.search_directory(args.directory):
            if result is not None:
                print(result["file_name"] + ',' + result["file_sha256"] + ',' +
                      result["file_size"] + ',' + result["opcode_hash"] + ',' +
                      result["dexofuzzy"])
                if args.method_fuzzy:
                    print(json.dumps(result["method_fuzzy"], indent=4))
                dexofuzzy_list.append(result)

    if args.file:
        result = dexofuzzy.search_file(args.file)
        if result is not None:
            print(result["file_name"] + ',' + result["file_sha256"] + ',' +
                  result["file_size"] + ',' + result["opcode_hash"] + ',' +
                  result["dexofuzzy"])
            if args.method_fuzzy:
                print(json.dumps(result["method_fuzzy"], indent=4))
            dexofuzzy_list.append(result)

    if args.clustering:
        dexofuzzy_list = dexofuzzy.cluster_dexofuzzy(dexofuzzy_list,
                                                     args.clustering)
        print(json.dumps(dexofuzzy_list, indent=4))

    if args.csv:
        try:
            with open(args.csv, "w", newline="") as fd:
                fieldnames = ["file_name", "file_sha256", "file_size",
                              "opcode_hash", "dexofuzzy"]

                writer = csv.DictWriter(fd, fieldnames=fieldnames)
                writer.writeheader()
                for output in dexofuzzy_list:
                    row = {}
                    row["file_name"] = output["file_name"]
                    row["file_sha256"] = output["file_sha256"]
                    row["file_size"] = output["file_size"]
                    row["opcode_hash"] = output["opcode_hash"]
                    row["dexofuzzy"] = output["dexofuzzy"]
                    writer.writerow(row)

        except Exception:
            print("%s : %s" % (inspect.stack()[0][3], format_exc()))
            return False

    if args.json:
        try:
            with open(args.json, "w") as fd:
                json.dump(dexofuzzy_list, fd, indent=4)

        except Exception:
            print("%s : %s" % (inspect.stack()[0][3], format_exc()))
            return False

    end = time.time()
    print("Running Time : %s" % str((end - start)))


if __name__ == '__main__':
    main()
