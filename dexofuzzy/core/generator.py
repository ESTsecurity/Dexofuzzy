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
import ctypes
import struct
import sys
import zipfile
from contextlib import closing

# Internal packages
if sys.platform == "win32":
    import dexofuzzy.bin as ssdeep
else:
    import ssdeep


class GenerateDexofuzzyError(Exception):
    pass


class GenerateDexofuzzy:
    def __init__(self):
        self.method_opcode_sequence_list = []

    def generate_dexofuzzy(self, param):
        try:
            self.method_opcode_sequence_list = []
            if isinstance(param, bytes):
                if self.__extract_opcode(param):
                    dexofuzzy = self.__get_dexofuzzy()

                    return dexofuzzy

            elif isinstance(param, str):
                if self.extract_dexfile_opcode(param):
                    dexofuzzy = self.__get_dexofuzzy()

                    return dexofuzzy

        except Exception:
            raise GenerateDexofuzzyError("Unable to generate dexofuzzy")

    def extract_dexfile_opcode(self, file_path):
        try:
            filetype = self.__check_file_type(file_path)
            if filetype == "application/zip":
                for dex_data in self.__extract_dexfile(file_path):
                    self.__extract_opcode(dex_data)

                return self.method_opcode_sequence_list

            elif filetype == "application/x-dex":
                with open(file_path, "rb") as fd:
                    dex_data = fd.read()

                self.__extract_opcode(dex_data)

                return self.method_opcode_sequence_list

        except Exception:
            raise GenerateDexofuzzyError("Unable to extract dexfile opcode")

    def __extract_dexfile(self, file_path):
        try:
            dex_list = []
            with closing(zipfile.ZipFile(file_path)) as ZipData:
                for info in ZipData.infolist():
                    if(info.filename.startswith("classes") and
                       info.filename.endswith(".dex")):
                        dex_list.append(info.filename)

                if not dex_list:
                    raise GenerateDexofuzzyError(
                                "Unable to find 'classes.dex' in the APK file")

                for dex_name in sorted(dex_list):
                    with ZipData.open(dex_name) as dex:
                        yield dex.read()

        except Exception:
            raise GenerateDexofuzzyError("Unable to extract dex file")

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
            raise GenerateDexofuzzyError("Unable to check file type")

    def __get_dexofuzzy(self):
        feature = ""
        for opcode in self.method_opcode_sequence_list:
            feature += ssdeep.hash(opcode, encoding="UTF-8").split(":")[1]

        dexofuzzy = ssdeep.hash(feature, encoding="UTF-8")

        return dexofuzzy

    def __extract_opcode(self, dex):
        header = {}
        string_ids = []
        type_ids = []
        class_defs = []

        if (isinstance(dex, bytes) and (
           (dex[0:8].find(b"dex\n035") == 0) or
           (dex[0:8].find(b"dex\n036") == 0) or
           (dex[0:8].find(b"dex\n037") == 0) or
           (dex[0:8].find(b"dex\n038") == 0))):

            header = self.__get_header(dex)
            string_ids = self.__get_string_ids(dex, header)
            type_ids = self.__get_type_ids(dex, header)
            class_defs = self.__get_class_defs(dex, header)
            self.__dex_to_smali(dex, header, string_ids, type_ids, class_defs)

            return self.method_opcode_sequence_list

    def __get_header(self, dex):
        magic_number = dex[0x00:0x08]
        checksum = struct.unpack("<L", dex[0x08:0x0C])[0]
        sha1 = dex[0x0C:0x20]
        file_size = struct.unpack("<L", dex[0x20:0x24])[0]
        header_size = struct.unpack("<L", dex[0x24:0x28])[0]
        endian_tag = struct.unpack("<L", dex[0x28:0x2C])[0]
        link_size = struct.unpack("<L", dex[0x2C:0x30])[0]
        link_offset = struct.unpack("<L", dex[0x30:0x34])[0]
        map_offset = struct.unpack("<L", dex[0x34:0x38])[0]
        string_ids_size = struct.unpack("<L", dex[0x38:0x3C])[0]
        string_ids_offset = struct.unpack("<L", dex[0x3C:0x40])[0]
        type_ids_size = struct.unpack("<L", dex[0x40:0x44])[0]
        type_ids_offset = struct.unpack("<L", dex[0x44:0x48])[0]
        proto_ids_size = struct.unpack("<L", dex[0x48:0x4C])[0]
        proto_ids_offset = struct.unpack("<L", dex[0x4C:0x50])[0]
        field_ids_size = struct.unpack("<L", dex[0x50:0x54])[0]
        field_ids_offset = struct.unpack("<L", dex[0x54:0x58])[0]
        method_ids_size = struct.unpack("<L", dex[0x58:0x5C])[0]
        method_ids_offset = struct.unpack("<L", dex[0x5C:0x60])[0]
        class_defs_size = struct.unpack("<L", dex[0x60:0x64])[0]
        class_defs_offset = struct.unpack("<L", dex[0x64:0x68])[0]
        data_size = struct.unpack("<L", dex[0x68:0x6C])[0]
        data_offset = struct.unpack("<L", dex[0x6C:0x70])[0]

        header = {}
        header["magic_number"] = magic_number
        header["checksum"] = checksum
        header["sha1"] = sha1
        header["file_size"] = file_size
        header["header_size"] = header_size
        header["endian_tag"] = endian_tag
        header["link_size"] = link_size
        header["link_offset"] = link_offset
        header["map_offset"] = map_offset
        header["string_ids_size"] = string_ids_size
        header["string_ids_offset"] = string_ids_offset
        header["type_ids_size"] = type_ids_size
        header["type_ids_offset"] = type_ids_offset
        header["proto_ids_size"] = proto_ids_size
        header["proto_ids_offset"] = proto_ids_offset
        header["field_ids_size"] = field_ids_size
        header["field_ids_offset"] = field_ids_offset
        header["method_ids_size"] = method_ids_size
        header["method_ids_offset"] = method_ids_offset
        header["class_defs_size"] = class_defs_size
        header["class_defs_offset"] = class_defs_offset
        header["data_size"] = data_size
        header["data_offset"] = data_offset

        return header

    def __get_uleb128(self, dex, offset):
        i = 0
        inc_offset = offset
        result = 0

        while True:
            value = dex[offset+i]
            inc_offset += 1
            if (value & 0x80) != 0:
                result = (result | (value ^ 0x80) << (i * 7))

            else:
                result = (result | value << (i * 7))
                break
            i += 1

        size = inc_offset - offset

        return result, size

    def __get_utf16_size_len(self, value):
        if value < (0x80):
            return 1

        elif value < (0x80 << 7):
            return 2

        elif value < (0x80 << 14):
            return 3

        return 4

    def __get_string_ids(self, dex, header):
        string_ids = []
        string_ids_size = header["string_ids_size"]
        string_ids_offset = header["string_ids_offset"]

        for i in range(string_ids_size):
            offset = struct.unpack("<L", dex[string_ids_offset+(i*4):
                                             string_ids_offset+(i*4)+4])[0]
            utf16_size, _ = self.__get_uleb128(dex, offset)

            if utf16_size <= 0:
                string_id = ""

            else:
                utf16_size_len = self.__get_utf16_size_len(utf16_size)
                string_id = dex[offset + utf16_size_len:
                                offset + utf16_size_len + utf16_size]

            string_ids.append(string_id)

        return string_ids

    def __get_type_ids(self, dex, header):
        type_ids = []
        type_ids_size = header["type_ids_size"]
        type_ids_offset = header["type_ids_offset"]

        for i in range(type_ids_size):
            offset = struct.unpack("<L", dex[type_ids_offset+(i*4):
                                             type_ids_offset+(i*4)+4])[0]
            type_ids.append(offset)

        return type_ids

    def __get_class_defs(self, dex, header):
        class_defs = []
        class_defs_size = header["class_defs_size"]
        class_defs_offset = header["class_defs_offset"]

        for i in range(class_defs_size):
            class_index = struct.unpack(
                                "<L", dex[class_defs_offset+(i*0x20):
                                          class_defs_offset+(i*0x20)+4])[0]
            access_flags = struct.unpack(
                                "<L", dex[class_defs_offset+(i*0x20)+4:
                                          class_defs_offset+(i*0x20)+8])[0]
            superclass_index = struct.unpack(
                                "<L", dex[class_defs_offset+(i*0x20)+8:
                                          class_defs_offset+(i*0x20)+12])[0]
            interfaces_offset = struct.unpack(
                                "<L", dex[class_defs_offset+(i*0x20)+12:
                                          class_defs_offset+(i*0x20)+16])[0]
            source_file_index = struct.unpack(
                                "<L", dex[class_defs_offset+(i*0x20)+16:
                                          class_defs_offset+(i*0x20)+20])[0]
            annotations_offset = struct.unpack(
                                "<L", dex[class_defs_offset+(i*0x20)+20:
                                          class_defs_offset+(i*0x20)+24])[0]
            class_data_offset = struct.unpack(
                                "<L", dex[class_defs_offset+(i*0x20)+24:
                                          class_defs_offset+(i*0x20)+28])[0]
            static_values_offset = struct.unpack(
                                "<L", dex[class_defs_offset+(i*0x20)+28:
                                          class_defs_offset+(i*0x20)+32])[0]
            class_defs.append([class_index, access_flags, superclass_index,
                               interfaces_offset, source_file_index,
                               annotations_offset, class_data_offset,
                               static_values_offset])

        return class_defs

    def __get_string_from_type_id(self, string_ids, type_ids, index):
        type_index = -1
        if len(type_ids) > index:
            type_index = type_ids[index]
        if len(string_ids) > type_index and type_index != -1:
            return string_ids[type_index]

        return ""

    def __dex_to_smali(self, dex, header, string_ids, type_ids, class_defs):
        class_defs_size = header["class_defs_size"]
        for index in range(class_defs_size):
            class_str = self.__get_string_from_type_id(
                                    string_ids, type_ids, class_defs[index][0])

            if class_str.find(b"Landroid/support/") == -1:
                if class_defs[index][6] > 0:
                    self.__get_class_data_item(dex, class_defs, index)

    def __get_class_data_item(self, dex, class_defs, index):
        offset = class_defs[index][6]
        static_fields, size = self.__get_uleb128(dex, offset)
        offset += size
        instance_fields, size = self.__get_uleb128(dex, offset)
        offset += size
        direct_methods, size = self.__get_uleb128(dex, offset)
        offset += size
        virtual_methods, size = self.__get_uleb128(dex, offset)
        offset += size

        if static_fields > 0:
            offset = self.__decode_field(dex, offset, static_fields)
        if instance_fields > 0:
            offset = self.__decode_field(dex, offset, instance_fields)
        if direct_methods > 0:
            offset = self.__decode_method(dex, offset, direct_methods)
        if virtual_methods > 0:
            offset = self.__decode_method(dex, offset, virtual_methods)

    def __decode_field(self, dex, offset, fields):
        for _ in range(fields):
            _, size = self.__get_uleb128(dex, offset)
            offset += size
            _, size = self.__get_uleb128(dex, offset)
            offset += size

        return offset

    def __get_code_item(self, dex, offset):
        registers_size = struct.unpack("<H", dex[offset:offset+2])[0]
        ins_size = struct.unpack("<H", dex[offset+2:offset+4])[0]
        outs_size = struct.unpack("<H", dex[offset+4:offset+6])[0]
        tries_size = struct.unpack("<H", dex[offset+6:offset+8])[0]
        debug_info_offset = struct.unpack("<L", dex[offset+8:offset+12])[0]
        insns_size = struct.unpack("<L", dex[offset+12:offset+16])[0]

        code_items = {}
        code_items["registers_size"] = registers_size
        code_items["ins_size"] = ins_size
        code_items["outs_size"] = outs_size
        code_items["tries_size"] = tries_size
        code_items["debug_info_offset"] = debug_info_offset
        code_items["insns_size"] = insns_size

        return code_items

    def __decode_method(self, dex, offset, methods):
        for _ in range(methods):
            _, size = self.__get_uleb128(dex, offset)
            offset += size
            _, size = self.__get_uleb128(dex, offset)
            offset += size
            code_offset, size = self.__get_uleb128(dex, offset)
            offset += size

            if code_offset != 0:
                current_offset = code_offset
                code_items = self.__get_code_item(dex, current_offset)
                current_offset += 16

                bytecode_size = ctypes.c_ushort(
                                            code_items["insns_size"] * 2).value
                bytecode_offset = current_offset
                opcodes = self.__bytecode(dex, bytecode_offset, bytecode_size)
                self.method_opcode_sequence_list.append(opcodes)

        return offset

    def __bytecode(self, dex, offset, bytecode_size):
        try:
            bytecode = [0]*bytecode_size
            for b in range(0, bytecode_size):
                bytecode[b] = dex[offset+b]

            opcode_offset_format = {
                0x00: self.__format_10x, 0x01: self.__format_12x,
                0x02: self.__format_22x, 0x03: self.__format_32x,
                0x04: self.__format_12x, 0x05: self.__format_22x,
                0x06: self.__format_32x, 0x07: self.__format_12x,
                0x08: self.__format_22x, 0x09: self.__format_32x,
                0x0a: self.__format_11x, 0x0b: self.__format_11x,
                0x0c: self.__format_11x, 0x0d: self.__format_11x,
                0x0e: self.__format_10x, 0x0f: self.__format_11x,
                0x10: self.__format_11x, 0x11: self.__format_11x,
                0x12: self.__format_11n, 0x13: self.__format_21s,
                0x14: self.__format_31i, 0x15: self.__format_21h,
                0x16: self.__format_21s, 0x17: self.__format_31i,
                0x18: self.__format_51l, 0x19: self.__format_21h,
                0x1a: self.__format_21c, 0x1b: self.__format_31c,
                0x1c: self.__format_21c, 0x1d: self.__format_11x,
                0x1e: self.__format_11x, 0x1f: self.__format_21c,
                0x20: self.__format_22c, 0x21: self.__format_12x,
                0x22: self.__format_21c, 0x23: self.__format_22c,
                0x24: self.__format_35c, 0x25: self.__format_3rc,
                0x26: self.__format_31t, 0x27: self.__format_11x,
                0x28: self.__format_10t, 0x29: self.__format_20t,
                0x2a: self.__format_30t, 0x2b: self.__format_31t,
                0x2c: self.__format_31t, 0x2d: self.__format_23x,
                0x2e: self.__format_23x, 0x2f: self.__format_23x,
                0x30: self.__format_23x, 0x31: self.__format_23x,
                0x32: self.__format_22t, 0x33: self.__format_22t,
                0x34: self.__format_22t, 0x35: self.__format_22t,
                0x36: self.__format_22t, 0x37: self.__format_22t,
                0x38: self.__format_21t, 0x39: self.__format_21t,
                0x3a: self.__format_21t, 0x3b: self.__format_21t,
                0x3c: self.__format_21t, 0x3d: self.__format_21t,
                0x3e: self.__format_10x, 0x3f: self.__format_10x,
                0x40: self.__format_10x, 0x41: self.__format_10x,
                0x42: self.__format_10x, 0x43: self.__format_10x,
                0x44: self.__format_23x, 0x45: self.__format_23x,
                0x46: self.__format_23x, 0x47: self.__format_23x,
                0x48: self.__format_23x, 0x49: self.__format_23x,
                0x4a: self.__format_23x, 0x4b: self.__format_23x,
                0x4c: self.__format_23x, 0x4d: self.__format_23x,
                0x4e: self.__format_23x, 0x4f: self.__format_23x,
                0x50: self.__format_23x, 0x51: self.__format_23x,
                0x52: self.__format_22c, 0x53: self.__format_22c,
                0x54: self.__format_22c, 0x55: self.__format_22c,
                0x56: self.__format_22c, 0x57: self.__format_22c,
                0x58: self.__format_22c, 0x59: self.__format_22c,
                0x5a: self.__format_22c, 0x5b: self.__format_22c,
                0x5c: self.__format_22c, 0x5d: self.__format_22c,
                0x5e: self.__format_22c, 0x5f: self.__format_22c,
                0x60: self.__format_21c, 0x61: self.__format_21c,
                0x62: self.__format_21c, 0x63: self.__format_21c,
                0x64: self.__format_21c, 0x65: self.__format_21c,
                0x66: self.__format_21c, 0x67: self.__format_21c,
                0x68: self.__format_21c, 0x69: self.__format_21c,
                0x6a: self.__format_21c, 0x6b: self.__format_21c,
                0x6c: self.__format_21c, 0x6d: self.__format_21c,
                0x6e: self.__format_35c, 0x6f: self.__format_35c,
                0x70: self.__format_35c, 0x71: self.__format_35c,
                0x72: self.__format_35c, 0x73: self.__format_10x,
                0x74: self.__format_3rc, 0x75: self.__format_3rc,
                0x76: self.__format_3rc, 0x77: self.__format_3rc,
                0x78: self.__format_3rc, 0x79: self.__format_10x,
                0x7a: self.__format_10x, 0x7b: self.__format_12x,
                0x7c: self.__format_12x, 0x7d: self.__format_12x,
                0x7e: self.__format_12x, 0x7f: self.__format_12x,
                0x80: self.__format_12x, 0x81: self.__format_12x,
                0x82: self.__format_12x, 0x83: self.__format_12x,
                0x84: self.__format_12x, 0x85: self.__format_12x,
                0x86: self.__format_12x, 0x87: self.__format_12x,
                0x88: self.__format_12x, 0x89: self.__format_12x,
                0x8a: self.__format_12x, 0x8b: self.__format_12x,
                0x8c: self.__format_12x, 0x8d: self.__format_12x,
                0x8e: self.__format_12x, 0x8f: self.__format_12x,
                0x90: self.__format_23x, 0x91: self.__format_23x,
                0x92: self.__format_23x, 0x93: self.__format_23x,
                0x94: self.__format_23x, 0x95: self.__format_23x,
                0x96: self.__format_23x, 0x97: self.__format_23x,
                0x98: self.__format_23x, 0x99: self.__format_23x,
                0x9a: self.__format_23x, 0x9b: self.__format_23x,
                0x9c: self.__format_23x, 0x9d: self.__format_23x,
                0x9e: self.__format_23x, 0x9f: self.__format_23x,
                0xa0: self.__format_23x, 0xa1: self.__format_23x,
                0xa2: self.__format_23x, 0xa3: self.__format_23x,
                0xa4: self.__format_23x, 0xa5: self.__format_23x,
                0xa6: self.__format_23x, 0xa7: self.__format_23x,
                0xa8: self.__format_23x, 0xa9: self.__format_23x,
                0xaa: self.__format_23x, 0xab: self.__format_23x,
                0xac: self.__format_23x, 0xad: self.__format_23x,
                0xae: self.__format_23x, 0xaf: self.__format_23x,
                0xb0: self.__format_12x, 0xb1: self.__format_12x,
                0xb2: self.__format_12x, 0xb3: self.__format_12x,
                0xb4: self.__format_12x, 0xb5: self.__format_12x,
                0xb6: self.__format_12x, 0xb7: self.__format_12x,
                0xb8: self.__format_12x, 0xb9: self.__format_12x,
                0xba: self.__format_12x, 0xbb: self.__format_12x,
                0xbc: self.__format_12x, 0xbd: self.__format_12x,
                0xbe: self.__format_12x, 0xbf: self.__format_12x,
                0xc0: self.__format_12x, 0xc1: self.__format_12x,
                0xc2: self.__format_12x, 0xc3: self.__format_12x,
                0xc4: self.__format_12x, 0xc5: self.__format_12x,
                0xc6: self.__format_12x, 0xc7: self.__format_12x,
                0xc8: self.__format_12x, 0xc9: self.__format_12x,
                0xca: self.__format_12x, 0xcb: self.__format_12x,
                0xcc: self.__format_12x, 0xcd: self.__format_12x,
                0xce: self.__format_12x, 0xcf: self.__format_12x,
                0xd0: self.__format_22s, 0xd1: self.__format_22s,
                0xd2: self.__format_22s, 0xd3: self.__format_22s,
                0xd4: self.__format_22s, 0xd5: self.__format_22s,
                0xd6: self.__format_22s, 0xd7: self.__format_22s,
                0xd8: self.__format_22b, 0xd9: self.__format_22b,
                0xda: self.__format_22b, 0xdb: self.__format_22b,
                0xdc: self.__format_22b, 0xdd: self.__format_22b,
                0xde: self.__format_22b, 0xdf: self.__format_22b,
                0xe0: self.__format_22b, 0xe1: self.__format_22b,
                0xe2: self.__format_22b, 0xe3: self.__format_10x,
                0xe4: self.__format_10x, 0xe5: self.__format_10x,
                0xe6: self.__format_10x, 0xe7: self.__format_10x,
                0xe8: self.__format_10x, 0xe9: self.__format_10x,
                0xea: self.__format_10x, 0xeb: self.__format_10x,
                0xec: self.__format_10x, 0xed: self.__format_10x,
                0xee: self.__format_10x, 0xef: self.__format_10x,
                0xf0: self.__format_10x, 0xf1: self.__format_10x,
                0xf2: self.__format_10x, 0xf3: self.__format_10x,
                0xf4: self.__format_10x, 0xf5: self.__format_10x,
                0xf6: self.__format_10x, 0xf7: self.__format_10x,
                0xf8: self.__format_10x, 0xf9: self.__format_10x,
                0xfa: self.__format_45cc, 0xfb: self.__format_4rcc,
                0xfc: self.__format_35c, 0xfd: self.__format_3rc,
                0xfe: self.__format_21c, 0xff: self.__format_21c,
            }
            opcode = ""
            current_offset = 0

            while bytecode_size > current_offset:
                opcode_hex = bytecode[current_offset]
                if opcode_hex in opcode_offset_format:
                    opcode += "{:02x}".format(opcode_hex)
                    current_offset = opcode_offset_format[opcode_hex](
                                                    bytecode, current_offset)
                else:
                    current_offset += 1
                    break

                if current_offset > bytecode_size:
                    break

        except Exception:
            return opcode

        return opcode

    def __format_10x(self, bytecode, offset):
        offset += 1
        try:
            if bytecode[offset] == 0x00:
                offset += 1

            elif bytecode[offset] == 0x01:
                offset = self.__format_31t_packed_switch_payload(
                                                            bytecode, offset)

            elif bytecode[offset] == 0x02:
                offset = self.__format_31t_sparse_switch_payload(
                                                            bytecode, offset)

            elif bytecode[offset] == 0x03:
                offset = self.__format_31t_fill_array_data_payload(
                                                            bytecode, offset)

            else:
                offset += 1

        except Exception:
            return offset

        return offset

    def __format_10t(self, _, offset):
        offset += 2
        return offset

    def __format_11n(self, _, offset):
        offset += 2
        return offset

    def __format_11x(self, _, offset):
        offset += 2
        return offset

    def __format_12x(self, _, offset):
        offset += 2
        return offset

    def __format_20t(self, _, offset):
        offset += 4
        return offset

    def __format_21c(self, _, offset):
        offset += 4
        return offset

    def __format_21h(self, _, offset):
        offset += 4
        return offset

    def __format_21s(self, _, offset):
        offset += 4
        return offset

    def __format_21t(self, _, offset):
        offset += 4
        return offset

    def __format_22b(self, _, offset):
        offset += 4
        return offset

    def __format_22c(self, _, offset):
        offset += 4
        return offset

    def __format_22s(self, _, offset):
        offset += 4
        return offset

    def __format_22t(self, _, offset):
        offset += 4
        return offset

    def __format_22x(self, _, offset):
        offset += 4
        return offset

    def __format_23x(self, _, offset):
        offset += 4
        return offset

    def __format_30t(self, _, offset):
        offset += 6
        return offset

    def __format_31c(self, _, offset):
        offset += 6
        return offset

    def __format_31i(self, _, offset):
        offset += 6
        return offset

    def __format_31t(self, _, offset):
        offset += 6
        return offset

    def __format_31t_fill_array_data_payload(self, bytecode, offset):
        offset += 1
        shift = bytecode[offset] << 8
        offset += 1
        element_width = shift | bytecode[offset]
        element_width = struct.unpack(
                                    "<H", struct.pack(">H", element_width))[0]
        offset += 1
        shift = bytecode[offset] << 8
        offset += 1
        size = shift | bytecode[offset]
        size = struct.unpack("<H", struct.pack(">H", size))[0]
        offset += 1
        offset_check = (offset-6)+(int((size*element_width+1)/2+4)*2)
        offset += 2

        offset += (1*size*element_width)

        if offset != offset_check:
            return offset_check

        return offset

    def __format_31t_packed_switch_payload(self, bytecode, offset):
        offset += 1
        shift = bytecode[offset] << 8
        size = shift | bytecode[offset+1]
        size = struct.unpack("<H", struct.pack(">H", size))[0]
        offset_check = (offset-2)+(int((size*2)+4)*2)
        offset += 6

        offset += (4*size)

        if offset != offset_check:
            return offset_check

        return offset

    def __format_31t_sparse_switch_payload(self, bytecode, offset):
        offset += 1
        shift = bytecode[offset] << 8
        size = shift | bytecode[offset+1]
        size = struct.unpack("<H", struct.pack(">H", size))[0]
        offset_check = (offset-2)+(int((size*4)+2)*2)
        offset += 2

        offset += (4*size)
        offset += (4*size)

        if offset != offset_check:
            return offset_check

        return offset

    def __format_32x(self, _, offset):
        offset += 6
        return offset

    def __format_35c(self, _, offset):
        offset += 6
        return offset

    def __format_3rc(self, _, offset):
        offset += 6
        return offset

    def __format_51l(self, _, offset):
        offset += 10
        return offset

    def __format_4rcc(self, _, offset):
        offset += 8
        return offset

    def __format_45cc(self, _, offset):
        offset += 12
        return offset
