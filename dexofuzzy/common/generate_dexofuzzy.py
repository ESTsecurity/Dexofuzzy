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
import ctypes
import struct
import sys

# 3rd-party packages

# Internal packages

if sys.platform == "win32":
    import dexofuzzy.bin as ssdeep
else:
    import ssdeep

# 3rd-party packages


class GenerateDexofuzzyError(Exception):
    pass


class GenerateDexofuzzy:
    def __init__(self):
        self.method_opcode_sequence_list = []

    def generate_dexofuzzy(self, dex):
        if self.extract_opcode(dex):
            feature = ""
            for opcode in self.method_opcode_sequence_list:
                feature += ssdeep.hash(opcode, encoding="UTF-8").split(":")[1]

            dexofuzzy = ssdeep.hash(feature, encoding="UTF-8")

            return dexofuzzy

        else:
            return None

    def extract_opcode(self, dex):
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

        else:
            raise GenerateDexofuzzyError("The file isn't dex format")

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
        current_offset = 0
        opcode = ""

        try:
            bytecode = [0]*bytecode_size
            for b in range(0, bytecode_size):
                bytecode[b] = dex[offset+b]

            while bytecode_size > current_offset:
                if bytecode[current_offset] == 0x00:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x01:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x02:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x03:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_32x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x04:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x05:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x06:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_32x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x07:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x08:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x09:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_32x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x0a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x0b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x0c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x0d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x0e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x0f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x10:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x11:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x12:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11n(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x13:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x14:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_31i(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x15:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21h(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x16:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x17:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_31i(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x18:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_51l(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x19:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21h(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x1a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x1b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_31c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x1c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x1d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x1e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x1f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x20:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x21:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x22:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x23:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x24:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_35c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x25:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_3rc(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x26:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_31t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x27:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_11x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x28:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x29:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_20t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x2a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_30t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x2b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_31t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x2c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_31t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x2d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x2e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x2f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x30:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x31:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x32:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x33:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x34:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x35:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x36:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x37:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x38:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x39:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x3a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x3b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x3c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x3d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21t(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x3e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x3f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x40:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x41:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x42:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x43:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x44:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x45:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x46:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x47:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x48:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x49:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x4a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x4b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x4c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x4d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x4e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x4f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x50:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x51:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x52:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x53:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x54:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x55:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x56:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x57:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x58:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x59:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x5a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x5b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x5c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x5d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x5e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x5f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x60:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x61:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x62:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x63:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x64:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x65:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x66:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x67:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x68:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x69:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x6a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x6b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x6c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x6d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x6e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_35c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x6f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_35c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x70:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_35c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x71:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_35c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x72:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_35c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x73:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x74:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_3rc(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x75:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_3rc(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x76:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_3rc(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x77:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_3rc(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x78:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_3rc(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x79:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x7a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x7b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x7c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x7d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x7e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x7f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x80:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x81:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x82:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x83:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x84:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x85:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x86:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x87:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x88:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x89:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x8a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x8b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x8c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x8d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x8e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x8f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x90:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x91:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x92:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x93:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x94:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x95:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x96:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x97:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x98:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x99:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x9a:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x9b:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x9c:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x9d:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x9e:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0x9f:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa0:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa1:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa2:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa3:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa4:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa5:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa6:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa7:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa8:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xa9:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xaa:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xab:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xac:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xad:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xae:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xaf:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_23x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb0:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb1:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb2:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb3:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb4:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb5:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb6:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb7:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb8:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xb9:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xba:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xbb:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xbc:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xbd:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xbe:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xbf:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc0:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc1:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc2:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc3:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc4:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc5:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc6:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc7:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc8:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xc9:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xca:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xcb:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xcc:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xcd:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xce:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xcf:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_12x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd0:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd1:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd2:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd3:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd4:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd5:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd6:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd7:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22s(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd8:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xd9:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xda:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xdb:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xdc:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xdd:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xde:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xdf:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe0:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe1:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe2:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_22b(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe3:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe4:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe5:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe6:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe7:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe8:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xe9:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xea:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xeb:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xec:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xed:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xee:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xef:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf0:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf1:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf2:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf3:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf4:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf5:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf6:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf7:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf8:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xf9:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_10x(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xfa:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_45cc(bytecode,
                                                        current_offset)
                elif bytecode[current_offset] == 0xfb:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_4rcc(bytecode,
                                                        current_offset)
                elif bytecode[current_offset] == 0xfc:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_35c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xfd:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_3rc(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xfe:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                elif bytecode[current_offset] == 0xff:
                    opcode += "{:02x}".format(bytecode[current_offset])
                    current_offset = self.__format_21c(bytecode,
                                                       current_offset)
                else:
                    current_offset += 1
                    break

                if current_offset > bytecode_size:
                    break

        except Exception:
            raise GenerateDexofuzzyError("Unable to extract opcode")
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
            raise GenerateDexofuzzyError("Unable to extract format_10x")
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
        offset += 5
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
