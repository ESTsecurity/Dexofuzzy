"""
This is a Python wrapper for ssdeep by Jesse Kornblum (http://ssdeep.sourceforge.net).
Inspired by python-ssdeep (https://github.com/DinoTools/python-ssdeep).
"""
import os
import sys
import ctypes
from os.path import join
from os.path import split
from pip._vendor import six


# Length of an individual fuzzy hash signature component
SPAMSUM_LENGTH = 64

# The longest possible length for a fuzzy hash signature
FUZZY_MAX_RESULT = (2 * SPAMSUM_LENGTH + 20)


class FuzzyLibError(Exception):
    def __init__(self, error_number):
        self.error_number = error_number


is_64bits = sys.maxsize > 2**32
_package_path = split(__file__)[0]
_lib_path = join(_package_path, r'fuzzy_64.dll' if is_64bits else r'fuzzy.dll')
fuzzy_lib = ctypes.cdll.LoadLibrary(_lib_path)


def compare(signature_1, signature_2):
    """Computes the match score between two fuzzy hash signatures.
    A match score of zero indicates the signatures did not match.

    :param str|unicode|bytes signature_1: First fuzzy hash signature
    :param str|unicode|bytes signature_2: Second fuzzy hash signature
    :return: A value from zero to 100 indicating the match score of the two signatures
    :rtype: int
    :raises FuzzyLibError: If the fuzzy library returns an internal error
    :raises TypeError: If one of the signatures type is not str, unicode or bytes
    """
    if isinstance(signature_1, six.text_type):
        signature_1 = signature_1.encode('ascii')
    if isinstance(signature_2, six.text_type):
        signature_2 = signature_2.encode('ascii')

    if not isinstance(signature_1, six.binary_type):
        raise TypeError('"signature_1" must be of binary or text type')
    if not isinstance(signature_2, six.binary_type):
        raise TypeError('"signature_2" must be of binary or text type')

    hash_1_buffer = ctypes.create_string_buffer(signature_1)
    hash_2_buffer = ctypes.create_string_buffer(signature_2)
    compare_result = fuzzy_lib.fuzzy_compare(hash_1_buffer, hash_2_buffer)

    if compare_result == -1:
        raise FuzzyLibError(compare_result)

    return compare_result


def hash(data, encoding='utf-8'):
    """Compute the fuzzy hash of a string or binary data.

    :param str|unicode|bytes data: The data to be fuzzy hashed
    :param str|unicode encoding: The encoding that will be used to encode data if it is a string
    :return: The fuzzy hash of the data
    :rtype: str|unicode
    :raises FuzzyLibError: If the fuzzy library returns an internal error
    :raises TypeError: If data is not str, unicode or bytes
    """
    if not isinstance(encoding, six.string_types):
        raise TypeError('"encoding" must be of string type')

    if isinstance(data, six.text_type):
        data = data.encode(encoding)

    if not isinstance(data, six.binary_type):
        raise TypeError('"data" must be of binary or text type')

    result_buffer = ctypes.create_string_buffer(FUZZY_MAX_RESULT)
    file_buffer = ctypes.create_string_buffer(data)
    # Ignoring the terminating null byte
    hash_result = fuzzy_lib.fuzzy_hash_buf(file_buffer, len(file_buffer) - 1, result_buffer)
    if hash_result != 0:
        raise FuzzyLibError(hash_result)

    hash_value = result_buffer.value.decode('ascii')
    return hash_value


def hash_from_file(file_path):
    """
    Compute the fuzzy hash of a file.

    :param str|unicode file_path: The path of the file to be hashed
    :return: The fuzzy hash of the file
    :rtype: str|unicode
    :raises IOError: If Python is unable to read the file
    :raises FuzzyLibError: If the fuzzy library returns an internal error
    """
    if not isinstance(file_path, six.string_types):
        raise TypeError('"file_path" must be of string type')

    if not os.path.exists(file_path):
        raise IOError("Path not found")
    if not os.path.isfile(file_path):
        raise IOError("Not a file")
    if not os.access(file_path, os.R_OK):
        raise IOError("File is not readable")

    result_buffer = ctypes.create_string_buffer(FUZZY_MAX_RESULT)
    file_path_buffer = ctypes.create_string_buffer(file_path.encode('utf-8'))
    hash_result = fuzzy_lib.fuzzy_hash_filename(file_path_buffer, result_buffer)
    if hash_result != 0:
        raise FuzzyLibError(hash_result)

    hash_value = result_buffer.value.decode('ascii')
    return hash_value
