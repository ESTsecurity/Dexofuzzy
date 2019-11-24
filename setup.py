# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages

about = {}
with open(os.path.join(os.path.abspath(os.path.dirname(__file__)),
                       'dexofuzzy', '__version__.py')) as f:
    exec(f.read(), about)

with open('README.rst') as f:
    readme = f.read()

setup(
    name=about['__title__'],
    version=about['__version__'],
    description=about['__description__'],
    long_description=readme,
    long_description_content_type='text/x-rst',
    author=about['__author__'],
    author_email=about['__author_email__'],
    url=about['__url__'],
    license=about['__license__'],
    python_requires='>=3',
    include_package_data=True,
    ext_package="dexofuzzy",
    packages=find_packages(exclude=[]),
    install_requires=['ssdeep; platform_system!="Windows"'],
    entry_points={
        'console_scripts': [
            'dexofuzzy=dexofuzzy.cli:execute_from_command_line'
        ],
    },
    keywords=[
        'android', 'malware', 'opcode', 'similarity', 'clustering', 'n-gram',
        'hash', 'fuzzyhash'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: '+about['__license__'],
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy'
    ],
)
