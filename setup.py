# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
from dexofuzzy import __title__, __version__, __license__

setup(
    name=__title__,
    version=__version__,
    url='https://github.com/ESTsecurity/Dexofuzzy',
    author='Shinho Lee, Wookhyun Jung, Sangwon Kim',
    author_email='lee1029ng@estsecurity.com, pplan5872@estsecurity.com, bestksw@estsecurity.com',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: '+__license__,
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    license=__license__,
    description='Dexofuzzy : Dalvik EXecutable Opcode Fuzzyhash',
    long_description=open("README.rst").read(),
    long_description_content_type='text/x-rst',
    keywords=[
        'Android Malware Similarity using Method Opcode Sequence',
        'Android Malware Similarity Fuzzyhash',
        'Method Opcode Sequence Fuzzyhash',
    ],
    packages=find_packages(exclude=[]),
    include_package_data=True,
    install_requires=[
        'ssdeep; platform_system!="Windows"',
        'filetype',
    ],
    python_requires='>=3',
    entry_points={
        'console_scripts': [
            'dexofuzzy=dexofuzzy.main:main',
        ],
    },
    ext_package="dexofuzzy",
)
