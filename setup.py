#!/usr/bin/python

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="quickcov-egueler",
    version="0.0.1",
    author="Emre Gueler",
    author_email="emre.gueler@ruhr-uni-bochum.de",
    description="QuickCov: quickly get code coverage (by leveraging AFL forkserver inside)",
    long_description=long_description,
    url="https://github.com/egueler/quickcov",
    packages=setuptools.find_packages(),
    include_package_data=True,
    package_data={'': ["aflforkserver.so", "afl-qemu-trace"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)