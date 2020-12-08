#!/bin/bash

make -j 
mv aflforkserver.so quickcov/
cp afl-qemu-trace quickcov/
python3 -m pip install .