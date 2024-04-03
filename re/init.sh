#!/bin/sh

# increase stack size to avoid segfault
ulimit -s 65520

# create data directory
cd ..
mkdir -p data
cd re

# build experiments
cd src
make

# run cache experiments
sudo ./evset_gen.out
