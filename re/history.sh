#!/bin/zsh

trials=$1; shift  # number of trials
BIN=./src/l2l1_fetch.out  # exp binary
core_id=4  # 4-7 p core
test_idx=0  # test pointer index
evict_option=2 # L2 evict
precache_option=0 # no pre-cache

# increase stack size to avoid segfault
ulimit -s 65520

# number of dummy pointers to clean history
for num_ptrs in 0 1 2 4 8 16 32 64 128 256; do
    rm -rf out
    mkdir -p out
    data_file_directory="../data/l1l2fetch/${num_ptrs}_${evict_option}_${precache_option}"
    # Start test
    trial=0
    while [[ $trial -lt $trials ]]; do
        outdir="${data_file_directory}/${trial}"
        mkdir -p $outdir

        echo "====== EVICT($evict_option)/PRECACHE($precache_option)/TRIAL($trial) ======"

        successful=0
        while [[ $successful -eq 0 ]]; do
            successful=1
            sudo $BIN $core_id $test_idx $num_ptrs $evict_option $precache_option \
                || successful=0
        done

        mv -f out/atk.txt "${outdir}/atk_${test_idx}.txt"
        ((trial+=1))
        sleep 1
    done
done
