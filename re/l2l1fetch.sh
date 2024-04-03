#!/bin/zsh

trials=$1; shift  # number of trials
num_ptrs=$1; shift  # dummy pointers to clean history
BIN=./src/l2l1_fetch.out  # exp binary
core_id=4  # 4-7 p core
test_idx=0  # test pointer index

# increase stack size to avoid segfault
ulimit -s 65520

# evict options (1: L1 evict, 2: L2 evict)
for evict_option in 2 1; do
    # pre-cache options (0: no, 1: yes)
    for precache_option in 0 1; do
        if [[ evict_option -eq 1 && precache_option -eq 1 ]]; then
            echo "No need to pre-cache for L1 evict"
            continue
        fi
        if [[ evict_option -eq 2 && precache_option -eq 0 ]]; then
            echo "DRAM access has been measured in history.sh"
            continue
        fi
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
done
