#!/bin/zsh

trials=$1; shift  # number of trials
BIN=./src/no_deref.out  # exp binary
core_id=4  # 4-7 p core
victim_size=1  # size of the victim array
num_ptrs=1  # number of inserted pointers
ptr_start=0  # index where pointer start
num_touch=1  # number of touched entries in the victim array
bit_flip_position=64  # no bit flip for stored pointer value
touch_start=0  #  index of the first touched entry

# test offset = 1 -> test next line wrt the point mapped by the pointer
for test_offset in 1 2; do
	rm -rf out
	mkdir -p out
	data_file_directory="../data/noderef/${victim_size}_${num_ptrs}_${ptr_start}_${test_offset}_${bit_flip_position}_${num_touch}_${touch_start}"
	# Start test
	trial=0
	while [[ $trial -lt $trials ]]; do
		outdir="${data_file_directory}/${trial}"
		mkdir -p $outdir

		test_idx=0
		while [[ $test_idx -lt $num_ptrs ]]; do
			echo "====== TEST_IDX($test_idx)/NUM_PTR($num_ptrs)/AOP_SIZE($victim_size)/TRIAL($trial) ======"

			successful=0
			while [[ $successful -eq 0 ]]; do
				successful=1
				sudo $BIN $core_id $victim_size $num_ptrs $ptr_start $test_idx $test_offset $bit_flip_position $num_touch $touch_start \
					|| successful=0
			done

			mv -f out/atk.txt "${outdir}/atk_${test_idx}.txt"
			mv -f out/base.txt "${outdir}/base_${test_idx}.txt"

			((test_idx+=1))
			sleep 1
		done
		((trial+=1))
	done
done
