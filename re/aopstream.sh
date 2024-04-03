#!/bin/zsh

victim_size=$1; shift  # size of the victim array
training_length=$1; shift  # number of in-bound pointers
trials=$1; shift  # number of trials
BIN=./src/aop_stream.out  # exp binary
core_id=4  # 4-7 p core

# Check input
if [[ $training_length -gt $victim_size ]]; then
	echo "Training Length exceeds Array Size!!"
	exit 1
fi

# Create data directory
rm -rf out
mkdir -p out
data_file_directory="../data/aopstream/${victim_size}_${training_length}"

# Start test
trial=0
while [[ $trial -lt $trials ]]; do
	outdir="${data_file_directory}/${trial}"
	mkdir -p $outdir

	test_idx=0
	while [[ $test_idx+$training_length -lt $victim_size ]]; do
		echo "====== TEST_IDX($test_idx)/TRAIN_LEN($training_length)/AOP_SIZE($victim_size)/TRIAL($trial) ======"

		successful=0
		while [[ $successful -eq 0 ]]; do
			successful=1
			sudo $BIN $core_id $victim_size $training_length $test_idx \
				|| successful=0
		done

		mv -f out/atk.txt "${outdir}/atk_${test_idx}.txt"
		mv -f out/base.txt "${outdir}/base_${test_idx}.txt"

		((test_idx+=1))
		sleep 1
	done
	((trial+=1))
done
