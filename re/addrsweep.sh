#!/bin/zsh

stride=$1; shift  # stride of each sweep
sweep_times=$1; shift  # number of sweeps
data_buf_boundary=$1; shift  # start of the sweep address
trials=$1; shift  # number of trials
BIN=./src/addr_sweep.out  # exp binary
core_id=4  # 4-7 p core

# renew out directory
rm -rf out
mkdir -p out

data_file_directory="../data/addrsweep/${data_buf_boundary}_${stride}_${sweep_times}"
mkdir -p $data_file_directory

# test start
trial=0
while [[ $trial -lt $trials ]]; do
	outdir="${data_file_directory}/${trial}"
	mkdir -p $outdir
	echo "$trial / $trials"
	successful=0
	while [[ $successful -eq 0 ]]; do
		successful=1
		sudo $BIN $core_id \
			$stride $sweep_times $data_buf_boundary \
			|| successful=0
	done

	mv -f out/* "${outdir}/"
	((trial+=1))
	sleep 1
done
