#!/bin/zsh
num_message=$1; shift
num_process=$1; shift

bucket=$((num_message / num_process))
echo "Num of Message: $num_message"
echo "Num of process: $num_process"
echo "Num of message per process: $bucket"

for ((process_idx = 0; process_idx < num_process; process_idx++)); do
    echo "process_idx $process_idx start"
    rm -f col_${process_idx}.txt
    go test -bench BenchmarkSign_Attack -benchtime=${bucket}x -timeout 24h > col_${process_idx}.txt &
    sleep 1s
done
wait
rm -f col_all.txt
touch col_all.txt
for ((process_idx = 0; process_idx < num_process; process_idx++)); do
    cat col_${process_idx}.txt >> col_all.txt
done
echo "Collection Finish"
