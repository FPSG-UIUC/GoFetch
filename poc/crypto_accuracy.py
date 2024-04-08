import argparse
import numpy as np
import os
import pdb

# get rid of outliers
def clear_outlier(time_list):
    time_list = np.array(time_list)
    data_mean = time_list.mean()
    data_std = time_list.std()
    new_time_list = []
    for dp in time_list:
        if ((dp-data_mean)/data_std <= 3) and ((dp-data_mean)/data_std >= -3):
            new_time_list.append(dp)
    new_time_list = np.array(new_time_list)
    return new_time_list

def get_mean_std(file_path, object_name):
    with open(file_path, 'r') as f:
        time_list = [int(x) for x in f.readlines()]
    new_time_list = clear_outlier(time_list)
    print(f"{object_name}: mean->{new_time_list.mean()};std->{new_time_list.std()}")


parser = argparse.ArgumentParser()
parser.add_argument('--crypto', help="cryptographic algorithm", required=False, default='dh')
args = parser.parse_args()

# Output profile results
get_mean_std(f"crypto_attacker/{args.crypto}_0.txt", args.crypto)
get_mean_std(f"crypto_attacker/{args.crypto}_1.txt", args.crypto)

# Output accuracy results (only DMP directly recovered part)
if args.crypto == "dh":
    # open secret key file
    with open("crypto_victim/dh.txt") as f_v:
        secret_key = f_v.read()
    secret_key_list = [secret_key[i:i+2] for i in range(0, len(secret_key), 2)]
    # open guess secret key file
    with open("crypto_attacker/dh.txt") as f_a:
        guess_key = f_a.read()
        guess_key_list = [guess_key[i:i+2] for i in range(0, len(guess_key), 2)]
    # DH DMP leakage accuracy
    print("///////////////////////")
    print("/// DMP Leakage Accuracy Results ///")
    print("///////////////////////")
    count = 0
    assert len(secret_key_list) == len(guess_key_list)
    for i in range(len(secret_key_list)):
        if secret_key_list[i] == guess_key_list[i]:
            count += 1
        else:
            print(f"Byte {i} -> secret:{secret_key_list[i]}, guess:{guess_key_list[i]}")
    print(f"Accuracy: {count}/{len(secret_key_list)}")
elif args.crypto == "kyber":
    # open secret key file
    with open("crypto_victim/kyber.txt") as f_v:
        secret_key = f_v.read().splitlines()
    # open guess secret key file
    with open("crypto_attacker/kyber.txt") as f_a:
        guess_key = f_a.read().splitlines()
    # Kyber DMP leakage accuracy
    print("///////////////////////")
    print("/// DMP Leakage Accuracy Results ///")
    print("///////////////////////")
    count = 0
    for i in range(len(guess_key)):
        bit_id = int(guess_key[i].split(',')[0].split(':')[1])
        guess_value = guess_key[i].split(',')[1].split(':')[1]
        if guess_value == secret_key[bit_id]:
            count += 1
        else:
            print(f"Coeff {bit_id} -> secret:{secret_key[bit_id]}, guess:{guess_value}")
    print(f"Accuracy: {count}/{len(guess_key)}/{len(secret_key)}")
    # Execute kyber lattice reduction
    os.system("python kyber_reduction.py")
elif args.crypto == "rsa":
    # Load RSA private key
    with open("crypto_victim/rsa_priv.txt") as f_v:
        secret_key = f_v.read().splitlines()
        secret_key = [int(secret_key[i], 16) for i in range(len(secret_key))]
    big_prime_str = str(hex(max(secret_key)))[2:]
    big_prime_list = [big_prime_str[i:i+2] for i in range(0, len(big_prime_str), 2)]
    # Load RSA DMP leakage
    with open("crypto_attacker/rsa.txt") as f_a:
        guess_key = f_a.read().splitlines()
    # RSA DMP leakage accuracy
    print("///////////////////////")
    print("/// DMP Leakage Accuracy Results ///")
    print("///////////////////////")
    count = 0
    for i in range(len(guess_key)):
        if guess_key[i] == big_prime_list[i]:
            count += 1
        else:
            print(f"Byte {i} -> secret:{big_prime_list[i]}, guess:{guess_key[i]}")
    print(f"DMP Leakage Accuracy: {count}/{len(guess_key)}")

    # Execute Coppersmith
    os.system("python coppersmith.sage.py")

    # RSA Full Recovery Accuracy
    # Load RSA Fully recovered key
    with open("crypto_attacker/rsa.txt") as f_a:
        guess_key = f_a.read().splitlines()
    # RSA DMP leakage accuracy
    print("///////////////////////")
    print("/// RSA Key Recovery Accuracy Results ///")
    print("///////////////////////")
    count = 0
    for i in range(len(guess_key)):
        if guess_key[i] == big_prime_list[i]:
            count += 1
        else:
            print(f"Byte {i} -> secret:{big_prime_list[i]}, guess:{guess_key[i]}")
    print(f"RSA Key Recovery Accuracy: {count}/{len(guess_key)}")
elif args.crypto == "dilithium":
    # Ask for user input
    measure_list = input("Please add a measure list (e.g. 1 2 3): ")
    page_number = input("Please add a page number (e.g. 0x10000): ")
    num_hints = input("Please add number of mod-q hints to break dilithium (e.g. 876): ")
    neg = input("Please add use neg file or not (e.g. y/n): ")
    # parse input
    user_args = ""
    if measure_list != "":
        user_args += f"--measure_list {measure_list} "
    else:
        user_args += f"--measure_list 1 "
    if page_number != "":
        user_args += f"--page_number {page_number} "
    if num_hints != "":
        user_args += f"--num_hints {num_hints} "
    if neg == "y":
        user_args += f"--neg"
    # Execute dilithium lattice reduction
    os.system(f"python dilithium_reduction.py {user_args}")
else:
    exit(1)
