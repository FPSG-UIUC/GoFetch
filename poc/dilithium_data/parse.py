
import argparse
import re
import os
import numpy as np
import pdb

# Define macros
top_32_target = 0x140
cs1_target = 8380417
bottom_frame = 0x10000
# Define Directory
msg_output_dir = "./dilithium_msg"
c_output_dir = "./dilithium_c"
z_output_dir = "./dilithium_z"
y_output_dir = "./dilithium_y"
c_parse_output_dir = "./dilithium_c_parsed"

def parse_file(fn):
    total_sig = 0
    mul_ptr_sig = 0
    
    start = 0
    hit_on_y = -1
    hit_on_z = -1
    seed = None

    # Initialize coef analysis
    coef_analy = {}
    for ptr_idx in range(1024//2):  # 2 coefs makes one ptr
        coef_analy[ptr_idx] = {"seed": "", "num_sig": 0, 
                               "good_sig": 0, "msg": [], 
                               "c": [], "z": [], "y": []}
    # Read file
    file1 = open(fn, 'r')
    for line_idx, line in enumerate(file1):
        # Examine Seed Consistency
        if("seed" in line):
            cur_seed = re.sub("[^0-9]", repl= ' ', string=line.split("seed")[1]).strip().split()
            if not seed:
                seed = cur_seed
            else:
                if seed != cur_seed:
                    print(f"Current Seed {cur_seed}")
                    print(f"Global Seed: {seed}")
                    exit(1)
        # Start Signature Transaction
        if("Got upper 32" in line):
            start = 1
        # Detect Duplicated Pointer for single message, stop
        if("Duplicated pointer" in line):
            assert start == 1
            start = 0
            mul_ptr_sig += 1
            total_sig += 1
        # Read Message
        if((start==1) and ("m" in line)):
            msg_cur = re.sub("[^0-9]", repl= ' ', string=line.split("m")[1]).strip()
        # Read y
        if((start==1) and ("y" in line)):
            y_list = re.sub("[^0-9]", repl= ' ', string=line.split("y")[1]).strip().split()
            try:
                assert len(y_list)==1024  # 4 polys * 256 ranks
            except AssertionError:
                print("y length is %d" % len(y_list) )
            # Test if y has upper 0x140
            for idx, x in enumerate(y_list):
                if((idx%2==0) and (int(y_list[idx+1])==top_32_target)):
                    assert hit_on_y == -1
                    assert int(x) & 0xffffc000 == bottom_frame
                    hit_on_y = idx
                    coef_analy[hit_on_y // 2]["good_sig"] += 1
        # Read cs1
        if((start==1) and ("cs1" in line)):
            cs1_list = re.sub("[^0-9]", repl= ' ', string=line.split("cs1")[1]).strip().split()
            try:
                assert len(cs1_list)==1024
            except AssertionError:
                print("cs1 length is %d" % len(cs1_list) )
            if hit_on_y != -1:  # if hit_on_y is found then cs1 should be target
                try:
                    assert int(cs1_list[hit_on_y+1]) == cs1_target
                except AssertionError:
                    pdb.set_trace()
        # Read sig.z and stop
        if((start==1) and ("sig.z" in line)):
            z_list = re.sub("[^0-9]", repl= ' ', string=line.split("sig.z")[1]).strip().split()
            try:
                assert len(z_list)==1024
            except AssertionError:
                print("sig.z length is %d" % len(z_list) )
            # Test if z has upper 0x140
            for idx, x in enumerate(z_list):
                if((idx%2==0) and (int(z_list[idx+1])==top_32_target)):
                    assert hit_on_z == -1
                    try:
                        assert int(x) & 0xffffc000 == bottom_frame
                    except AssertionError:
                        pdb.set_trace()
                    hit_on_z = idx
                    if hit_on_y != -1:
                        assert hit_on_z == hit_on_y
                    coef_analy[hit_on_z // 2]["num_sig"] += 1
                    coef_analy[hit_on_z // 2]["msg"].append(msg_cur)
                    coef_analy[hit_on_z // 2]["z"].append(hex(int(x) | (int(z_list[idx+1]) << 32)))
                    coef_analy[hit_on_z // 2]["y"].append(hex(int(y_list[idx]) | (int(y_list[idx+1]) << 32)))
            assert hit_on_z != -1
        if((start==1) and ("c " in line)):
            c_cur = re.sub("[^0-9]", repl= ' ', string=line.split("c")[1]).strip().split()
            if hit_on_z != -1:
                coef_analy[hit_on_z // 2]["c"].append(" ".join(c_cur))
            hit_on_z = -1
            hit_on_y = -1
            start = 0
            total_sig += 1

    
    print(f"Match upper 32 (0x140) -> {total_sig}\nPotential pointer existence -> {mul_ptr_sig}\nSingle pointer existence -> {total_sig-mul_ptr_sig}")
    if not os.path.exists(msg_output_dir):
        os.makedirs(msg_output_dir)
    if not os.path.exists(z_output_dir):
        os.makedirs(z_output_dir)
    if not os.path.exists(y_output_dir):
        os.makedirs(y_output_dir)
    if not os.path.exists(c_output_dir):
        os.makedirs(c_output_dir)
    
    for ptr_idx in range(1024//2):
        print(f"Pointer {ptr_idx}: #Signature -> {coef_analy[ptr_idx]['num_sig']}, #Good Signature -> {coef_analy[ptr_idx]['good_sig']}")
        with open(msg_output_dir + f"/msg_{ptr_idx}.txt", 'w') as f_msg:
            for msg in coef_analy[ptr_idx]["msg"]:
                f_msg.write(msg)
                f_msg.write("\n")
        with open(z_output_dir + f"/z_{ptr_idx}.txt", 'w') as f_msg:
            for msg in coef_analy[ptr_idx]["z"]:
                f_msg.write(msg)
                f_msg.write("\n")
        with open(y_output_dir + f"/y_{ptr_idx}.txt", 'w') as f_msg:
            for msg in coef_analy[ptr_idx]["y"]:
                f_msg.write(msg)
                f_msg.write("\n")
        with open(c_output_dir + f"/c_{ptr_idx}.txt", 'w') as f_msg:
            for msg in coef_analy[ptr_idx]["c"]:
                f_msg.write(msg)
                f_msg.write("\n")

def parse_c():
    if not os.path.exists(c_parse_output_dir):
        os.makedirs(c_parse_output_dir)
    poly_idx_list = np.linspace(start=0, stop=255, num=256, dtype=int)
    rotation_matrix = np.zeros((256,256), dtype=int)
    sign_matrix = np.zeros((256,256), dtype=int)
    for i in range(256):
        for j in range(256):
            c = 1
            if j < i:
                c = -1
            rotation_matrix[i][j] = poly_idx_list[(j-i)%256]
            sign_matrix[i][j] = c
    
    for ptr_idx in range(1024//2):
        with open(c_output_dir + f"/c_{ptr_idx}.txt", 'r') as f_c:
            c_str_vec = f_c.readlines()
        with open(c_parse_output_dir + f"/cp_{ptr_idx}.txt", 'w') as f_cp:
            for c_str in c_str_vec:
                c = [int(chara) for chara in c_str.strip().split(' ')]
                v = [str(sign*c[idx]%cs1_target) for sign, idx in zip(sign_matrix[:,(2*ptr_idx+1)%256], rotation_matrix[:,(2*ptr_idx+1)%256])]
                v = ['0']*((2*ptr_idx+1)//256)*256 + v + ['0']*(1024//256 - 1 - (2*ptr_idx+1)//256)*256
                assert len(v) == 1024
                f_cp.write((' ').join(v))
                f_cp.write("\n")

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('file')

    
    args = parser.parse_args()
    file_name = args.file

    parse_file(file_name)
    parse_c()


if __name__ == "__main__":
    main()