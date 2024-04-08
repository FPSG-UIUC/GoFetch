from lwe_with_hints import *
import numpy as np
import time
from random import randrange


KYBER_N = 256
q = 3329
k = 2
n = 512
# load public value A, t
with open("crypto_attacker/kyber_pub.txt", 'r') as f_pub:
    pub_list = f_pub.read().splitlines()
A = pub_list[0:KYBER_N*4]
A = [int(A[i]) for i in range(len(A))]
A = [A[0:KYBER_N], A[KYBER_N:2*KYBER_N], A[2*KYBER_N:3*KYBER_N], A[3*KYBER_N:4*KYBER_N]]
A = module(A, k, k)
t = pub_list[KYBER_N*4:KYBER_N*6]
t = np.block([int(t[i]) for i in range(len(t))]) % q

# generate lattice
lattice = LWELattice(A, t, q, verbose=True)

# open guess secret key file
with open("crypto_attacker/kyber.txt") as f_a:
    guess_key = f_a.read().splitlines()
guess_s = [0]*n
for i in range(len(guess_key)):
    bit_id = int(guess_key[i].split(',')[0].split(':')[1])
    guess_value = int(guess_key[i].split(',')[1].split(':')[1])
    guess_s[bit_id] = guess_value

# generate modular hint
for i in range(392):
    v = np.array([ randrange(q) for _ in range(n) ])
    for poly_id in range(2):
        for u64_id in range(4):
            for bit_id in range(0, 64):
                if (bit_id < 7) or (bit_id > 55):
                    # print(f"{bit_id} is zeroed")
                    global_id = bit_id + u64_id * 64 + poly_id * 256
                    v[global_id] = 0
    l = v.dot(guess_s)
    lattice.integrateModularHint( v, l % q, q )

# lattice reduction
start = time.time()
lattice.reduce()
end = time.time()

print(f"[+] Finishing -> Time consumption: {end-start}")
print(lattice.s)
with open('crypto_attacker/kyber_reduction.txt', 'w') as f_r:
    for i in range(len(lattice.s)):
        f_r.write(f"{lattice.s[i]}\n")

# open secret key file and compare
with open("crypto_victim/kyber.txt") as f_v:
    secret_key = f_v.read().splitlines()
count = 0
for i in range(len(secret_key)):
    if int(secret_key[i]) == lattice.s[i]:
        count += 1
print(f"Accuracy: {count}/{len(secret_key)}")
