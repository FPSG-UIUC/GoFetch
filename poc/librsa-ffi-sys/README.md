# Patch Go Library to Support RSA PoC

## File 1
Go to file `/usr/local/go/src/crypto/internal/bigmod/nat.go`. And add the following helper functions. `GetLimbsAddr()` is used to uncover the start address of the `limbs` array inside the `Nat` structure. `GetNat()` will return the `Nat` inside the `Modulus` structure.

```
/* start of nat dmp */

func (x *Nat) GetLimbsAddr() *uint {
	return &x.limbs[0]
}

func (m *Modulus) GetNat() *Nat {
	return m.nat
}
```

Insert following line to the function `Exp(x *Nat, e []byte, m *Modulus)` to profile the address of the `table`, which is a local copy of the chosen cipher. It turns out that it has different page offset to the target AoP `t0.limbs`, hence, won't introduce the false positive.
```
println("table[0] address %p", table[0])
```

## File 2
Go to file `/usr/local/go/src/crypto/rsa/rsa.go`. And add the following helper functions. The goal of this patch is to dump the secret keys owned by the victim, which won't forward to the attacker, but verify the success of the attack.

```
/* Start of DMP */

// Helper functions
func (priv *PrivateKey) Dump_PQ() {
	P := priv.Precomputed.p.GetNat().Bytes(priv.Precomputed.n)
	Q := priv.Precomputed.q.GetNat().Bytes(priv.Precomputed.n)
	N := priv.Precomputed.n.GetNat().Bytes(priv.Precomputed.n)
	fmt.Printf("N -> \n[% x](%d)\n", N, len(N)*8-leading_zero_bits(N))
	fmt.Printf("P -> \n[% x](%d)\n", P, len(N)*8-leading_zero_bits(P))
	fmt.Printf("Q -> \n[% x](%d)\n", Q, len(N)*8-leading_zero_bits(Q))
	f_priv, _ := os.Create("rsa_priv.txt")
	defer f_priv.Close()
	f_priv.WriteString(fmt.Sprintf("%x\n", P))
	f_priv.WriteString(fmt.Sprintf("%x\n", Q))
	f_priv.Sync()
	f_pub, _ := os.Create("rsa_pub.txt")
	defer f_pub.Close()
	f_pub.WriteString(fmt.Sprintf("%x\n", N))
	f_pub.Sync()
}

func leading_zero_bits(x []byte) int {
	num_leading_zero_bits := 0
	var non_zero, mask_bit byte
	for i := 0; i < len(x); i++ {
		if x[i] == 0 {
			num_leading_zero_bits += 8
		} else {
			non_zero = x[i]
			break
		}
	}
	mask_bit = 0b10000000
	for i := 0; i < 8; i++ {
		if (non_zero & mask_bit) == 0b0 {
			num_leading_zero_bits += 1
		} else {
			break
		}
		mask_bit = mask_bit >> 1
	}

	return num_leading_zero_bits
}
```

Insert following line to the function `decrypt(priv *PrivateKey, ciphertext []byte, check bool)` to profile the address of the `t0.limbs`, which stores the output of `c mod p` and `c mod q`.
```
println("P -> t0.limbs addr %p", t0.GetLimbsAddr())
println("Q -> t0.limbs addr %p", t0.GetLimbsAddr())
```