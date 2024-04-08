# Patch Circl Dilithium for Signature Collection
Install the CIRCL library `git clone https://github.com/cloudflare/circl.git`.
Go to `circl/sign/dilithium/mode2/internal`.

## Patch `dilithium.go`
Add a function `SignTo_Collection` to the file `dilithium.go`, which is modified from the original sign function `SignTo` and dumps relevant value for those having potential to inject valid pointers to `y`.
```
func SignTo_Collection(sk *PrivateKey, msg []byte, signature []byte) {
	var mu, rhop [64]byte
	var w1Packed [PolyW1Size * K]byte
	var y, yh VecL
	var w, w0, w1, w0mcs2, ct0, w0mcs2pct0 VecK
	var ch common.Poly
	var yNonce uint16
	var sig unpackedSignature

	// fixme
	var cs1 VecL

	if len(signature) < SignatureSize {
		panic("Signature does not fit in that byteslice")
	}

	//  μ = CRH(tr ‖ msg)
	h := sha3.NewShake256()
	_, _ = h.Write(sk.tr[:])
	_, _ = h.Write(msg)
	_, _ = h.Read(mu[:])

	// ρ' = CRH(key ‖ μ)
	h.Reset()
	_, _ = h.Write(sk.key[:])
	_, _ = h.Write(mu[:])
	_, _ = h.Read(rhop[:])

	// Main rejection loop
	attempt := 0
	for {
		attempt++
		if attempt >= 576 {
			// Depending on the mode, one try has a chance between 1/7 and 1/4
			// of succeeding.  Thus it is safe to say that 576 iterations
			// are enough as (6/7)⁵⁷⁶ < 2⁻¹²⁸.
			panic("This should only happen 1 in  2^{128}: something is wrong.")
		}

		// y = ExpandMask(ρ', key)
		VecLDeriveUniformLeGamma1(&y, &rhop, yNonce)
		yNonce += uint16(L)

		// Set w to A y
		yh = y
		yh.NTT()
		for i := 0; i < K; i++ {
			PolyDotHat(&w[i], &sk.A[i], &yh)
			w[i].ReduceLe2Q()
			w[i].InvNTT()
		}

		// Decompose w into w₀ and w₁
		w.NormalizeAssumingLe2Q()
		w.Decompose(&w0, &w1)

		// c~ = H(μ ‖ w₁)
		w1.PackW1(w1Packed[:])
		h.Reset()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed[:])
		_, _ = h.Read(sig.c[:])

		PolyDeriveUniformBall(&ch, &sig.c)
		ch.NTT()

		// Ensure ‖ w₀ - c·s2 ‖_∞ < γ₂ - β.
		//
		// By Lemma 3 of the specification this is equivalent to checking that
		// both ‖ r₀ ‖_∞ < γ₂ - β and r₁ = w₁, for the decomposition
		// w - c·s₂	 = r₁ α + r₀ as computed by decompose().
		// See also §4.1 of the specification.
		for i := 0; i < K; i++ {
			w0mcs2[i].MulHat(&ch, &sk.s2h[i])
			w0mcs2[i].InvNTT()
		}
		w0mcs2.Sub(&w0, &w0mcs2)
		w0mcs2.Normalize()

		if w0mcs2.Exceeds(Gamma2 - Beta) {
			continue
		}

		// z = y + c·s₁
		for i := 0; i < L; i++ {
			sig.z[i].MulHat(&ch, &sk.s1h[i])
			sig.z[i].InvNTT()
		}

		cs1 = sig.z
		sig.z.Add(&sig.z, &y)
		sig.z.Normalize()

		// Ensure  ‖z‖_∞ < γ₁ - β
		if sig.z.Exceeds(Gamma1 - Beta) {
			continue
		}

		// Compute c·t₀
		for i := 0; i < K; i++ {
			ct0[i].MulHat(&ch, &sk.t0h[i])
			ct0[i].InvNTT()
		}
		ct0.NormalizeAssumingLe2Q()

		// Ensure ‖c·t₀‖_∞ < γ₂.
		if ct0.Exceeds(Gamma2) {
			continue
		}

		// Create the hint to be able to reconstruct w₁ from w - c·s₂ + c·t0.
		// Note that we're not using makeHint() in the obvious way as we
		// do not know whether ‖ sc·s₂ - c·t₀ ‖_∞ < γ₂.  Instead we note
		// that our makeHint() is actually the same as a makeHint for a
		// different decomposition:
		//
		// Earlier we ensured indirectly with a check that r₁ = w₁ where
		// r = w - c·s₂.  Hence r₀ = r - r₁ α = w - c·s₂ - w₁ α = w₀ - c·s₂.
		// Thus  MakeHint(w₀ - c·s₂ + c·t₀, w₁) = MakeHint(r0 + c·t₀, r₁)
		// and UseHint(w - c·s₂ + c·t₀, w₁) = UseHint(r + c·t₀, r₁).
		// As we just ensured that ‖ c·t₀ ‖_∞ < γ₂ our usage is correct.
		w0mcs2pct0.Add(&w0mcs2, &ct0)
		w0mcs2pct0.NormalizeAssumingLe2Q()
		hintPop := sig.hint.MakeHint(&w0mcs2pct0, &w1)
		if hintPop > Omega {
			continue
		}

		break
	}
	// check if this signature contains a zi||zi+1 that looks like a pointer
	var pointer int
	pointer = 0
	var pointer_num int
	pointer_num = 0
	for i := 0; i < L; i++ {
		for j := 0; j < common.N; j++ {
			if j%2 == 0 {
				curr_coef := sig.z[i][j]
				next_coef := sig.z[i][j+1]
				// curr_coef -> zi+1; next_coef -> zi (little edian)
                // next_coef == 320 (0x140) for go allocates valid memory region with upper 32 bits == 0x140
				// (curr_coef&16256 != 0 and curr_coef&16256 != 16256) 16256=0b11111110000000 to avoid cross page corner case.
				// 0xffffc000 = 4294950912 as a mask to enforce page frame part to 0x010000 = 65536 (could be other value)
				if (next_coef == uint32(320)) && (curr_coef&uint32(16256) != uint32(16256)) && (curr_coef&uint32(16256) != 0) && (curr_coef&uint32(4294950912) == uint32(65536)) {
					pointer = 1
					fmt.Println("[+] Got upper 32 = 0x140 with lower 32 fixed frame 0x10000")
				}
                // consider false positive y as well
				if next_coef <= uint32(320+78) && next_coef >= uint32(320-78) {
					pointer_num = pointer_num + 1
				}
			}
		}
	}
    // dump relevant values
	if (pointer == 1) && (pointer_num == 1) {
		var c common.Poly
		PolyDeriveUniformBall(&c, &sig.c)
		fmt.Println("m", msg)
		fmt.Println("y", y)
		fmt.Println("cs1", cs1)
		fmt.Println("sig.z", sig.z)
		fmt.Println("c", c)
	}
    // make sure only one zi||zi+1 has potential to inject pointer to y
	if (pointer == 1) && (pointer_num > 1) {
		fmt.Println("[+] Duplicated pointer like value")
	}
	sig.Pack(signature[:])
}
```

## Patch `dilithium_test.go`
Add a function `BenchmarkSign_Attack` to the file `dilithium_test.go`, which is modified from the original sign testbench `BenchmarkSign`. The private key depends on the random seed. We set it as all zeros by default.
```
func BenchmarkSign_Attack(b *testing.B) {
	// Note that the expansion of the matrix A is done at Unpacking/Keygen
	// instead of at the moment of signing (as in the reference implementation.)
	var seed [32]byte
	var msg [8]byte
	var sig [SignatureSize]byte
	// fixme: set seed to be anything you want
	fmt.Println("seed", seed)
	_, sk := NewKeyFromSeed(&seed)
	b.ResetTimer()
	fmt.Println("bn", b.N)
	rand.Seed(time.Now().UnixNano())
	start_value := rand.Uint64()
	for i := start_value; i < start_value+uint64(b.N); i++ {
		binary.LittleEndian.PutUint64(msg[:], uint64(i))
		SignTo_Collection(sk, msg[:], sig[:])
	}
}
```

## Run signature collections
Run collection script `collection.sh` with arguments that specify the total number of signature requests and the number of process spawn to speed up the collection.

Run the python script `parse.py` to parse the output file generated by the collection script, which prepares the necessary information for the poc attacker.