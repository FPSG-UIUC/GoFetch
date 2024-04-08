# Patch Circl Go Library to Support Dilithium PoC

## File 1
Go to file `/Users/<user_name>/go/pkg/mod/github.com/cloudflare/circl@v1.3.3/sign/dilithium/mode2/dilithium.go`. And add the following helper functions.

```
/* Start of DMP */
type VecL internal.VecL
type VecK internal.VecK
func (sk *PrivateKey) Dump_s() (VecL, VecK) {
	return (VecL)((*internal.PrivateKey)(sk).Dump_s1()), (VecK)((*internal.PrivateKey)(sk).Dump_s2())
}

func (sk *PrivateKey) Dump_t() VecK {
	return (VecK)((*internal.PrivateKey)(sk).Dump_t())
}
```

## File 2
Go to file `/Users/<user name>/go/pkg/mod/github.com/cloudflare/circl@v1.3.3/sign/dilithium/mode2/internal/dilithium.go`. And add the following helper functions.
```
/* Start of DMP */
func (sk *PrivateKey) Dump_s1() VecL {
	return sk.s1
}

func (sk *PrivateKey) Dump_s2() VecK {
	return sk.s2
}

// Computes t0 and t1 from sk.s1h, sk.s2 and sk.A.
func (sk *PrivateKey) Dump_t() VecK {
	var t VecK

	// Set t to A s₁ + s₂
	for i := 0; i < K; i++ {
		PolyDotHat(&t[i], &sk.A[i], &sk.s1h)
		t[i].ReduceLe2Q()
		t[i].InvNTT()
	}
	t.Add(&t, &sk.s2)
	t.Normalize()
	return t
}
```

Insert following line to the function `SignTo(sk *PrivateKey, msg []byte, signature []byte)` to profile the address of the `z` and `y` array.
```
println("y addr -> ", &y[0][0])
println("z addr ->", &(sig.z[0][0]))
```