package main

import "C"

import (
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

// Global variable
var privateKey *mode2.PrivateKey

//export Init
func Init() uint {
	var seed [mode2.SeedSize]byte
	fmt.Println("Seed:", seed)
	// Generate Key
	pk_temp, sk_temp := mode2.NewKeyFromSeed(&seed)
	privateKey = sk_temp
	// Store Private Key
	cur_s1, cur_s2 := privateKey.Dump_s()
	f_s, _ := os.Create("dilithium_priv.txt")
	defer f_s.Close()
	f_s.WriteString(fmt.Sprintf("%d\n", cur_s1))
	f_s.WriteString(fmt.Sprintf("%d\n", cur_s2))
	// fmt.Println("s1", cur_s1)
	// fmt.Println("s1", cur_s2)
	// Store public Key A and t
	// A
	cur_A := *(pk_temp.A)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			cur_A[i][j].InvNTT()
		}
	}
	// fmt.Println("A", *cur_A)
	// t
	cur_t := privateKey.Dump_t()
	// fmt.Println("t", cur_t)
	f_pub, _ := os.Create("dilithium_pub.txt")
	defer f_pub.Close()
	f_pub.WriteString(fmt.Sprintf("%d\n", cur_A))
	f_pub.WriteString(fmt.Sprintf("%d\n", cur_t))
	return 0
}

//export Victim
func Victim(input_msg []byte) uint {
	var sig [mode2.SignatureSize]byte
	mode2.SignTo(privateKey, input_msg, sig[:])
	return 0
}


func main() {
	// C library for Dilithium
}
