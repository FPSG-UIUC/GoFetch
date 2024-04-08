#ifndef KEM_H
#define KEM_H

#include "params.h"
#include <stdint.h>

#define crypto_kem_keypair KYBER_NAMESPACE(_keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_kem_enc KYBER_NAMESPACE(_enc)
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

#define crypto_kem_enc_attack KYBER_NAMESPACE(_enc_attack)
int crypto_kem_enc_attack(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk,
                   uint64_t* victim_pointer,
                   int index,
                   int flip,
                   uint64_t rand_mask);

#define crypto_kem_enc_fake KYBER_NAMESPACE(_enc_fake)
int crypto_kem_enc_fake(unsigned char *ct,
                  unsigned char *ss,
                  const unsigned char *pk,
                  uint64_t* victim_pointer,
                  int index,
                  int16_t guess,
                  int poly_idx,
                  uint64_t rand_mask);

#define crypto_kem_dec KYBER_NAMESPACE(_dec)
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#endif
