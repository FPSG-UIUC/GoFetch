#ifndef API_H
#define API_H

#include "params.h"
#include <stdint.h>

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber512-90s"
#else
#define CRYPTO_ALGNAME "Kyber512"
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber768-90s"
#else
#define CRYPTO_ALGNAME "Kyber768"
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber1024-90s"
#else
#define CRYPTO_ALGNAME "Kyber1024"
#endif
#endif

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

#define indcpa_get_sk_coef KYBER_NAMESPACE(_indcpa_get_sk_coef)
void indcpa_get_sk_coef(const unsigned char *sk,
                            int16_t *coeffs_vec);

#define indcpa_get_pk_coef KYBER_NAMESPACE(_indcpa_get_pk_coef)
void indcpa_get_pk_coef(const unsigned char *pk,
                            int16_t *coeffs_vec_a,
                            int16_t *coeffs_vec_t);

#define crypto_kem_dec KYBER_NAMESPACE(_dec)
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#define crypto_kem_dec_attack KYBER_NAMESPACE(_dec_attack)
int crypto_kem_dec_attack(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk,
                   uint8_t buf[2*KYBER_SYMBYTES]);
#endif
