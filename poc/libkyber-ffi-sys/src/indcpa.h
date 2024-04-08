#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix KYBER_NAMESPACE(_gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#define indcpa_keypair KYBER_NAMESPACE(_indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#define indcpa_enc KYBER_NAMESPACE(_indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

#define indcpa_enc_attack KYBER_NAMESPACE(_indcpa_enc_attack)
void indcpa_enc_attack(uint8_t c[KYBER_INDCPA_BYTES],
                uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES],
                int index,
                int flip);

#define indcpa_enc_fake KYBER_NAMESPACE(_indcpa_enc_fake)
void indcpa_enc_fake(uint8_t c[KYBER_INDCPA_BYTES],
                uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES],
                int index,
                int16_t guess,
                int poly_idx);

#define indcpa_get_sk_coef KYBER_NAMESPACE(_indcpa_get_sk_coef)
void indcpa_get_sk_coef(const unsigned char *sk,
                            int16_t *coeffs_vec);

#define indcpa_get_pk_coef KYBER_NAMESPACE(_indcpa_get_pk_coef)
void indcpa_get_pk_coef(const unsigned char *pk,
                            int16_t *coeffs_vec_a,
                            int16_t *coeffs_vec_t);
                
#define indcpa_dec KYBER_NAMESPACE(_indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#endif
