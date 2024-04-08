#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "rng.h"
#include "ntt.h"
#include "symmetric.h"
#include "reduce.h"

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r:          pointer to the output serialized public key
*              polyvec *pk:         pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  size_t i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk:             pointer to output public-key
*                                         polynomial vector
*              - uint8_t *seed:           pointer to output seed to generate
*                                         matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  size_t i;
  polyvec_frombytes(pk, packedpk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r:  pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key;
*              inverse of pack_sk
*
* Arguments:   - polyvec *sk:             pointer to output vector of
*                                         polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk,
                      const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk:   pointer to the input vector of polynomials b
*              poly *v:    pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES],
                            polyvec *b,
                            poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void pack_ct_attack(uint8_t r[KYBER_INDCPA_BYTES],
                            polyvec *b,
                            poly *v,
                            int index,
                            int16_t guess)
{
  polyvec_compress(r, b);
  // assign guess value after compression
  r = r+KYBER_POLYVECCOMPRESSEDBYTES;
  unsigned int i,j;
  uint8_t t[8];

  poly_csubq(v);

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      if((int)(8*i+j) == index)
        t[j] = guess;
      else
        t[j] = ((((uint16_t)v->coeffs[8*i+j] << 4) + KYBER_Q/2)/KYBER_Q) & 15;
    }

    r[0] = t[0] | (t[1] << 4);
    r[1] = t[2] | (t[3] << 4);
    r[2] = t[4] | (t[5] << 4);
    r[3] = t[6] | (t[7] << 4);
    r += 4;
  }
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b:       pointer to the output vector of polynomials b
*              - poly *v:          pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b,
                              poly *v,
                              const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r:          pointer to output buffer
*              - unsigned int len:    requested number of 16-bit integers
*                                     (uniform mod q)
*              - const uint8_t *buf:  pointer to input buffer
*                                     (assumed to be uniform random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a:          pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed:      boolean deciding whether A or A^T
*                                     is generated
**************************************************/
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q \
                             + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++)
          buf[k] = buf[buflen - off + k];
        xof_squeezeblocks(buf + off, 1, &state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;

  randombytes(buf, KYBER_SYMBYTES);
  hash_g(buf, buf, KYBER_SYMBYTES);

  gen_a(a, publicseed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  polyvec_ntt(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_pointwise_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c:           pointer to output ciphertext
*                                      (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m:     pointer to input message
*                                      (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk:    pointer to input public key
*                                      (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins
*                                      used as seed (of length KYBER_SYMBYTES)
*                                      to deterministically generate all
*                                      randomness
**************************************************/
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], bp;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_pointwise_acc_montgomery(&bp.vec[i], &at[i], &sp);

  polyvec_pointwise_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&bp);
  poly_invntt_tomont(&v);

  polyvec_add(&bp, &bp, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&bp);
  poly_reduce(&v);

  pack_ciphertext(c, &bp, &v);
}



void indcpa_enc_attack(uint8_t c[KYBER_INDCPA_BYTES],
                uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES],
                int index,
                int flip)
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], bp;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  // clean ptr in m
  for (int i=0; i<KYBER_INDCPA_MSGBYTES; i++) {
    m[i] = 0;
  }
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);

  // set r to be 0
  for(int i=0; i<KYBER_K; i++){
    for(int j=0; j<KYBER_N; j++){
      sp.vec[i].coeffs[j] = 0;
    }
  }
  // set e1 to (0,1)
  for(int i=0; i<KYBER_K; i++){
    for(int j=0; j<KYBER_N; j++){
      ep.vec[i].coeffs[j] = 0;
    }
  }
  ep.vec[KYBER_K-1].coeffs[0] = 1;

  // set e2 to target a index of secret
  for(int j=0; j<KYBER_N; j++){
    epp.coeffs[j] = 0;
  }

  int16_t add_on = 0;
  if(flip==1){
    add_on = KYBER_Q/2;
  }else{
    add_on = KYBER_Q/16;
  }
  epp.coeffs[index] = add_on;

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_pointwise_acc_montgomery(&bp.vec[i], &at[i], &sp);

  polyvec_pointwise_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&bp);
  poly_invntt_tomont(&v);

  polyvec_add(&bp, &bp, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&bp);
  poly_reduce(&v);

  pack_ciphertext(c, &bp, &v);
}

void indcpa_enc_fake(uint8_t c[KYBER_INDCPA_BYTES],
                uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES],
                int index,
                int16_t guess,
                int poly_idx)
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], bp;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  // clean ptr in m
  for (int i=0; i<KYBER_INDCPA_MSGBYTES; i++) {
    m[i] = 0;
  }
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);

  // set r to be 0
  for(int i=0; i<KYBER_K; i++){
    for(int j=0; j<KYBER_N; j++){
      sp.vec[i].coeffs[j] = 0;
    }
  }
  // set e1 to (0,1)
  for(int i=0; i<KYBER_K; i++){
    for(int j=0; j<KYBER_N; j++){
      ep.vec[i].coeffs[j] = 0;
    }
  }
  // select one of the secret polys
  ep.vec[poly_idx].coeffs[0] = (int)(KYBER_Q / 16.0 + 0.5);

  // set e2 to target a index of secret
  for(int j=0; j<KYBER_N; j++){
    epp.coeffs[j] = 0;
  }

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_pointwise_acc_montgomery(&bp.vec[i], &at[i], &sp);

  polyvec_pointwise_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&bp);
  poly_invntt_tomont(&v);

  polyvec_add(&bp, &bp, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&bp);
  poly_reduce(&v);

  pack_ct_attack(c, &bp, &v, index, guess);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m:        pointer to output decrypted message
*                                   (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c:  pointer to input ciphertext
*                                   (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec bp, skpv;
  poly v, mp;

  unpack_ciphertext(&bp, &v, c);
  unpack_sk(&skpv, sk);

  polyvec_ntt(&bp);
  polyvec_pointwise_acc_montgomery(&mp, &skpv, &bp);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}

/*************************************************
* Name:        indcpa_get_sk_coef
*
* Description: Get the coefficient of sk
*
* Arguments:   - int16_t *coeffs_vec: an array to record secret key coefficients
*                (an already allocated array of 2*KYBER_N elements)
*              - const unsigned char *sk: pointer to input private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns void
**************************************************/
void indcpa_get_sk_coef(const unsigned char *sk,
                            int16_t *coeffs_vec)
{
  polyvec sk_ntt, skpv;

  unpack_sk(&skpv, sk);
  for (int i = 0; i < KYBER_K; i++)
  {
    for (int j = 0; j < KYBER_N; j++)
    {
      sk_ntt.vec[i].coeffs[j] = skpv.vec[i].coeffs[j];
    }
  }
  
  polyvec_invntt_tomont(&sk_ntt);

  for (int i = 0; i < KYBER_K; i++)
  {
    for (int j = 0; j < KYBER_N; j++)
    {
      coeffs_vec[i*KYBER_N + j] = montgomery_reduce((int32_t)sk_ntt.vec[i].coeffs[j]);
    }
  }
}

/*************************************************
* Name:        indcpa_get_pk_coef
*
* Description: Get the coefficient of pk
*
* Arguments:   - int16_t *coeffs_vec_a: an array to record A coefficients
*                (an already allocated array of 4*KYBER_N elements)
*              - int16_t *coeffs_vec_t: an array to record t coefficients
*                (an already allocated array of 2*KYBER_N elements)
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns void
**************************************************/
void indcpa_get_pk_coef(const unsigned char *pk,
                            int16_t *coeffs_vec_a,
                            int16_t *coeffs_vec_t)
{
  uint8_t seed[KYBER_SYMBYTES];
  polyvec t, at[KYBER_K], t_ntt, at_ntt[KYBER_K];

  unpack_pk(&t, seed, pk);
  gen_at(at, seed);
  // unpack at
  for (int i = 0; i < KYBER_K; i++)
  {
    for (int j = 0; j < KYBER_K; j++)
    {
      for (int k = 0; k < KYBER_N; k++)
      {
        at_ntt[i].vec[j].coeffs[k] = at[i].vec[j].coeffs[k];
      }
    }
  }
  for (int i = 0; i < KYBER_K; i++)
  {
    polyvec_invntt_tomont(&at_ntt[i]);
  }
  for (int i = 0; i < KYBER_K; i++)
  {
    for (int j = 0; j < KYBER_K; j++)
    {
      for (int k = 0; k < KYBER_N; k++)
      {
        coeffs_vec_a[i*2*KYBER_N + j*KYBER_N + k] = montgomery_reduce((int32_t)at_ntt[i].vec[j].coeffs[k]);
      }
    }
  }
  // unpack t
  for (int i = 0; i < KYBER_K; i++)
  {
    for (int j = 0; j < KYBER_N; j++)
    {
      t_ntt.vec[i].coeffs[j] = t.vec[i].coeffs[j];
    }
  }
  
  polyvec_invntt_tomont(&t_ntt);

  for (int i = 0; i < KYBER_K; i++)
  {
    for (int j = 0; j < KYBER_N; j++)
    {
      coeffs_vec_t[i*KYBER_N + j] = montgomery_reduce((int32_t)t_ntt.vec[i].coeffs[j]);
    }
  }
}
