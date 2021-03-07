/* keygen.c FAST Bitcoin address generator

    Modified by magnuspub

Forked from - Super Vanitygen - Vanity Bitcoin address generator */

// Copyright (C) 2016 Byron Stanoszek  <gandalf@winds.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "externs.h"

/* Number of secp256k1 operations per batch */
#define STEP 1

#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"

#include "sha256slow.h"

#define MY_VERSION "0.3"

/* Global command-line settings */

static bool verbose;

/* Static Functions */
static void announce_result(int found, const u8 result[52]);
static void engine(int thread);

static void my_secp256k1_ge_set_all_gej_var(secp256k1_ge *r,
					    const secp256k1_gej *a);
static void my_secp256k1_gej_add_ge_var(secp256k1_gej *r,
					const secp256k1_gej *a,
					const secp256k1_ge *b);


/**** Main Program ***********************************************************/

// Main program entry.
//
int main(int argc, char *argv[])
{
  /* Auto-detect fastest SHA-256 function to use */
  sha256_register(verbose);
  /*run Hash Engine */
  engine(1);
  return 1;
}

// Parent process loop, which tracks hash counts and announces new results to
// standard output.
//


static void announce_result(int found, const u8 result[72])
{
  align8 u8 priv_block[64], pub_block[64], cksum_block[64];
  align8 u8 priv_wif[64], wif[64], checksum[32];

  /* Display matching keys in hexadecimal */
/*  if(verbose) {
    printf("Private: ");
    for(j=0;j < 32;j++)
      printf("%02x", result[j]);
    printf(" ");

    printf("Public:  ");
    for(j=0;j < 20;j++)
      printf("%02x", result[j+32]);
    printf("\n");
  }

*/

  /* Convert Private Key to WIF */

  /* Set up sha256 block for hashing the private key; length of 34 bytes */
  sha256_prepare(priv_block, 33);
  priv_block[0]=0x80;
  memcpy(priv_block+1, result, 32);
  /* priv_block[33]=0x01;	/1* 1=Compressed Public Key *1/ */

  /* Compute checksum and copy first 4-bytes to end of private key */
  sha256_prepare(cksum_block, 32);
  sha256_hash(cksum_block, priv_block);
  sha256_hash(checksum, cksum_block);
  memcpy(priv_block+33, checksum, 4);

  b58enc(priv_wif, priv_block, 37);
  /* printf("%s\n", priv_wif); */


  /* Convert Public Key to Compressed WIF */

 /* Set up checksum block; length of 32 bytes */
  sha256_prepare(cksum_block, 32);

  /* Set up sha256 block for hashing the public key; length of 21 bytes */
  sha256_prepare(pub_block, 21);
  memcpy(pub_block+1, result+32, 20);

  /* Compute checksum and copy first 4-bytes to end of public key */
  sha256_hash(cksum_block, pub_block);
  sha256_hash(checksum, cksum_block);
  memcpy(pub_block+21, checksum, 4);

  b58enc(wif, pub_block, 25);
  printf("%s,%s\n", wif, priv_wif);

  /* Convert Public Key to Uncompressed WIF */

 /* Set up checksum block; length of 32 bytes */
  sha256_prepare(cksum_block, 32);

  /* Set up sha256 block for hashing the public key; length of 21 bytes */
  sha256_prepare(pub_block, 21);
  memcpy(pub_block+1, result+52, 20);

  /* Compute checksum and copy first 4-bytes to end of public key */
  sha256_hash(cksum_block, pub_block);
  sha256_hash(checksum, cksum_block);
  memcpy(pub_block+21, checksum, 4);

  b58enc(wif, pub_block, 25);
  printf("%s,%s\n", wif, priv_wif);

}

/**** Hash Engine ************************************************************/

static void engine(int thread)
{
  static secp256k1_gej base[STEP];
  static secp256k1_ge rslt[STEP];
  secp256k1_context *sec_ctx;
  secp256k1_scalar scalar_key, scalar_one={{1}};
  secp256k1_gej temp;
  secp256k1_ge offset;

  align8 u8 sha_block[65], rmd_block[64], result[72], *pubkey_uncomp=result+32, *pubkey_comp=result+52;
  u64 privkey[4], *key=(u64 *)result;
  int i, k, fd, len;

  SHA256_CTX ctx;

  /* Initialize the secp256k1 context */
  sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  /* Set up sha256 block for an input length of 33 bytes */
  /* sha256_prepare(sha_block, 33); */

  /* Set up rmd160 block for an input length of 32 bytes */
  rmd160_prepare(rmd_block, 32);

  rekey:

  // Generate a random private key. Specifically, any 256-bit number from 0x1
  // to 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C
  // D036 4140 is a valid private key.

  if((fd=open("/dev/urandom", O_RDONLY|O_NOCTTY)) == -1) {
    perror("/dev/urandom");
    return;
  }

  /* Use 32 bytes from /dev/urandom as starting private key */
  do {
    if((len=read(fd, privkey, 32)) != 32) {
      if(len != -1)
	errno=EAGAIN;
      perror("/dev/urandom");
      return;
    }
  } while(privkey[0]+1 < 2);  /* Ensure only valid private keys */

  close(fd);

  /* Copy private key to secp256k1 scalar format */
  secp256k1_scalar_set_b32(&scalar_key, (u8 *)privkey, NULL);

  /* Convert key to cpu endianness */
  privkey[0]=be64(privkey[0]);
  privkey[1]=be64(privkey[1]);
  privkey[2]=be64(privkey[2]);
  privkey[3]=be64(privkey[3]);

  /* Create group elements for both the random private key and the value 1 */
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &base[STEP-1], &scalar_key);
  secp256k1_ecmult_gen(&sec_ctx->ecmult_gen_ctx, &temp, &scalar_one);
  secp256k1_ge_set_gej_var(&offset, &temp);

  /* Main Loop */

  printf("\r");  // This magically makes the loop faster by a smidge

  while(1) {
    /* Add 1 in Jacobian coordinates and save the result; repeat STEP times */
    my_secp256k1_gej_add_ge_var(&base[0], &base[STEP-1], &offset);
    for(k=1;k < STEP;k++)
      my_secp256k1_gej_add_ge_var(&base[k], &base[k-1], &offset);

    /* Convert all group elements from Jacobian to affine coordinates */
    my_secp256k1_ge_set_all_gej_var(rslt, base);

    for(k=0;k < STEP;k++) {

      /* /1* Extract the 33-byte compressed public key from the group element *1/ */
      /* sha_block[0]=(secp256k1_fe_is_odd(&rslt[k].y) ? 0x03 : 0x02); */
      /* secp256k1_fe_get_b32(sha_block+1, &rslt[k].x); */
      /* sha_block[33]=0x10; */

// PREPARE UNCOMPRESSED PUBKEY
      sha_block[0] = 0x04;
      secp256k1_fe_get_b32(sha_block+1, &rslt[k].x);
      secp256k1_fe_get_b32(sha_block+33, &rslt[k].y);

// PRINT PUBKEY
    /* for(int i = 0; i < 65; i++) */
    /*     printf("%02x", sha_block[i]); */
    /* printf("\n"); */

// HASH UNCOMPRESSED PUBKEY
    sha256_init_slow(&ctx);
    sha256_update_slow(&ctx, sha_block, 65);
    sha256_final_slow(&ctx, rmd_block);

    rmd160_hash(pubkey_uncomp, rmd_block);
// PRINT SHA256
    /* for(int i = 0; i < 32; i++) */
    /*     printf("%02x", rmd_block[i]); */
    /* printf("\n"); */

// PREPARE COMPRESSED PUBKEY
      sha_block[0]=(secp256k1_fe_is_odd(&rslt[k].y) ? 0x03 : 0x02);
    /* for(int i = 0; i < 33; i++) */
    /*     printf("%02x", sha_block[i]); */
    /* printf("\n"); */

      /* Hash public key */
      /* sha256_hash(rmd_block, sha_block); */

// HASH COMPRESSED PUBKEY
    sha256_init_slow(&ctx);
    sha256_update_slow(&ctx, sha_block, 33);
    sha256_final_slow(&ctx, rmd_block);
    /* for(int i = 0; i < 32; i++) */
    /*     printf("%02x", rmd_block[i]); */
    /* printf("\n"); */
      rmd160_hash(pubkey_comp, rmd_block);

// PRINT RIPEMD160
    /* for(int i = 0; i < 20; i++) */
    /*     printf("%02x", pubkey[i]); */
    /* printf("\n"); */
      
      /* Compare hashed public key with byte patterns */

	if(1) {
	  /* key := privkey+k+1 */
	  key[0]=privkey[0];
	  key[1]=privkey[1];
	  key[2]=privkey[2];
	  if((key[3]=privkey[3]+k+1) < privkey[3])
	    if(!++key[2])
	      if(!++key[1])
		++key[0];

	  /* Convert key to big-endian byte format */
	  key[0]=be64(key[0]);
	  key[1]=be64(key[1]);
	  key[2]=be64(key[2]);
	  key[3]=be64(key[3]);

	  /* Announce (PrivKey,PubKey) result */
	  announce_result(1, result);
	  /* Pick a new random starting private key */
	  goto rekey;
	}

    }

    /* Increment privkey by STEP */
    if((privkey[3] += STEP) < STEP)  /* Check for overflow */
      if(!++privkey[2])
	if(!++privkey[1])
	  ++privkey[0];
  }
}

/**** libsecp256k1 Overrides *************************************************/

static void my_secp256k1_fe_inv_all_gej_var(secp256k1_fe *r,
					    const secp256k1_gej *a)
{
  secp256k1_fe u;
  int i;

  r[0]=a[0].z;

  for(i=1;i < STEP;i++)
    secp256k1_fe_mul(&r[i], &r[i-1], &a[i].z);

  secp256k1_fe_inv_var(&u, &r[--i]);

  for(;i > 0;i--) {
    secp256k1_fe_mul(&r[i], &r[i-1], &u);
    secp256k1_fe_mul(&u, &u, &a[i].z);
  }

  r[0]=u;
}

static void my_secp256k1_ge_set_all_gej_var(secp256k1_ge *r,
					    const secp256k1_gej *a)
{
  static secp256k1_fe azi[STEP];
  int i;

  my_secp256k1_fe_inv_all_gej_var(azi, a);

  for(i=0;i < STEP;i++)
    secp256k1_ge_set_gej_zinv(&r[i], &a[i], &azi[i]);
}

static void my_secp256k1_gej_add_ge_var(secp256k1_gej *r,
					const secp256k1_gej *a,
					const secp256k1_ge *b)
{
  /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
  secp256k1_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

  secp256k1_fe_sqr(&z12, &a->z);
  u1 = a->x; secp256k1_fe_normalize_weak(&u1);
  secp256k1_fe_mul(&u2, &b->x, &z12);
  s1 = a->y; secp256k1_fe_normalize_weak(&s1);
  secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
  secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
  secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
  secp256k1_fe_sqr(&i2, &i);
  secp256k1_fe_sqr(&h2, &h);
  secp256k1_fe_mul(&h3, &h, &h2);
  secp256k1_fe_mul(&r->z, &a->z, &h);
  secp256k1_fe_mul(&t, &u1, &h2);
  r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3);
  secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
  secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t);
  secp256k1_fe_mul(&r->y, &r->y, &i);
  secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
  secp256k1_fe_add(&r->y, &h3);
}
