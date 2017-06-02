/* 
  This program implements the ECIES public key encryption scheme based on the
  NIST B163 elliptic curve and the XTEA block cipher. The code was written
  as an accompaniment for an article published in phrack #63 and is released to
  the public domain.
*/

#include "ecc.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static inline uint32_t __swap32(uint32_t val){
  return
    ((((uint32_t)(val)) & 0x000000ff) << 24) |
    ((((uint32_t)(val)) & 0x0000ff00) <<  8) |
    ((((uint32_t)(val)) & 0x00ff0000) >>  8) |
    ((((uint32_t)(val)) & 0xff000000) >> 24);
}

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  ifndef be32toh
#    define be32toh(val) (val)
#  endif
#  ifndef htobe32
#    define htobe32(val) (val)
#  endif
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  ifndef be32toh
#    define be32toh(val) __swap32(val)
#  endif
#  ifndef htobe32
#    define htobe32(val) __swap32(val)
#  endif
#endif

#define MACRO(A) do { A; } while(0)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define CHARS2INT(ptr) ( be32toh(*(uint32_t*)(ptr)) )
#define INT2CHARS(ptr, val) MACRO( (*(uint32_t*)(ptr)) = htobe32(val) )

/* the following type will represent bit vectors of length (ECIES_DEGREE+MARGIN) */
typedef uint32_t bitstr_t[ECIES_NUMWORDS];

/* some basic bit-manipulation routines that act on these vectors follow */
#define bitstr_getbit(A, idx) ((A[(idx) / 32] >> ((idx) % 32)) & 1)
#define bitstr_setbit(A, idx) MACRO( A[(idx) / 32] |= 1 << ((idx) % 32) )
#define bitstr_clrbit(A, idx) MACRO( A[(idx) / 32] &= ~(1 << ((idx) % 32)) )

#define bitstr_clear(A) MACRO( memset(A, 0, sizeof(bitstr_t)) )
#define bitstr_copy(A, B) MACRO( memcpy(A, B, sizeof(bitstr_t)) )
#define bitstr_swap(A, B) MACRO( bitstr_t h; \
  bitstr_copy(h, A); bitstr_copy(A, B); bitstr_copy(B, h) )
#define bitstr_is_equal(A, B) (! memcmp(A, B, sizeof(bitstr_t)))

static int bitstr_is_clear(const bitstr_t x)
{
  int i;
  for(i = 0; i < ECIES_NUMWORDS && ! *x++; i++);
  return i == ECIES_NUMWORDS;
}

/* return the number of the highest one-bit + 1 */
static int bitstr_sizeinbits(const bitstr_t x)
{
  int i;
  uint32_t mask;
  for(x += ECIES_NUMWORDS, i = 32 * ECIES_NUMWORDS; i > 0 && ! *--x; i -= 32);
  if (i)
    for(mask = 1 << 31; ! (*x & mask); mask >>= 1, i--);
  return i;
}

/* left-shift by 'count' digits */
static void bitstr_lshift(bitstr_t A, const bitstr_t B, int count)
{
  int i, offs = 4 * (count / 32);
  memmove((char*)A + offs, B, sizeof(bitstr_t) - offs);
  memset(A, 0, offs);
  if (count %= 32) {
    for(i = ECIES_NUMWORDS - 1; i > 0; i--)
      A[i] = (A[i] << count) | (A[i - 1] >> (32 - count));
    A[0] <<= count;
  }
}

static void bitstr_load(bitstr_t bstr, const ECIES_byte_t *data, ECIES_size_t len){
  uint32_t *bptr = bstr + ((len + 3) / 4) - 1;
  
  len %= 4;
  
  if(len > 0){
    *bptr = 0;
    if(len > 1){
      if(len > 2){
        *bptr |= (uint32_t)(*data++) << 16;
      }
      *bptr |= (uint32_t)(*data++) <<  8;
    }
    *bptr |= (uint32_t)(*data++);
    bptr--;
  }
  
  for(; bptr >= bstr; bptr--){
    *bptr  = (uint32_t)(*data++) << 24;
    *bptr |= (uint32_t)(*data++) << 16;
    *bptr |= (uint32_t)(*data++) <<  8;
    *bptr |= (uint32_t)(*data++);
  }
}

static void bitstr_dump(ECIES_byte_t *data, ECIES_size_t len, const bitstr_t bstr){
  const uint32_t *bptr = bstr + ((len + 3) / 4) - 1;
  
  len %= 4;

  if(len > 0){
    if(len > 1){
      if(len > 2){
        *data++ = *bptr >> 16;
      }
      *data++ = *bptr >>  8;
    }
    *data++ = *bptr;
    bptr--;
  }
  
  for(; bptr >= bstr; bptr--){
    *data++ = *bptr >> 24;
    *data++ = *bptr >> 16;
    *data++ = *bptr >>  8;
    *data++ = *bptr;
  }
}

/* (raw) import from a byte array */
static void bitstr_import(bitstr_t x, const ECIES_byte_t *s)
{
  int i;
  for(x += ECIES_NUMWORDS, i = 0; i < ECIES_NUMWORDS; i++, s += 4)
    *--x = CHARS2INT(s);
}

/* (raw) export to a byte array */
static void bitstr_export(ECIES_byte_t *s, const bitstr_t x)
{
  int i;
  for(x += ECIES_NUMWORDS, i = 0; i < ECIES_NUMWORDS; i++, s += 4)
    INT2CHARS(s, *--x);
}

/* this type will represent field elements */
typedef bitstr_t elem_t;

/* the reduction polynomial */
static const elem_t poly = { ECIES_POLY };

#define field_set1(A) MACRO( A[0] = 1; memset(A + 1, 0, sizeof(elem_t) - 4) )

int field_is1(const elem_t x)
{
  int i;
  if (*x++ != 1) return 0;
  for(i = 1; i < ECIES_NUMWORDS && ! *x++; i++);
  return i == ECIES_NUMWORDS;
}

/* field addition */
static void field_add(elem_t z, const elem_t x, const elem_t y)
{
  int i;
  for(i = 0; i < ECIES_NUMWORDS; i++)
    *z++ = *x++ ^ *y++;
}

#define field_add1(A) MACRO( A[0] ^= 1 )

/* field multiplication */
static void field_mult(elem_t z, const elem_t x, const elem_t y)
{
  elem_t b;
  int i, j;
  /* assert(z != y); */
  bitstr_copy(b, x);
  if (bitstr_getbit(y, 0))
    bitstr_copy(z, x);
  else
    bitstr_clear(z);
  for(i = 1; i < ECIES_DEGREE; i++) {
    for(j = ECIES_NUMWORDS - 1; j > 0; j--)
      b[j] = (b[j] << 1) | (b[j - 1] >> 31);
    b[0] <<= 1;
    if (bitstr_getbit(b, ECIES_DEGREE))
      field_add(b, b, poly);
    if (bitstr_getbit(y, i))
      field_add(z, z, b);
  }
}

/* field inversion */
static void field_invert(elem_t z, const elem_t x)
{
  elem_t u, v, g, h;
  int i;
  bitstr_copy(u, x);
  bitstr_copy(v, poly);
  bitstr_clear(g);
  field_set1(z);
  while (! field_is1(u)) {
    i = bitstr_sizeinbits(u) - bitstr_sizeinbits(v);
    if (i < 0) {
      bitstr_swap(u, v); bitstr_swap(g, z); i = -i;
    }
    bitstr_lshift(h, v, i);
    field_add(u, u, h);
    bitstr_lshift(h, g, i);
    field_add(z, z, h);
  }
}

/* The following routines do the ECC arithmetic. Elliptic curve points
   are represented by pairs (x,y) of elem_t. It is assumed that curve
   coefficient 'a' is equal to 1 (this is the case for all NIST binary
   curves). Coefficient 'b' is given in 'coeff_b'.  '(base_x, base_y)'
   is a point that generates a large prime order group.             */

static const elem_t coeff_b = { ECIES_COEFF_B }, base_x = { ECIES_BASE_X }, base_y = { ECIES_BASE_Y };

#define point_is_zero(x, y) (bitstr_is_clear(x) && bitstr_is_clear(y))
#define point_set_zero(x, y) MACRO( bitstr_clear(x); bitstr_clear(y) )
#define point_copy(x1, y1, x2, y2) MACRO( bitstr_copy(x1, x2); \
                                          bitstr_copy(y1, y2) )

/* check if y^2 + x*y = x^3 + *x^2 + coeff_b holds */
static int is_point_on_curve(const elem_t x, const elem_t y)
{
  elem_t a, b;
  if (point_is_zero(x, y))
    return 1;
  field_mult(a, x, x);
  field_mult(b, a, x);
  field_add(a, a, b);
  field_add(a, a, coeff_b);
  field_mult(b, y, y);
  field_add(a, a, b);
  field_mult(b, x, y);
  return bitstr_is_equal(a, b);
}

/* double the point (x,y) */
static void point_double(elem_t x, elem_t y)
{
  if (! bitstr_is_clear(x)) {
    elem_t a;
    field_invert(a, x);
    field_mult(a, a, y);
    field_add(a, a, x);
    field_mult(y, x, x);
    field_mult(x, a, a);
    field_add1(a);        
    field_add(x, x, a);
    field_mult(a, a, x);
    field_add(y, y, a);
  }
  else
    bitstr_clear(y);
}

/* add two points together (x1, y1) := (x1, y1) + (x2, y2) */
static void point_add(elem_t x1, elem_t y1, const elem_t x2, const elem_t y2)
{
  if (! point_is_zero(x2, y2)) {
    if (point_is_zero(x1, y1))
      point_copy(x1, y1, x2, y2);
    else {
      if (bitstr_is_equal(x1, x2)) {
	if (bitstr_is_equal(y1, y2))
	  point_double(x1, y1);
	else 
	  point_set_zero(x1, y1);
      }
      else {
	elem_t a, b, c, d;
	field_add(a, y1, y2);
	field_add(b, x1, x2);
	field_invert(c, b);
	field_mult(c, c, a);
	field_mult(d, c, c);
	field_add(d, d, c);
	field_add(d, d, b);
	field_add1(d);
	field_add(x1, x1, d);
	field_mult(a, x1, c);
	field_add(a, a, d);
	field_add(y1, y1, a);
	bitstr_copy(x1, d);
      }
    }
  }
}

typedef bitstr_t exp_t;

static const exp_t base_order = { ECIES_BASE_ORDER };

/* point multiplication via double-and-add algorithm */
static void point_mult(elem_t x, elem_t y, const exp_t exp)
{
  elem_t X, Y;
  int i;
  point_set_zero(X, Y);
  for(i = bitstr_sizeinbits(exp) - 1; i >= 0; i--) {
    point_double(X, Y);
    if (bitstr_getbit(exp, i))
      point_add(X, Y, x, y);
  }
  point_copy(x, y, X, Y);
}

#if RAND_MAX >= ((1 << 32) - 1) /* 4 random bytes */
#define RAND_BYTES 4
#elif RAND_MAX >= ((1 << 24) - 1) /* 3 random bytes */
#define RAND_BYTES 3
#elif RAND_MAX >= ((1 << 16) - 1) /* 2 random bytes */
#define RAND_BYTES 2
#elif RAND_MAX >= ((1 << 8) - 1) /* 1 random byte */
#define RAND_BYTES 1
#else
#error "RAND_MAX too small!"
#endif

/* draw a random value 'exp' with 1 <= exp < n */
static void get_random_exponent(exp_t exp)
{
  ECIES_byte_t buf[4 * ECIES_NUMWORDS];
  ECIES_byte_t *ptr = buf + 4 * ECIES_NUMWORDS - 1;
  int r;
  long int val;
  
  srand(time(NULL));
  do {
    for(; ptr >= buf + RAND_BYTES; ){
      val = rand();
      *ptr-- = val;
      for(r = 1; r < RAND_BYTES; r++){
        val >>= 8;
        *ptr-- = val;
      }
    }
    if(ptr >= buf){
      val = rand();
      for(; ptr >= buf; ){
        *ptr-- = val;
        val >>= 8;
      }
    }
    
    bitstr_import(exp, buf);
    for(r = bitstr_sizeinbits(base_order) - 1; r < ECIES_NUMWORDS * 32; r++)
      bitstr_clrbit(exp, r);
  } while(bitstr_is_clear(exp));
}

static void XTEA_init_key(uint32_t *k, const ECIES_byte_t *key)
{
  k[0] = CHARS2INT(key + 0); k[1] = CHARS2INT(key + 4);
  k[2] = CHARS2INT(key + 8); k[3] = CHARS2INT(key + 12);
}

                                                     /* the XTEA block cipher */
static void XTEA_encipher_block(ECIES_byte_t *data, const uint32_t *k)
{
  uint32_t sum = 0, delta = 0x9e3779b9, y, z;
  int i;
  y = CHARS2INT(data); z = CHARS2INT(data + 4);
  for(i = 0; i < 32; i++) {
    y += ((z << 4 ^ z >> 5) + z) ^ (sum + k[sum & 3]);
    sum += delta;
    z += ((y << 4 ^ y >> 5) + y) ^ (sum + k[sum >> 11 & 3]);
  }
  INT2CHARS(data, y); INT2CHARS(data + 4, z);
}
/* encrypt in CTR mode */
static void XTEA_ctr_crypt(ECIES_byte_t *data, ECIES_size_t size, const ECIES_byte_t *key)
{
  uint32_t k[4], ctr = 0;
  ECIES_size_t len, i;
  ECIES_byte_t buf[8];
  XTEA_init_key(k, key);
  while(size) {
    INT2CHARS(buf, 0); INT2CHARS(buf + 4, ctr++);
    XTEA_encipher_block(buf, k);
    len = MIN(8, size);
    for(i = 0; i < len; i++)
      *data++ ^= buf[i];
    size -= len;
  }
}

/* calculate the CBC MAC */
static void XTEA_cbcmac(ECIES_byte_t *mac, const ECIES_byte_t *data, ECIES_size_t size, const ECIES_byte_t *key)
{
  uint32_t k[4];
  ECIES_size_t len, i;
  XTEA_init_key(k, key);
  INT2CHARS(mac, 0);
  INT2CHARS(mac + 4, size);
  XTEA_encipher_block(mac, k);
  while(size) {
    len = MIN(8, size);
    for(i = 0; i < len; i++)
      mac[i] ^= *data++;
    XTEA_encipher_block(mac, k);
    size -= len;
  }
}

/* modified(!) Davies-Meyer construction.*/
static void XTEA_davies_meyer(ECIES_byte_t *out, const ECIES_byte_t *in, int ilen)
{
  uint32_t k[4];
  ECIES_byte_t buf[8];
  ECIES_size_t i;
  memset(out, 0, 8);
  while(ilen--) {
    XTEA_init_key(k, in);
    memcpy(buf, out, 8);
    XTEA_encipher_block(buf, k);
    for(i = 0; i < 8; i++)
      out[i] ^= buf[i];
    in += 16;
  }
}

/* generate a public/private key pair */
void ECIES_generate_keys(ECIES_privkey_t *priv,
                         ECIES_pubkey_t *pub)
{
  elem_t x, y;
  exp_t k;
  
  get_random_exponent(k);
  point_copy(x, y, base_x, base_y);
  point_mult(x, y, k);
  
  bitstr_dump(pub->x, ECIES_KEY_SIZE, x);
  bitstr_dump(pub->y, ECIES_KEY_SIZE, y);
  bitstr_dump(priv->k, ECIES_KEY_SIZE, k);
}

/* check that a given elem_t-pair is a valid point on the curve != 'o' */
static int ECIES_intern_validate_pubkey(const elem_t Px, const elem_t Py)
{
  return (bitstr_sizeinbits(Px) > ECIES_DEGREE) || (bitstr_sizeinbits(Py) > ECIES_DEGREE) ||
    point_is_zero(Px, Py) || ! is_point_on_curve(Px, Py) ? -1 : 1;
}

/* same thing, but check also that (Px,Py) generates a group of order n */
int ECIES_validate_pubkey(const ECIES_pubkey_t *pubkey)
{
  elem_t x, y;
  
  bitstr_load(x, pubkey->x, ECIES_KEY_SIZE);
  bitstr_load(y, pubkey->y, ECIES_KEY_SIZE);
  
  if (ECIES_intern_validate_pubkey(x, y) < 0)
    return -1;
  
  point_mult(x, y, base_order);
  
  return point_is_zero(x, y) ? 1 : -1;
}

/* a non-standard KDF */
static void ECIES_kdf(ECIES_byte_t *k1, ECIES_byte_t *k2, const elem_t Zx,
                      const elem_t Rx, const elem_t Ry)
{
  ECIES_size_t bufsize = (3 * (4 * ECIES_NUMWORDS) + 1 + 15) & ~15;
  ECIES_byte_t buf[bufsize];
  memset(buf, 0, bufsize);
  bitstr_export(buf, Zx);
  bitstr_export(buf + 4 * ECIES_NUMWORDS, Rx);
  bitstr_export(buf + 8 * ECIES_NUMWORDS, Ry);
  buf[12 * ECIES_NUMWORDS] = 0; XTEA_davies_meyer(k1, buf, bufsize / 16);
  buf[12 * ECIES_NUMWORDS] = 1; XTEA_davies_meyer(k1 + 8, buf, bufsize / 16);
  buf[12 * ECIES_NUMWORDS] = 2; XTEA_davies_meyer(k2, buf, bufsize / 16);
  buf[12 * ECIES_NUMWORDS] = 3; XTEA_davies_meyer(k2 + 8, buf, bufsize / 16);
}

void ECIES_encrypt(ECIES_byte_t *msg, const char *raw, ECIES_size_t len, const ECIES_pubkey_t *pubkey){
  ECIES_stream_t stm;
  
  ECIES_encrypt_start(&stm, msg, pubkey);
  
  memcpy(msg + ECIES_START_OVERHEAD, raw, len);
  
  ECIES_encrypt_chunk(&stm, msg + ECIES_START_OVERHEAD, len);
}

int ECIES_decrypt(char *raw, ECIES_size_t len, const ECIES_byte_t *msg, const ECIES_privkey_t *privkey){
  int res;
  ECIES_stream_t stm;
  ECIES_byte_t mac[ECIES_CHUNK_OVERHEAD];
  
  if((res = ECIES_decrypt_start(&stm, msg, privkey)) < 0){
    return res;
  }
  
  XTEA_cbcmac(mac, msg + ECIES_START_OVERHEAD, len, stm.k2);
  
  if(memcmp(mac, msg + ECIES_START_OVERHEAD + len, ECIES_CHUNK_OVERHEAD)){
    return -2;
  }
  
  memcpy(raw, msg + ECIES_START_OVERHEAD, len);
  
  XTEA_ctr_crypt((ECIES_byte_t*)raw, len, stm.k1);
  
  return 1;
}

void ECIES_encrypt_start(ECIES_stream_t *stm, ECIES_byte_t *msg, const ECIES_pubkey_t *pubkey)
{
  elem_t Rx, Ry, Zx, Zy;
  exp_t k;
  
  do {
    get_random_exponent(k);
    bitstr_load(Zx, pubkey->x, ECIES_KEY_SIZE);
    bitstr_load(Zy, pubkey->y, ECIES_KEY_SIZE);
    point_mult(Zx, Zy, k);
    point_double(Zx, Zy); /* cofactor h = 2 on B163 */
  } while(point_is_zero(Zx, Zy));
  point_copy(Rx, Ry, base_x, base_y);
  point_mult(Rx, Ry, k);
  ECIES_kdf(stm->k1, stm->k2, Zx, Rx, Ry);
  
  bitstr_export(msg, Rx);
  bitstr_export(msg + 4 * ECIES_NUMWORDS, Ry);
}

void ECIES_encrypt_chunk(const ECIES_stream_t *stm, ECIES_byte_t *msg, ECIES_size_t len)
{
  XTEA_ctr_crypt(msg, len, stm->k1);
  XTEA_cbcmac(msg + len, msg, len, stm->k2);
}

/* ECIES decryption */
int ECIES_decrypt_start(ECIES_stream_t *stm, const ECIES_byte_t *msg, const ECIES_privkey_t *privkey)
{
  elem_t Rx, Ry, Zx, Zy;
  exp_t d;
  
  bitstr_import(Rx, msg);
  bitstr_import(Ry, msg + 4 * ECIES_NUMWORDS);
  
  if (ECIES_intern_validate_pubkey(Rx, Ry) < 0)
    return -1;
  
  bitstr_load(d, privkey->k, ECIES_KEY_SIZE);
  point_copy(Zx, Zy, Rx, Ry);
  point_mult(Zx, Zy, d);
  point_double(Zx, Zy); /* cofactor h = 2 on B163 */
  
  if (point_is_zero(Zx, Zy))
    return -1;
  
  ECIES_kdf(stm->k1, stm->k2, Zx, Rx, Ry);
  
  return 1;
}

int ECIES_decrypt_chunk(const ECIES_stream_t *stm, ECIES_byte_t *msg, ECIES_size_t len)
{
  ECIES_byte_t mac[ECIES_CHUNK_OVERHEAD];
  
  XTEA_cbcmac(mac, msg, len, stm->k2);
  
  if (memcmp(mac, msg + len, ECIES_CHUNK_OVERHEAD))
    return -2;
  
  XTEA_ctr_crypt(msg, len, stm->k1);
  
  return 1;
}
