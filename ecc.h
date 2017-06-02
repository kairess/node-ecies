#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @file
 * @brief ECIES Library
 *
 * @defgroup ecc ECIES Library
 * @brief The ECIES implementation based on Phrack Stuff's code from #63.
 * @{
 *
 * It includes key generation, validation, encryption and decryption calls.
 *
 * Differences from original code:
 *
 * - Data types for public/private keys and stream.
 * - Hex bit strings replaced by binary strings.
 * - Static initialization using compile-time constants.
 * - Encryption/decryption in-place instead of data copy.
 * - Some optimizations for embedded platforms.
 *
 * For example of usage see `demo.c` and `tool.c`.
 *
 */

#ifndef _ECC_H_
#define _ECC_H_ "ecc.h"

/* the degree of the field polynomial */
#define ECIES_DEGREE 163

/* the coefficients for B163 */
#define ECIES_POLY 0x000000c9, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x8
#define ECIES_COEFF_B 0x4a3205fd, 0x512f7874, 0x1481eb10, 0xb8c953ca, 0x0a601907, 0x2
#define ECIES_BASE_X 0xe8343e36, 0xd4994637, 0xa0991168, 0x86a2d57e, 0xf0eba162, 0x3
#define ECIES_BASE_Y 0x797324f1, 0xb11c5c0c, 0xa2cdd545, 0x71a0094f, 0xd51fbc6c, 0x0
#define ECIES_BASE_ORDER 0xa4234c33, 0x77e70c12, 0x000292fe, 0x00000000, 0x00000000, 0x4

/* don't touch this */
#define ECIES_MARGIN 3
#define ECIES_NUMWORDS ((ECIES_DEGREE + ECIES_MARGIN + 31) / 32)

#define ECIES_OVERHEAD (8 * ECIES_NUMWORDS + 8)

#define ECIES_KEY_SIZE ((ECIES_DEGREE + 7) / 8)

typedef unsigned int ECIES_size_t;
typedef unsigned char ECIES_byte_t;
typedef ECIES_byte_t ECIES_key_t[ECIES_KEY_SIZE];

/**
 * @brief Public key type.
 */
typedef struct {
  ECIES_key_t x, y;
} ECIES_pubkey_t;

/**
 * @brief Private key type.
 */
typedef struct {
  ECIES_key_t k;
} ECIES_privkey_t;

/**
 * @brief Generate public/private key pair.
 *
 * It uses `random()` function to get random numbers, so you may use `srandom()` to set initial random seed.
 *
 * @param[out] priv The result private key.
 * @param[out] pub The result public key.
 */
void ECIES_generate_keys(ECIES_privkey_t *priv, ECIES_pubkey_t *pub);

/**
 * @brief Validate public key.
 *
 * @param[in] pubkey The target public key.
 */
int ECIES_validate_pubkey(const ECIES_pubkey_t *pubkey);

/**
 * @brief Encrypt data.
 *
 * @param[out] msg The destination buffer for the encrypted data.
 * @param[in] raw The source data buffer.
 * @param[in] len The source data length in chars.
 * @param[in] pubkey The public key which will be used for encryption.
 *
 * Encrypted data will be `len + ECIES_OVERHEAD` bytes long.
 */
void ECIES_encrypt(ECIES_byte_t *msg, const char *raw, ECIES_size_t len, const ECIES_pubkey_t *pubkey);

/**
 * @brief Decrypt data.
 *
 * @param[out] raw The destination buffer for decrypted data.
 * @param[in] len The destination data length.
 * @param[in] msg The source encrypted data buffer.
 * @param[in] privkey The private key wich will be used for decryption.
 * @return 1 when success, < 0 when error reached.
 *
 * Encrypted data must be `len + ECIES_OVERHEAD` bytes long.
 */
int ECIES_decrypt(char *raw, ECIES_size_t len, const ECIES_byte_t *msg, const ECIES_privkey_t *privkey);

/**
 * @brief The starting overhead of encrypted data in bytes.
 */
#define ECIES_START_OVERHEAD (8 * ECIES_NUMWORDS)

/**
 * @brief The per-chunk overhead of encrypted data in bytes.
 */
#define ECIES_CHUNK_OVERHEAD (8)

/**
 * @brief Encryption/decryption stream data.
 */
typedef struct {
  ECIES_byte_t k1[16], k2[16];
} ECIES_stream_t;

/**
 * @brief Start the encryption.
 *
 * @param[out] stm The stream data.
 * @param[out] msg The destination encrypted data buffer.
 * @param[in] pubkey The public key which will be used for encryption.
 *
 * Starting sequence (@p msg) will be `ECIES_START_OVERHEAD` bytes long.
 */
void ECIES_encrypt_start(ECIES_stream_t *stm, ECIES_byte_t *msg, const ECIES_pubkey_t *pubkey);

/**
 * @brief Encrypt data chunk.
 *
 * @param[in] stm The stream data.
 * @param[in,out] msg The source raw data and destination encrypted data buffer.
 * @param[in] len The length of source raw data in bytes.
 *
 * Encryption is performed in-place on @p msg parameter.
 * Encrypted data will be `len + ECIES_CHUNK_OVERHEAD` bytes long.
 */
void ECIES_encrypt_chunk(const ECIES_stream_t *stm, ECIES_byte_t *msg, ECIES_size_t len);

/**
 * @brief Start the decryption.
 *
 * @param[out] stm The stream data.
 * @param[in] msg The source encrypted data buffer.
 * @param[in] privkey The private key wich will be used for decryption.
 * @return 1 when success, < 0 when error reached.
 *
 * Starting sequence (@p msg) must be `ECIES_START_OVERHEAD` bytes long.
 */
int ECIES_decrypt_start(ECIES_stream_t *stm, const ECIES_byte_t *msg, const ECIES_privkey_t *privkey);

/**
 * @brief Decrypt data chunk.
 *
 * @param[in] stm The stream data.
 * @param[in,out] msg The source encrypted data and destination decrypted raw data buffer.
 * @param[in] len The length of destination decrypted raw data in bytes.
 * @return 1 when success, < 0 when error reached.
 *
 * Decryption is performed in-place on @p msg parameter.
 * Encrypted data must be `len + ECIES_CHUNK_OVERHEAD` bytes long.
 */
int ECIES_decrypt_chunk(const ECIES_stream_t *stm, ECIES_byte_t *msg, ECIES_size_t len);

#endif/*_ECC_H_*/
/**
 * @}
 */

#ifdef __cplusplus
}
#endif