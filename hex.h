#ifdef __cplusplus
extern "C"
{
#endif
/**
 * @defgroup hex HEX utils
 * @brief Some useful hex conversion functions.
 * @{
 *
 * @file
 * @brief Hex utils
 *
 * Some functions for load/dump hexademical strings to/from bit strings.
 */
#ifndef _HEX_H_
#define _HEX_H_

/**
 * @brief The size of hex string with @p len bytes.
 *
 * @param len The binary data length in bytes.
 * @return The number of chars.
 */
#define HEX_SIZE(len) (2 * (len) + 1)

/**
 * @brief The size type.
 */
typedef unsigned int hex_size_t;
/**
 * @brief The data type.
 */
typedef unsigned char hex_byte_t;

/**
 * @brief The hex load function.
 *
 * Loading hexademical string @p b to bit string @p s with length @p len.
 *
 * @param[out] s The destination binary buffer.
 * @param[in] len The destination buffer length in bytes.
 * @param[in] b The source hex string.
 * @return The number of given hex chars when success, -1 when fails.
 */
int hex_load(hex_byte_t *s, hex_size_t len, const char *b);

/**
 * @brief The hex dump function.
 *
 * Dumping bit string @p s with length @p len to hexademical string @p b.
 *
 * @param[out] b The destination hex string buffer.
 * @param[in] s The source binary buffer.
 * @param[in] len The source buffer size in bytes.
 */
void hex_dump(char *b, const hex_byte_t *s, hex_size_t len);

#endif/*_HEX_H_*/
/**
 * @}
 */
#ifdef __cplusplus
}
#endif