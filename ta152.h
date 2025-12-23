#ifndef TA152_H
#define TA152_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#define SUCCESS_ENCRYPT 101
#define SUCCESS_DECRYPT 102

#define ERR_OPEN_FAILED -101
#define ERR_NO_READ -102
#define ERR_NO_WRITE -103
#define ERR_CLOSE_FAILED -104
#define ERR_CANNOT_STAT_SIZE -105
#define ERR_NO_PATH_OUT -110
#define ERR_INVALID_KEY_SIZE -111
#define ERR_KEY_NOT_LOADED -112
#define ERR_UNDEFINED_STATUS -113
#define ERR_UNINITIALIZED_IV -114
//#define ERR_INVALID_STATUS_CONFIG -115
#define ERR_CANNOT_INIT_HEADER -116
#define ERR_HEADER_INVALID -117
#define ERR_UNSUPPORTED_VERSION -118

#define MATRIX_LEN 256
#define KEY_SIZE 16
#define IV_SIZE 16

#define MAGIC_NUMBER 0x54313532
#define VERSION 1
#define STATUS_ON 1
#define STATUS_OFF 0

//uint8_t ta152_round(uint8_t key, uint8_t *base_mx, uint8_t *inverse_mx);

uint8_t ta152_encrypt_chunk(uint8_t input_chunk, uint8_t key_byte, uint8_t *base_mx, uint8_t *inverse_mx);

uint8_t ta152_decrypt_chunk(uint8_t input_chunk, uint8_t key_byte, uint8_t *base_mx, uint8_t *inverse_mx);

int ta152_encrypt(const char *in_path, const char *key_file, int status_b);

int ta152_decrypt(const char *in_path, const char *key_file);

#endif