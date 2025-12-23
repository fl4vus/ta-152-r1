#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/stat.h>
#include "ta152.h"

struct __attribute__((packed)) Header {
    uint32_t magic_number;
    uint8_t version_number;
    uint8_t status;
    uint8_t iv[IV_SIZE];
    uint32_t offset_a;
    uint16_t offset_b;
    uint32_t file_size;
};

int get_iv(uint8_t *iv) {
    if (getrandom(iv, IV_SIZE, 0) != IV_SIZE) {
        return ERR_UNINITIALIZED_IV;
    }
    return 1;
}

static inline uint8_t keystream_update(uint8_t S, uint8_t key_byte, uint32_t counter) {
    return (uint8_t)((S * 131 + key_byte + (counter & 0xFF)) & 0xFF);
}

static ssize_t min_ssize(ssize_t num1, ssize_t num2) {
    return num1 < num2 ? num1 : num2;
}

// open for read
static int fd_open_read(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return ERR_OPEN_FAILED;
    return fd;
}

// open for write
static int fd_open_write (const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return ERR_OPEN_FAILED;
    return fd;
}

// write at path, upto len bytes
static int write_all(int fd, const void *buffer, size_t len)
{
    const uint8_t *p = buffer;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0)
            return ERR_NO_WRITE;
        if (w == 0)
            continue;
        p   += w;
        len -= w;
    }
    return 0;
}

// basic read wrapper
static ssize_t fd_read(int fd, void *buf, size_t maxlen)
{
    ssize_t r = read(fd, buf, maxlen);
    if (r < 0)
        return ERR_NO_READ;
    return r;
}

long long filesize_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0)
        return ERR_CANNOT_STAT_SIZE;
    return st.st_size;
}

//close file at file descriptor
static int fd_close(int fd)
{
    int r = close(fd);
    if (r != 0)
        return ERR_CLOSE_FAILED;
    return 0;
}

static inline void swap_mx(uint8_t *base_mx, uint8_t *inverse_mx, int a, int b) {
    uint8_t x = base_mx[a];
    uint8_t y = base_mx[b];

    base_mx[a] = y;
    base_mx[b] = x;

    inverse_mx[x] = b;
    inverse_mx[y] = a;
}

int init_header(struct Header *hdr, int fd, int status) {
    hdr->magic_number = MAGIC_NUMBER;
    hdr->version_number = VERSION;
    if (status == 1) {
        hdr->status = STATUS_ON;
    }
    else if (status == 0) {
        hdr->status = STATUS_OFF;
    }
    else {
        return ERR_UNDEFINED_STATUS;
    }
    if (status == STATUS_OFF) {
        memset(hdr->iv, 0, IV_SIZE);
    }
    else {
        if (get_iv(hdr->iv) < 0)
            return ERR_UNINITIALIZED_IV;
    }
    hdr->offset_a = 0;
    hdr->offset_b = 65535;

    long long sz = filesize_fd(fd);
    if (sz < 0 || sz > UINT32_MAX)
        return ERR_CANNOT_STAT_SIZE;

    hdr->file_size = (uint32_t) sz;
    return 0;
}

int read_header(struct Header *hdr, int fd) {
    ssize_t r = fd_read(fd, hdr, sizeof *hdr);
    if (r != sizeof *hdr)
        return ERR_NO_READ;

    if (hdr->magic_number != MAGIC_NUMBER)
        return ERR_HEADER_INVALID;

    if (hdr->version_number > VERSION || hdr->version_number < 1)
        return ERR_UNSUPPORTED_VERSION;

    if (!(hdr->status == STATUS_ON || hdr->status == STATUS_OFF))
        return ERR_UNDEFINED_STATUS;

    return 0;
}

static void init_matrix(uint8_t base_mx[MATRIX_LEN]) {
    for (int i = 0; i < MATRIX_LEN; i++) {
        *(base_mx + i) = (uint8_t) i;
    }
}

static void ta152_round(uint8_t key, uint8_t *base_mx, uint8_t *inverse_mx) {
    
    int chunk_size;
    if (key == 0 || key == 1)
        chunk_size = 2;
    else
        chunk_size = (int)key;

//    uint8_t x, y;

    int offset = 0;
    while (offset + chunk_size <= MATRIX_LEN) {
        for (int i = 0; i < chunk_size / 2; i++) {
            int a = offset + i;
            int b = offset + chunk_size - 1 - i;

            swap_mx(base_mx, inverse_mx, a, b);
        }
        offset += chunk_size;
    }

    int leftover = MATRIX_LEN - offset;
    if (leftover > 1) {
        for (int i = 0; i < leftover / 2; i++) {
            int a = offset + i;
            int b = offset + leftover - 1 - i;

            swap_mx(base_mx, inverse_mx, a, b);
        }
    }
}

uint8_t ta152_encrypt_chunk(uint8_t input_chunk, uint8_t key_byte, uint8_t *base_mx, uint8_t *inverse_mx) {
        int pos = (int)input_chunk;
        ta152_round(key_byte, base_mx, inverse_mx);
        return *(base_mx + pos);
}

uint8_t ta152_decrypt_chunk(uint8_t input_chunk, uint8_t key_byte, uint8_t *base_mx, uint8_t *inverse_mx) {
    int pos = (int) input_chunk;
    ta152_round(key_byte, base_mx, inverse_mx);
    return *(inverse_mx + pos);
}

int ta152_encrypt(const char *in_path, const char *key_file, int status_b) {
    if (!(status_b == STATUS_ON || status_b == STATUS_OFF))
        return ERR_UNDEFINED_STATUS;

    size_t in_path_len = strlen(in_path);
    char *out_path = malloc(sizeof(char) * (in_path_len + 7));
    if (!out_path)
        return ERR_NO_PATH_OUT;
    strcpy(out_path, in_path);
    strcat(out_path, ".t152e");

    uint8_t *key_mx = malloc(sizeof(uint8_t) * KEY_SIZE);
    if (!key_mx) {
        free(out_path);
        return ERR_KEY_NOT_LOADED;
    }
    int keypos = 0;

    uint8_t base_mx[MATRIX_LEN];
    uint8_t inverse_mx[MATRIX_LEN];

    init_matrix(base_mx);
    init_matrix(inverse_mx);

    int in_file = fd_open_read(in_path);
    if (in_file < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_OPEN_FAILED;
    }

    int out_file = fd_open_write(out_path);
    if (out_file < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_OPEN_FAILED;
    }

    int key_d = fd_open_read(key_file);
    if (key_d < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        fd_close(in_file);
        fd_close(out_file);
        return ERR_OPEN_FAILED;
    }

    ssize_t key_bytes = fd_read(key_d, key_mx, KEY_SIZE);
    if (key_bytes != KEY_SIZE) {
        fd_close(in_file);
        fd_close(out_file); 
        fd_close(key_d);
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_INVALID_KEY_SIZE;
    }

    fd_close(key_d);

    struct Header hdr = {0};

    if (init_header(&hdr, in_file, status_b) < 0) {
        fd_close(in_file);
        fd_close(out_file);
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_CANNOT_INIT_HEADER;
    }

    if (write_all(out_file, &hdr, sizeof(hdr)) < 0) {
        fd_close(in_file);
        fd_close(out_file);
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_NO_WRITE;
    }

    uint8_t S = 0;
    uint32_t counter = 0;

    if (status_b == STATUS_ON) {
        S = key_mx[0] ^ hdr.iv[0] ^ hdr.iv[1];
        counter = (uint32_t) 0;
    }

    uint8_t inbuf[4096];
    uint8_t outbuf[4096];
    size_t outpos = 0;

    while (1) {
        ssize_t bytes_read = read(in_file, inbuf, sizeof inbuf);

        if (bytes_read == 0) {
            break; //EOF
        }

        if (bytes_read < 0) {
            explicit_bzero(key_mx, KEY_SIZE);
            free(key_mx);
            free(out_path);
            fd_close(in_file);
            fd_close(out_file);           
            return ERR_NO_READ;
        }

        for (ssize_t i = 0; i < bytes_read; i++) {
            uint8_t cipher =
                ta152_encrypt_chunk(inbuf[i], key_mx[keypos], base_mx, inverse_mx);
            if (status_b == STATUS_ON)
                cipher = cipher ^ S;

            outbuf[outpos++] = cipher;

            if (status_b == STATUS_ON) {
                S = keystream_update(S, key_mx[keypos], counter++);
            }
            keypos = (keypos + 1) % KEY_SIZE;

            if (outpos == sizeof outbuf) {
                if (write_all(out_file, outbuf, outpos) < 0) {
                    explicit_bzero(key_mx, KEY_SIZE);
                    free(key_mx);
                    free(out_path);
                    fd_close(in_file);
                    fd_close(out_file);
                    return ERR_NO_WRITE;
                }
                outpos = 0;
            }
        }
    }

// flush tail
    if (outpos > 0) {
        if (write_all(out_file, outbuf, outpos) < 0) {
            explicit_bzero(key_mx, KEY_SIZE);
            free(key_mx);
            free(out_path);
            fd_close(in_file);
            fd_close(out_file);
            return ERR_NO_WRITE;
        }
    }    

    free(out_path);
    explicit_bzero(key_mx, KEY_SIZE); 
    free(key_mx);
    fd_close(in_file);
    fd_close(out_file);
    return SUCCESS_ENCRYPT;
}

int ta152_decrypt(const char *in_path, const char *key_file) {
    size_t in_path_len = strlen(in_path);
    char extension[7];
    char *out_path = NULL;
    if (in_path_len > 6) {
        strcpy(extension, in_path + in_path_len - 6);

        if (strcmp(extension, ".t152e") == 0) {
            out_path = malloc(in_path_len - 6 + 1);
            if (!out_path) 
                return ERR_NO_PATH_OUT;

            strncpy(out_path, in_path, in_path_len - 6);
            out_path[in_path_len - 6] = '\0';
        }
    }

    if (!out_path) {
        out_path = malloc(in_path_len + 1);
        if (!out_path)
            return ERR_NO_PATH_OUT;
        strcpy(out_path, in_path);
    }

    uint8_t *key_mx = malloc(sizeof(uint8_t) * KEY_SIZE);
    if (!key_mx) {
        free(out_path);
        return ERR_KEY_NOT_LOADED;
    }
    int keypos = 0;
    

    uint8_t base_mx[MATRIX_LEN];
    uint8_t inverse_mx[MATRIX_LEN];

    init_matrix(base_mx);
    init_matrix(inverse_mx);

    int in_file = fd_open_read(in_path);
    if (in_file < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_OPEN_FAILED;
    }

    struct Header hdr = {0};
    int header_read = read_header(&hdr, in_file);
    if (header_read < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        fd_close(in_file);
        return header_read;
    }

    uint32_t remaining_for_read = hdr.file_size;

    long long in_file_size = filesize_fd(in_file);
    if (in_file_size < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        fd_close(in_file);
        return ERR_CANNOT_STAT_SIZE;
    }

    long long payload_size = in_file_size - (long long) sizeof (struct Header);
    if (payload_size != hdr.file_size) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        fd_close(in_file);
        return ERR_HEADER_INVALID;
    }


    int out_file = fd_open_write(out_path);
    if (out_file < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_OPEN_FAILED;
    }

    int key_d = fd_open_read(key_file);
    if (key_d < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        fd_close(in_file);
        fd_close(out_file);
        return ERR_OPEN_FAILED;
    }

    ssize_t key_bytes = fd_read(key_d, key_mx, KEY_SIZE);
    if (key_bytes != KEY_SIZE) {
        fd_close(in_file);
        fd_close(out_file); 
        fd_close(key_d);
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_INVALID_KEY_SIZE;
    }

    fd_close(key_d);

    uint8_t S = 0;
    uint32_t counter = 0;

    if (hdr.status == STATUS_ON) {
        S = key_mx[0] ^ hdr.iv[0] ^ hdr.iv[1];
        counter = (uint32_t) 0;
    }

    uint8_t inbuf[4096];
    uint8_t outbuf[4096];
    size_t outpos = 0;

    while (remaining_for_read > 0) {
        ssize_t to_read = min_ssize(remaining_for_read, sizeof(inbuf));
        ssize_t bytes_read = read(in_file, inbuf, to_read) ;
        //ssize_t bytes_read = read(in_file, inbuf, sizeof inbuf);

        if (bytes_read == 0) {
            break; //EOF
        }

        remaining_for_read -= bytes_read;

        if (bytes_read < 0) {
            explicit_bzero(key_mx, KEY_SIZE);
            free(key_mx);
            free(out_path);
            fd_close(in_file);
            fd_close(out_file);
            return ERR_NO_READ;
        }

        for (ssize_t i = 0; i < bytes_read; i++) {
            uint8_t plain_buffer = inbuf[i];
            if (hdr.status == STATUS_ON)
                plain_buffer = plain_buffer ^ S;

            uint8_t plain =
                ta152_decrypt_chunk(plain_buffer, key_mx[keypos], base_mx, inverse_mx);
            
            outbuf[outpos++] = plain;

            if (hdr.status == STATUS_ON) {
                S = keystream_update(S, key_mx[keypos], counter++);
            }
            keypos = (keypos + 1) % KEY_SIZE;

            if (outpos == sizeof outbuf) {
                if (write_all(out_file, outbuf, outpos) < 0) {
                    explicit_bzero(key_mx, KEY_SIZE);
                    free(key_mx);
                    free(out_path);
                    fd_close(in_file);
                    fd_close(out_file);
                    return ERR_NO_WRITE;
                }
                outpos = 0;
            }
        }
    }

// flush tail
    if (outpos > 0) {
        if (write_all(out_file, outbuf, outpos) < 0) {
            explicit_bzero(key_mx, KEY_SIZE);
            free(key_mx);
            free(out_path);
            fd_close(in_file);
            fd_close(out_file);
            return ERR_NO_WRITE;
        }
    }  
    
    free(out_path);
    explicit_bzero(key_mx, KEY_SIZE); 
    free(key_mx);
    fd_close(in_file);
    fd_close(out_file);
    return SUCCESS_DECRYPT;
}