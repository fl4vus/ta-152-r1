#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ta152.h"

static void usage (const char *prog) {
    fprintf(stderr, "Usage:\nENCRYPTION: %s encrypt <input_file> <keyfile>\nDECRYPTION: %s decrypt <input_file> <keyfile>\nENCRYPTION WITH IV: %s encrypt <input_file> <keyfile> -iv\n", prog, prog, prog);
}

static void print_error(int error_code) {
    switch (error_code) {
        case ERR_OPEN_FAILED:
            fprintf(stderr, "Error: failed to open file\n");
            break;

        case ERR_NO_READ:
            fprintf(stderr, "Error: read failure\n");
            break;

        case ERR_NO_WRITE:
            fprintf(stderr, "Error: write failure\n");
            break;

        case ERR_CLOSE_FAILED:
            fprintf(stderr, "Error: close failure\n");
            break;

        case ERR_CANNOT_STAT_SIZE:
            fprintf(stderr, "Error: cannot determine file size\n");
            break;

        case ERR_NO_PATH_OUT:
            fprintf(stderr, "Error: output path error\n");
            break;

        case ERR_INVALID_KEY_SIZE:
            fprintf(stderr, "Error: invalid key size\n");
            break;

        case ERR_KEY_NOT_LOADED:
            fprintf(stderr, "Error: key not loaded\n");
            break;

        case ERR_UNDEFINED_STATUS:
            fprintf(stderr, "Error: undefined status value\n");
            break;

        case ERR_UNINITIALIZED_IV:
            fprintf(stderr, "Error: IV not initialized\n");
            break;

        case ERR_CANNOT_INIT_HEADER:
            fprintf(stderr, "Error: cannot initialize header\n");
            break;

        case ERR_HEADER_INVALID:
            fprintf(stderr, "Error: invalid or corrupted header\n");
            break;

        case ERR_UNSUPPORTED_VERSION:
            fprintf(stderr, "Error: unsupported file version\n");
            break;

        default:
            fprintf(stderr, "Error: unknown error (%d)\n", error_code);
            break;
    }
}

int main(int argc, char *argv[])
{
    if (argc > 5 || argc < 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    uint8_t status_bit = STATUS_OFF;
    if (argc == 5) {
        if (strcmp(argv[4], "-iv") == 0) {
            status_bit = STATUS_ON;
        }
        else {
            fprintf(stderr, "Error: unknown option '-%s'\n", argv[4]);
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    
    const char *mode = argv[1];
    const char *in_path = argv[2];
    const char *key_path = argv[3];
    
    int rc;

    if (strcmp(mode, "encrypt") == 0) {
        rc = ta152_encrypt(in_path, key_path, status_bit);
    }
    else if (strcmp(mode, "decrypt") == 0) {
        if (argc > 4) {
            fprintf(stderr, "Error: decrypt does not accept arguments\n");
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        rc = ta152_decrypt(in_path, key_path);
    }
    else {
        fprintf(stderr, "Error: unknown mode '%s'\n", mode);
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (rc < 0) {
        print_error(rc);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}