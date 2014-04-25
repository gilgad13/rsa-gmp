/**********************************************************************
 *                                                                    *
 * Created by Adam Brockett                                           *
 *                                                                    *
 * Copyright (c) 2010                                                 *
 *                                                                    *
 * Redistribution and use in source and binary forms, with or without *
 * modification is allowed.                                           *
 *                                                                    *
 * But if you let me know you're using my code, that would be freaking*
 * sweet.                                                             *
 *                                                                    *
 **********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"

void print_hex(char* arr, int len)
{
    int i;
    for(i = 0; i < len; i++)
        printf("%02x", (unsigned char) arr[i]);
}

int main()
{
    int i;
    private_key ku;
    public_key kp;
    size_t message_size = 1234;
    size_t buf_size = 4 * message_size;
    size_t cipher_size;
    char* message;
    char* cipher;

    /* Initialize public key */
    mpz_init(kp.n);
    mpz_init(kp.e);
    /* Initialize private key */
    mpz_init(ku.n);
    mpz_init(ku.e);
    mpz_init(ku.d);
    mpz_init(ku.p);
    mpz_init(ku.q);

    generate_keys(&ku, &kp);
    printf("---------------Private Key-----------------\n");
    printf("kp.n is [%s]\n", mpz_get_str(NULL, 16, kp.n));
    printf("kp.e is [%s]\n", mpz_get_str(NULL, 16, kp.e));
    printf("---------------Public Key------------------\n");
    printf("ku.n is [%s]\n", mpz_get_str(NULL, 16, ku.n));
    printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, ku.e));
    printf("ku.d is [%s]\n", mpz_get_str(NULL, 16, ku.d));
    printf("ku.p is [%s]\n", mpz_get_str(NULL, 16, ku.p));
    printf("ku.q is [%s]\n", mpz_get_str(NULL, 16, ku.q));

    message = (char*) malloc(message_size * sizeof(*message));
    for(i = 0; i < message_size; i++)
        message[i] = rand() % 0xFF;

    puts("original is:");
    print_hex(message, message_size);
    puts("");

    cipher = (char*) malloc(buf_size);
    cipher_size = encrypt(cipher, message, message_size, kp);
    puts("encrypted is:");
    print_hex(cipher, cipher_size);
    puts("");

    message_size = decrypt(message, cipher, cipher_size, ku);
    puts("decrypted is:");
    print_hex(message, message_size);
    puts("");

    free(message);
    free(cipher);

    return 0;
}
