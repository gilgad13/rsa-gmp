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
    mpz_t M;
    mpz_t C;
    mpz_t DC;
    private_key ku;
    public_key kp;
    char buf[6*BLOCK_SIZE];

    mpz_init(M);
    mpz_init(C);
    mpz_init(DC);

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

    for(i = 0; i < 6*BLOCK_SIZE; i++)
        buf[i] = rand() % 0xFF;

    mpz_import(M, (6*BLOCK_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
    printf("original is [%s]\n", mpz_get_str(NULL, 16, M));
    block_encrypt(C, M, kp);
    printf("encrypted is [%s]\n", mpz_get_str(NULL, 16, C));
    block_decrypt(DC, C, ku);
    printf("decrypted is [%s]\n", mpz_get_str(NULL, 16, DC));
    return 0;
}
