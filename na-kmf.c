/* na - A tool for asymmetric encryption of files by grunfink - public domain */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "na.h"

#include "aes.h"
#include "ecc.h"
#include "sha256.h"

#define VERSION "1.02"


static int random_fill(uint8_t *buf, int z)
{
    int ret = 0;
    FILE *f;

    if ((f = fopen("/dev/random", "rb")) != NULL) {
        fread(buf, z, 1, f);
        fclose(f);
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: cannot read from random device\n");
    }

    return ret;
}


static int read_key_file(uint8_t *p, int size, char *fn)
/* reads a one-line hexadecimal text file into buffer */
{
    int ret = 0;
    FILE *f;

    if ((f = fopen(fn, "r")) != NULL) {
        int n, c;

        for (n = 0; n < size; n++) {
            fscanf(f, "%02x", &c);
            p[n] = c;
        }

        fclose(f);
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: cannot read key file\n");
    }

    return ret;
}


static int write_key_file(uint8_t *p, int size, char *fn)
/* writes a buffer as a one-line hexadecimal text file */
{
    int ret = 0;
    FILE *f; 

    if ((f = fopen(fn, "w")) != NULL) {
        int n;

        for (n = 0; n < size; n++)
            fprintf(f, "%02x", p[n]);
        fprintf(f, "\n");

        fclose(f);
    }
    else {
        ret = 3;
        fprintf(stderr, "ERROR: cannot write key file\n");
    }

    return ret;
}


int na_generate_keys(char *pk_fn, char *sk_fn)
{
    elem_t k, x, y;     /* secret and public keys */
    uint8_t sk[36];     /* secret key */
    uint8_t pk[72];     /* public key (x + y) */

    ecc_generate_key_pair_rnd(k, x, y);

    ecc_elem_to_bin(sk,      k);
    ecc_elem_to_bin(&pk[0],  x);
    ecc_elem_to_bin(&pk[36], y);

    /* write the secret and public keys */
    return write_key_file(sk, sizeof(sk), sk_fn) +
           write_key_file(pk, sizeof(pk), pk_fn);
}


int na_rebuild_public_key(char *pk_fn, char *sk_fn)
{
    int ret = 0;
    elem_t k, x, y;     /* secret and public keys */
    uint8_t sk[36];     /* secret key */
    uint8_t pk[72];     /* public key (x + y) */

    /* read the secret key */
    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) == 0) {
        /* recompute public key */
        ecc_bin_to_elem(k, sk);
        ecc_generate_key_pair(k, x, y);

        ecc_elem_to_bin(&pk[0],  x);
        ecc_elem_to_bin(&pk[36], y);

        /* write it */
        ret = write_key_file(pk, sizeof(pk), pk_fn);
    }

    return ret;
}


static void hash_key(uint8_t *salt, uint8_t *h_key, uint8_t *key, int size)
{
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, salt, 32);
    sha256_update(&ctx, key, size);
    sha256_final(&ctx, h_key);
}


static void encrypt_block(const uint8_t *nonce, uint8_t *hash, uint8_t *block, int size)
{
    SHA256_CTX ctx;
    int n;

    /* set the nonce as the IV */
    aes_set_iv(nonce);

    /* hash the plaintext block */
    sha256_init(&ctx);
    sha256_update(&ctx, block, size);
    sha256_final(&ctx, hash);

    /* encrypt */
    for (n = 0; n < size; n += 16)
        aes_ctr(&block[n], &block[n]);
}


static int decrypt_block(const uint8_t *nonce, const uint8_t *hash, uint8_t *block, int size)
{
    SHA256_CTX ctx;
    int n;
    uint8_t n_hash[32];

    /* set the nonce as the IV */
    aes_set_iv(nonce);

    /* decrypt */
    for (n = 0; n < size; n += 16)
        aes_ctr(&block[n], &block[n]);

    /* hash the plaintext block */
    sha256_init(&ctx);
    sha256_update(&ctx, block, size);
    sha256_final(&ctx, n_hash);

    return !!memcmp(hash, n_hash, 32);
}


#define BLOCK_SIZE 16 * 1024 * 1024

int na_encrypt(FILE *i, FILE *o, char *pk_fn)
{
    int ret = 0;
    elem_t x, y;            /* public key */
    elem_t t_k, t_x, t_y;   /* temporary keys */
    elem_t e_ss;            /* shared secret */
    uint8_t tmp_pk[72];     /* temporary public key */
    uint8_t ss[36];         /* shared secret */
    uint8_t h_ss[32];       /* hashed shared secret */
    uint8_t key[32];        /* stream key */
    uint8_t cy_key[32];     /* encrypted stream key */
    uint8_t salt[32];
    uint8_t nonce[16];
    uint8_t *bl;
    int z;

    bl = (uint8_t *)malloc(BLOCK_SIZE);

    /* read public key */
    if ((ret = read_key_file(tmp_pk, sizeof(tmp_pk), pk_fn)) != 0)
        goto end;

    ecc_bin_to_elem(x, &tmp_pk[0]);
    ecc_bin_to_elem(y, &tmp_pk[36]);

    /* create a disposable set of asymmetric keys:
       the public one shall be inside the encrypted stream
       aside with the encrypted symmetric key */
    ecc_generate_key_pair_rnd(t_k, t_x, t_y);
    ecc_elem_to_bin(&tmp_pk[0],  t_x);
    ecc_elem_to_bin(&tmp_pk[36], t_y);

    /* create a nonce for the encryption of the stream key */
    random_fill(nonce, sizeof(nonce));

    /* create the stream key */
    random_fill(key, sizeof(key));

    /* pick the shared secret */
    ecc_shared_secret(e_ss, t_k, x, y);
    ecc_elem_to_bin(ss, e_ss);

    /* create a salt to hash the shared secret */
    random_fill(salt, sizeof(salt));

    /* hash the shared secret to use it to encrypt the stream key */
    hash_key(salt, h_ss, ss, sizeof(ss));

    /* encrypt the stream key using the hashed shared secret as key */
    aes_set_key(h_ss);
    aes_set_iv(nonce);
    aes_encrypt_cbc_1(&key[0],  &cy_key[0]);
    aes_encrypt_cbc_1(&key[16], &cy_key[16]);

    /** start of output **/

    /* write the signature */
    bl[0] = 'n';
    bl[1] = 'a';
    bl[2] = 0x00;
    bl[3] = 0x03;
    fwrite(bl, 4, 1, o);

    /* write the disposable pk */
    fwrite(tmp_pk, sizeof(tmp_pk), 1, o);

    /* write the nonce */
    fwrite(nonce, sizeof(nonce), 1, o);

    /* write the salt */
    fwrite(salt, sizeof(salt), 1, o);

    /* write the encrypted stream key */
    fwrite(cy_key, sizeof(cy_key), 1, o);

    aes_set_key(key);

    /* read by blocks */
    while ((z = fread(bl, 1, BLOCK_SIZE, i)) > 0) {
        uint8_t hash[32];

        random_fill(nonce, sizeof(nonce));

        encrypt_block(nonce, hash, bl, z);

        if (fwrite(nonce, sizeof(nonce), 1, o) != 1 ||
            fwrite(hash,  sizeof(hash),  1, o) != 1 ||
            fwrite(bl, z, 1, o) != 1) {
            ret = 3;
            fprintf(stderr, "ERROR: write error\n");
            goto end;
        }
    }

end:
    free(bl);

    return ret;
}


int na_decrypt(FILE *i, FILE *o, char *sk_fn)
{
    int ret = 0;
    elem_t k;               /* secret key */
    elem_t t_x, t_y;        /* temporary keys */
    elem_t e_ss;            /* shared secret */
    uint8_t sk[36];         /* secret key */
    uint8_t tmp_pk[72];     /* temporary public key */
    uint8_t ss[36];         /* shared secret */
    uint8_t h_ss[32];       /* hashed shared secret */
    uint8_t key[32];        /* stream key */
    uint8_t cy_key[32];     /* encrypted stream key */
    uint8_t salt[32];
    uint8_t nonce[16];
    uint8_t hash[32];
    uint8_t *bl;
    int z;

    bl = (uint8_t *)malloc(BLOCK_SIZE);

    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) != 0)
        goto end;

    ecc_bin_to_elem(k, sk);

    /* read 4 bytes */
    if (fread(bl, 4, 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: unexpected EOF reading signature\n");
        goto end;
    }

    /* does it have a valid and supported signature? */
    if (bl[0] == 'n' && bl[1] == 'a' && bl[2] == 0x00) {
        if (bl[3] != 0x03) {
            ret = 4;
            fprintf(stderr, "ERROR: signature for another format (0x%02X)\n", bl[3]);
            goto end;
        }
    }
    else {
        ret = 4;
        fprintf(stderr, "ERROR: bad signature\n");
        goto end;
    }

    /* read the public key + the nonce + the mac + encrypted symmetric key */
    if (fread(tmp_pk, sizeof(tmp_pk), 1, i) != 1 ||
        fread(nonce,  sizeof(nonce),  1, i) != 1 ||
        fread(salt,   sizeof(salt),   1, i) != 1 ||
        fread(cy_key, sizeof(cy_key), 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: unexpected EOF reading header\n");
        goto end;
    }

    ecc_bin_to_elem(t_x, &tmp_pk[0]);
    ecc_bin_to_elem(t_y, &tmp_pk[36]);

    /* pick the shared secret */
    ecc_shared_secret(e_ss, k, t_x, t_y);
    ecc_elem_to_bin(ss, e_ss);

    /* hash the shared secret to use it to decrypt the stream key */
    hash_key(salt, h_ss, ss, sizeof(ss));

    /* decrypt the stream key using the hashed shared secret as key */
    aes_set_key(h_ss);
    aes_set_iv(nonce);
    aes_decrypt_cbc_1(&cy_key[0],  &key[0]);
    aes_decrypt_cbc_1(&cy_key[16], &key[16]);

    aes_set_key(key);

    /* read by blocks */
    while (fread(nonce, sizeof(nonce), 1, i) == 1 &&
           fread(hash,  sizeof(hash),  1, i) == 1 &&
           (z = fread(bl, 1, BLOCK_SIZE, i)) > 0) {

        if (decrypt_block(nonce, hash, bl, z)) {
            ret = 4;
            fprintf(stderr, "ERROR: corrupted stream\n");
            goto end;
        }

        if (fwrite(bl, z, 1, o) != 1) {
            ret = 3;
            fprintf(stderr, "ERROR: write error (block)\n");
            goto end;
        }
    }

end:
    free(bl);

    return ret;
}


int na_init(void)
{
    ecc_init_b283();

    return 0;
}


char *na_info(void)
{
    return "KMF (ECC B-283, SHA256, AES256-CTR) format=0x03";
}


char *na_version(void)
{
    return VERSION;
}
