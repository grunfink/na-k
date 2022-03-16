#ifndef ECC_H_
#define ECC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#define ECC_DEGREE 283              /* the degree of the field polynomial */
#define ECC_MARGIN 3                /* don't touch this */
#define ECC_NUMWORDS ((ECC_DEGREE + ECC_MARGIN + 31) / 32)

/* the following type will represent bit vectors of length (DEGREE+MARGIN) */
typedef __uint32_t bitstr_t[ECC_NUMWORDS];

typedef bitstr_t elem_t;        /* this type will represent field elements */
typedef bitstr_t exp_t;

#define ECC_STR_SIZE (8 * ECC_NUMWORDS + 1)
#define ECC_STR_OFFSET (ECC_NUMWORDS * 8 - (ECC_DEGREE + 3) / 4)


void ecc_generate_rnd(exp_t exp);

void ecc_generate_key_pair_rnd(exp_t k, elem_t x, elem_t y);
void ecc_generate_key_pair(elem_t k, elem_t x, elem_t y);

char *ecc_elem_to_str(char *buf, elem_t v);
void ecc_str_to_elem(elem_t v, char *buf);
void ecc_elem_to_bin(uint8_t *buf, elem_t v);
void ecc_bin_to_elem(elem_t v, uint8_t *buf);

int ecc_embedded_public_key_validation(const elem_t Px, const elem_t Py);
int ecc_public_key_validation(const char *Px, const char *Py);

void ecc_shared_secret(elem_t ss, const elem_t k, const elem_t Px, const elem_t Py);
void ecc_shared_secret_s(elem_t ss, char *priv, char *pub_x, char *pub_y);

void ecc_init_b283(void);

#ifdef __cplusplus
}
#endif

#endif /* ECC_H_ */
