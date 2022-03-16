/**************************************************************************************
 * 
 * This program implements the ECIES public key encryption scheme based on the
 * NIST B163 elliptic curve and the XTEA block cipher. The code was written
 * as an accompaniment for an article published in phrack #63 and is released to
 * the public domain.
 * Original author: Phrack Staff
 * Ported to ARM7TDMI: Jiri Pittner <jiri@pittnerovi.com>
 * compiled by arm-elf-gcc (GCC) 4.0.1 and tested on LPC2106
 * Adapted for B-283 and Leon-3 by a, 2018
 *
 **************************************************************************************/

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "ecc.h"

#define MACRO(A) do { A; } while(0)
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static __uint32_t CHARS2INT(const unsigned char *ptr)
{
    __uint32_t r;
    ptr += 3;
    r = *ptr--;
    r <<= 8;
    r |= *ptr--;
    r <<= 8;
    r |= *ptr--;
    r <<= 8;
    r |= *ptr--;
    return r;
}


/******************************************************************************/

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
    for (i = 0; i < ECC_NUMWORDS && !*x++; i++);
    return i == ECC_NUMWORDS;
}

/* return the number of the highest one-bit + 1 */
static int bitstr_sizeinbits(const bitstr_t x)
{
    int i;
    __uint32_t mask;
    for (x += ECC_NUMWORDS, i = 32 * ECC_NUMWORDS; i > 0 && !*--x; i -= 32);
    if (i)
        for (mask = ((__uint32_t) 1) << 31; !(*x & mask); mask >>= 1, i--);
    return i;
}

/* left-shift by 'count' digits */
static void bitstr_lshift(bitstr_t A, const bitstr_t B, int count)
{
    int i, offs = 4 * (count / 32);
    memmove((void *) A + offs, B, sizeof(bitstr_t) - offs);
    memset(A, 0, offs);
    if (count %= 32) {
        for (i = ECC_NUMWORDS - 1; i > 0; i--)
            A[i] = (A[i] << count) | (A[i - 1] >> (32 - count));
        A[0] <<= count;
    }
}

/* (raw) import from a byte array */
static void bitstr_import(bitstr_t x, const char *s)
{
    int i;
    for (x += ECC_NUMWORDS, i = 0; i < ECC_NUMWORDS; i++, s += 4)
        *--x = CHARS2INT((unsigned char *)s);
}


/* export as hex string (null-terminated!) */
static void bitstr_to_hex(char *s, const bitstr_t x)
{
    int i;
    for (x += ECC_NUMWORDS, i = 0; i < ECC_NUMWORDS; i++, s += 8)
        sprintf(s, "%08lX", (unsigned long) *--x);
}


static __uint8_t letter2bin(const char c)
{
    return c > '9' ? c + 10 - (c >= 'a' ? 'a' : 'A') : c - '0';
}

static __uint8_t octet2bin(const char *octet)
{
    return (letter2bin(octet[0]) << 4) | letter2bin(octet[1]);
}


static __uint32_t getword32(const char *s)
{

    //little endian
    union {
        __uint32_t i;
        __uint8_t c[sizeof(__uint32_t)];
    }
    r;
    r.c[3] = octet2bin(s);
    r.c[2] = octet2bin(s + 2);
    r.c[1] = octet2bin(s + 4);
    r.c[0] = octet2bin(s + 6);
    return r.i;
/*
    // BIG endian
    union {
        __uint32_t i;
        __uint8_t c[sizeof(__uint32_t)];
    }
    r;
    r.c[0] = octet2bin(s);
    r.c[1] = octet2bin(s + 2);
    r.c[2] = octet2bin(s + 4);
    r.c[3] = octet2bin(s + 6);
    return r.i;*/
}

/* import from a hex string */
static int bitstr_parse(bitstr_t x, const char *s)
{
    int len;
    if ((s[len = strspn(s, "0123456789abcdefABCDEF")]) ||
        (len > ECC_NUMWORDS * 8))
        return -1;

    bitstr_clear(x);
    x += len / 8;
    if (len % 8) {
        *x = getword32(s);
        *x >>= 32 - 4 * (len % 8);
        s += len % 8;
        len &= ~7;
    }
    for (; *s; s += 8)
        *--x = getword32(s);
    return len;
}


elem_t poly;                    /* the reduction polynomial */

#define field_set1(A) MACRO( A[0] = 1; memset(A + 1, 0, sizeof(elem_t) - 4) )

static int field_is1(const elem_t x)
{
    int i;
    if (*x++ != 1)
        return 0;
    for (i = 1; i < ECC_NUMWORDS && !*x++; i++);
    return i == ECC_NUMWORDS;
}

static void field_add(elem_t z, const elem_t x, const elem_t y)
{                               /* field addition */
    int i;
    for (i = 0; i < ECC_NUMWORDS; i++)
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
    for (i = 1; i < ECC_DEGREE; i++) {
        for (j = ECC_NUMWORDS - 1; j > 0; j--)
            b[j] = (b[j] << 1) | (b[j - 1] >> 31);
        b[0] <<= 1;
        if (bitstr_getbit(b, ECC_DEGREE))
            field_add(b, b, poly);
        if (bitstr_getbit(y, i))
            field_add(z, z, b);
    }
}

static void field_invert(elem_t z, const elem_t x)
/* field inversion */
{
    elem_t u, v, g, h;
    int i;
    bitstr_copy(u, x);
    bitstr_copy(v, poly);
    bitstr_clear(g);
    field_set1(z);
    while (!field_is1(u)) {
        i = bitstr_sizeinbits(u) - bitstr_sizeinbits(v);
        if (i < 0) {
            bitstr_swap(u, v);
            bitstr_swap(g, z);
            i = -i;
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

elem_t coeff_b, base_x, base_y, cofactor;

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

static void point_double(elem_t x, elem_t y)
/* double the point (x,y) */
{
    if (!bitstr_is_clear(x)) {
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
    } else
        bitstr_clear(y);
}

/* add two points together (x1, y1) := (x1, y1) + (x2, y2) */
static void point_add(elem_t x1, elem_t y1, const elem_t x2, const elem_t y2)
{
    if (!point_is_zero(x2, y2)) {
        if (point_is_zero(x1, y1))
            point_copy(x1, y1, x2, y2);
        else {
            if (bitstr_is_equal(x1, x2)) {
                if (bitstr_is_equal(y1, y2))
                    point_double(x1, y1);
                else
                    point_set_zero(x1, y1);
            } else {
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

exp_t base_order;

/* point multiplication via double-and-add algorithm */
static void point_mult(elem_t x, elem_t y, const exp_t exp)
{
    elem_t X, Y;
    int i;
    point_set_zero(X, Y);
    for (i = bitstr_sizeinbits(exp) - 1; i >= 0; i--) {
        point_double(X, Y);
        if (bitstr_getbit(exp, i))
            point_add(X, Y, x, y);
    }
    point_copy(x, y, X, Y);
}


static unsigned char __random(void)
{
    static int first_time = 1;
    static FILE *f = NULL;
    unsigned char v = 0;

    if (first_time) {
#ifndef BASIC_RANDOM
        f = fopen("/dev/random", "rb");
#endif /* BASIC_RANDOM */
        srandom(time(NULL));
        first_time = 0;
    }

    if (f == NULL || fread(&v, sizeof(v), 1, f) != 1)
        v = random() & 0xff;

    return v;
}


/* draw a random value 'exp' with 1 <= exp < n */
static void get_random_exponent(exp_t exp)
{
    unsigned char buf[4 * ECC_NUMWORDS];
    int r;
    do {
        for (r = 0; r < 4 * ECC_NUMWORDS; ++r) {
            buf[r] = __random() & 0xff;
        }
        bitstr_import(exp, (char *)buf);
        for (r = bitstr_sizeinbits(base_order) - 1; r < ECC_NUMWORDS * 32; r++)
            bitstr_clrbit(exp, r);
    } while (bitstr_is_clear(exp));
}


/** interface **/

void ecc_generate_rnd(exp_t exp)
/* generate a random exponent */
{
    get_random_exponent(exp);
}


void ecc_generate_key_pair_rnd(exp_t k, elem_t x, elem_t y)
/* generate a random public/private key pair */
{
    get_random_exponent(k);
    point_copy(x, y, base_x, base_y);
    point_mult(x, y, k);
}

void ecc_generate_key_pair(elem_t k, elem_t x, elem_t y) 
/* calculates x & y from a supplied k */
{
    point_copy(x, y, base_x, base_y);
    point_mult(x, y, k);
}


char *ecc_elem_to_str(char *buf, elem_t v)
{
    bitstr_to_hex(buf, v);

    return buf + ECC_STR_OFFSET - 1;
}


void ecc_elem_to_bin(uint8_t *buf, elem_t v)
{
    char str[ECC_STR_SIZE];
    int n;
    char *p;

    p = ecc_elem_to_str(str, v);

    for (n = 0; n < 36; n++) {
        int c;

        sscanf(p, "%02x", &c);
        buf[n] = (char) c;
        p += 2;
    }
}


void ecc_str_to_elem(elem_t v, char *buf)
{
    bitstr_parse(v, buf);
}


void ecc_bin_to_elem(elem_t v, uint8_t *buf)
{
    char str[ECC_STR_SIZE];
    int n;

    memset(str, '\0', sizeof(str));

    for (n = 0; n < 36; n++)
        sprintf(&str[n * 2], "%02x", buf[n]);

    ecc_str_to_elem(v, str);
}


int ecc_embedded_public_key_validation(const elem_t Px, const elem_t Py)
/* check that a given elem_t-pair is a valid point on the curve != 'o' */
{
    return (bitstr_sizeinbits(Px) > ECC_DEGREE)
        || (bitstr_sizeinbits(Py) > ECC_DEGREE) || point_is_zero(Px, Py)
        || !is_point_on_curve(Px, Py) ? -1 : 1;
}

int ecc_public_key_validation(const char *Px, const char *Py)
/* same thing, but check also that (Px,Py) generates a group of order n */
{
    elem_t x, y;
    if ((bitstr_parse(x, Px) < 0) || (bitstr_parse(y, Py) < 0))
        return -1;
    if (ecc_embedded_public_key_validation(x, y) < 0)
        return -1;
    point_mult(x, y, base_order);
    return point_is_zero(x, y) ? 1 : -1;
}


void ecc_shared_secret(elem_t ss, const elem_t k, const elem_t Px, const elem_t Py)
{
    elem_t y;

    point_copy(ss, y, Px, Py);
    point_mult(ss, y, k);
    point_mult(ss, y, cofactor);
}


void ecc_shared_secret_s(elem_t ss, char *priv, char *pub_x, char *pub_y)
{
    elem_t k, Px, Py;

    bitstr_parse(k, priv);
    bitstr_parse(Px, pub_x);
    bitstr_parse(Py, pub_y);

    ecc_shared_secret(ss, k, Px, Py);
}


void ecc_init_b283(void)
{
    /* x^283 + x^12 + x^7 + x^5 + 1 */
    bitstr_parse(poly,       "0800000000000000000000000000000000000000000000000000000000000000000010A1");
    bitstr_parse(coeff_b,    "027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5");
    bitstr_parse(base_x,     "05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053");
    bitstr_parse(base_y,     "03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4");
    bitstr_parse(base_order, "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307");
    bitstr_parse(cofactor,   "000000000000000000000000000000000000000000000000000000000000000000000002");
}
