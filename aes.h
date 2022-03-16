/*

    aes.h

*/

#ifndef AES_H_
#define AES_H_

#ifdef __cplusplus
extern "C" {
#endif

void aes_set_key(const unsigned char *key);
void aes_set_iv(const unsigned char *iv);
void aes_encrypt_1(const unsigned char *input, unsigned char *output);
void aes_decrypt_1(const unsigned char *input, unsigned char *output);
void aes_encrypt_cbc_1(const unsigned char *input, unsigned char *output);
void aes_decrypt_cbc_1(const unsigned char *input, unsigned char *output);
void aes_ctr(const unsigned char *input, unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif /* AES_H_ */
