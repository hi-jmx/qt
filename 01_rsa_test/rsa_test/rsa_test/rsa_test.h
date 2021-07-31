#ifndef RSA_TEST_H
#define RSA_TEST_H

#include "openssl/rsa.h"

RSA *createRSA(unsigned char *key, int publi);
int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);
int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);
int private_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);
int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);

int public_encrypt(QString &data, QString &keystr, QString &encrypted);
int private_decrypt(QString &data, QString &keystr, QString &decrypted);
int private_encrypt(QString &data, QString &keystr, QString &encrypted);
int public_decrypt(QString &data, QString &keystr, QString &decrypted);

#endif // RSA_TEST_H

