#include <QCoreApplication>
#include "rsa_test.h"

#define ENCRYPR_LENGTH_MAX 1024

uchar g_public_key[] = "-----BEGIN PUBLIC KEY-----\n" \
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2irHzIQHa5Wl+Lqs1ETTgwl6y\n"\
        "fKvR9qWKPpkvCy72hjkEUDEhLrAT1qjwZY7qG9xWJfJvgzDhyzIbw5+B0V6bhLmq\n"\
        "bBMXYWzLyLu4i/KTSRmQwmRHYkLOSprvUm3XapQonrlnu/YFtAabQf+sZO37Igo/\n"\
        "aPomoR/QOzcw1pdLywIDAQAB\n"\
        "-----END PUBLIC KEY-----";

uchar g_private_key[] = "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICWwIBAAKBgQC2irHzIQHa5Wl+Lqs1ETTgwl6yfKvR9qWKPpkvCy72hjkEUDEh\n"\
        "LrAT1qjwZY7qG9xWJfJvgzDhyzIbw5+B0V6bhLmqbBMXYWzLyLu4i/KTSRmQwmRH\n"\
        "YkLOSprvUm3XapQonrlnu/YFtAabQf+sZO37Igo/aPomoR/QOzcw1pdLywIDAQAB\n"\
        "AoGAEdCfZVcHU1GoZgQv+VHgkz7k9w5rxmYH6eIKGSlCQBUBY4ZgBRkFXipI+o0u\n"\
        "0XI+orm5W2C2WJL4JPWGj6jbTq/uNAFUahVwvI9zcfoaf733vqe50nbHlKlNsg3Q\n"\
        "P4tKTfe2laXs1g4cHLqWquIM1uxkMJwM3qzFAqPjP4lWMAECQQDneinLmw87SXyZ\n"\
        "RI6hzbo60JsCbB+hDnZ/VI0tYukmAuUY+Qf+0S21Qq1ZjxZJlF6VmRvFXNaKhfug\n"\
        "M8QzXZIBAkEAyeFdvmQK9N/TvaJVZlzPHGTz2ZD2lHRnxMbPMUc771H5ULx6IoxE\n"\
        "58jHYDgDGzN3/xvtCQ8I8DCCHjhHyoqFywJAFxBjDbh7ggrGcXcVRyX6glW6vDkN\n"\
        "xbxtLi68imMqm/D55s0ZcNhi14a3Qw8wx1ATRJCm5blkXxUOh13hFMUkAQJAYfA1\n"\
        "fFIohpe3r337lEdeKtZG/ru3BFpcpTgV+EAosXfBTgvB7NTD8PaU0vcZeq7Dfj3c\n"\
        "BtMGcQ/3cBW5rmb5dQJAWa0Pn3HC2rUhcb4ss2vVLr4/Sv+wO8E/hRiNFvKNzDKF\n"\
        "CHKXkdnWPF3FHINGJ7IXt4PkFiZ8S3uEQAoUZljukw==\n"\
        "-----END RSA PRIVATE KEY-----";

void StrToHex(unsigned char *pbDest, char *pbSrc, int nLen)
{
    char h1, h2;
    char s1, s2;
    int i;

    for (i = 0; i < nLen; i++)
    {
        if (pbSrc[2 * i] >= 'a' && pbSrc[2 * i] <= 'z')
        {
            pbSrc[2 * i] -= 'a' - 'A';
        }
        if (pbSrc[2 * i + 1] >= 'a' && pbSrc[2 * i + 1] <= 'z')
        {
            pbSrc[2 * i + 1] -= 'a' - 'A';
        }
        h1 = pbSrc[2 * i];
        h2 = pbSrc[2 * i + 1];

        s1 = h1 - 0x30;
        if (s1 > 9)
            s1 -= 7;

        s2 = h2 - 0x30;
        if (s2 > 9)
            s2 -= 7;

        pbDest[i] = s1 * 16 + s2;
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    char *data = "01234567899876543210";
    int dataLen = strlen(data);
    char dataEn[ENCRYPR_LENGTH_MAX];
    char dataDe[ENCRYPR_LENGTH_MAX];
    memset(dataEn, 0 , ENCRYPR_LENGTH_MAX);
    memset(dataDe, 0 , ENCRYPR_LENGTH_MAX);

    int enLen = public_encrypt((uchar*)data, dataLen, g_public_key, (uchar*)dataEn );
    printf("public_encrypt:enLen %d \n",enLen);
    for(int i = 0; i < enLen;i++)
    {
        printf("%02x",(uchar)dataEn[i]);
    }
    printf("\n");




    printf("\n-------------------------------------------------\n\n");

    int deLen = private_decrypt((uchar*)dataEn, enLen, g_private_key, (uchar*)dataDe );

    printf("private_decrypt:deLen %d  dataDe %s\n", deLen, (char*)dataDe);



    char crypt[] = "b56f2db56ed74c48619047198766e070a132417ab8fe01e3364bd1a258532fa5b4d75a738f85c756edb95e87b81a6dedc43b94732162bba816f05dd4418c78490c7cea02ebe88a13230c11dd685b865c824293480f23940233ff9d58620c7c0c7cc2b1755b787176dcadb7b6cc1f5e9211a8d270b62dd15621a38be86246b801";
    uchar byte[ENCRYPR_LENGTH_MAX];
    memset(byte, 0 , ENCRYPR_LENGTH_MAX);

    StrToHex(byte, crypt, strlen(crypt)/2);
    for(int i = 0; i < strlen(crypt)/2; i++)
    {
        printf("%02x",byte[i] );
    }
    printf("ok\n");

    printf("\n-------------------------------------------------\n\n");

    memset(dataDe, 0 , ENCRYPR_LENGTH_MAX);
    deLen = private_decrypt(byte, strlen(crypt)/2, g_private_key, (uchar*)dataDe );

    printf("private_decrypt:deLen %d  dataDe %s\n", deLen, (char*)dataDe);

    return a.exec();



}

