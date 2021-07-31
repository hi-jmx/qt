#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "qdebug.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "openssl/ssl.h"
#include "openssl/err.h"







#define RSA_LENGTH 1024
// define rsa public key
#define BEGIN_RSA_PUBLIC_KEY    "BEGIN RSA PUBLIC KEY"
#define BEGIN_PUBLIC_KEY        "BEGIN PUBLIC KEY"
/**
 * @brief createRSA 载入密钥
 * @param key 密钥
 * @param publi 公钥1 私钥0
 * @return
 */
RSA * createRSA(unsigned char * key,int publi)
{
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, strlen((char*)key));
    if (keybio==NULL)
    {
        qDebug()<< "Failed to create key BIO";
        return 0;
    }
    RSA* pRsa = RSA_new();
    if(publi)
    {
        pRsa = PEM_read_bio_RSA_PUBKEY(keybio, &pRsa,NULL, NULL);
    }
    else
    {
        pRsa = PEM_read_bio_RSAPrivateKey(keybio, &pRsa,NULL, NULL);
    }
    if(pRsa == NULL)
    {
        qDebug()<< "Failed to create RSA";
        BIO_free_all(keybio);
    }
    return pRsa;
}
/**
 * @brief public_encrypt 公钥加密
 * @param data 待加密数据
 * @param data_len 待加密的数据长度
 * @param key 公钥
 * @param encrypted 加密后的数据
 * @return 加密长度
 */
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    int rsaResult = RSA_public_encrypt(data_len,data,encrypted,rsa,RSA_PKCS1_PADDING);
    return rsaResult;
}
/**
 * @brief private_decrypt 私钥解密
 * @param enc_data 待解密数据
 * @param data_len 待解密数据长度
 * @param key 私钥
 * @param decrypted 解密后的数据
 * @return
 */
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    int  rsaResult = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,RSA_PKCS1_PADDING);
    return rsaResult;
}
/**
 * @brief private_encrypt 私钥加密
 * @param data 待加密数据
 * @param data_len 待加密数据长度
 * @param key 私钥
 * @param encrypted 加密后数据
 * @return
 */
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    qDebug()<<RSA_size(rsa);
    int rsaResult = RSA_private_encrypt(data_len,data,encrypted,rsa,RSA_PKCS1_PADDING );
    return rsaResult;
}
/**
 * @brief public_decrypt 公钥解密
 * @param enc_data 待解密数据
 * @param data_len 待解密数据长度
 * @param key 公钥
 * @param decrypted 解密后的数据
 * @return
 */
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    qDebug()<<RSA_size(rsa);
    int  rsaResult = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,RSA_PKCS1_PADDING );
    return rsaResult;
}
/**
 * @brief public_encrypt 公钥加密
 * @param data 待加密数据
 * @param keystr 公钥
 * @param encrypted 加密后数据
 * @return
 */
int public_encrypt(QString &data,QString &keystr,QString &encrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int exppadding=rsasize;
    int rsaResult=-1;
//    QByteArray decdata=QByteArray::fromStdString(data.toStdString()).toBase64(QByteArray::Base64Encoding);
    QByteArray decdata=data.toUtf8();
    QByteArray signByteArray;
    int data_len=decdata.length();
    if(data_len>exppadding-11)
        exppadding=exppadding-11;
    int b=0;
    int s=data_len/(exppadding);//片数
    if(data_len%(exppadding))
        s++;
    for(int i=0;i<s;i++)
    {
        QByteArray subdata;
        subdata.clear();
        for(int j=0;j<exppadding;j++)
        {
            if(i*exppadding+j>data_len)
                break;
            subdata[j]=decdata[j+i*exppadding];
        }
        unsigned char *smldata=(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        b +=RSA_public_encrypt(exppadding,smldata,smlencrypted,rsa,RSA_PKCS1_PADDING);
        if(b>0)
        {
            QByteArray subarray=QByteArray::fromRawData((const char *)smlencrypted,rsasize);
            signByteArray.append(subarray);
        }
        free(smldata);
    }
    QString str(signByteArray.toHex());
    qDebug()<<str;
    encrypted.append(str);
    rsaResult=b;
    return rsaResult;
}
/**
 * @brief private_decrypt 私钥解密
 * @param data 待解密数据
 * @param keystr 私钥
 * @param decrypted 解密后的数据
 * @return
 */
int private_decrypt(QString &data,QString &keystr,QString &decrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int rsaResult=-1;
    QByteArray encdata=QByteArray::fromHex(QByteArray::fromStdString( data.toStdString()));
    QByteArray signByteArray;
    int data_len=encdata.length();
    int b=0;
    int s=data_len/(rsasize);//片数
    if(data_len%(rsasize))
        s++;
    for(int i=0;i<s;i++)
    {
        QByteArray subdata;
        subdata.clear();
        for(int j=0;j<rsasize;j++)
        {
            if(i*rsasize+j>data_len)
                break;
            subdata[j]=encdata[j+i*rsasize];
        }
        unsigned char *smldata=(unsigned char*)subdata.data();//(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        b +=RSA_private_decrypt(rsasize,smldata,smlencrypted,rsa,RSA_PKCS1_PADDING);
        if(b>0)
        {
            QByteArray decdata((char*)smlencrypted);
            signByteArray.append(decdata);
        }
    }
//    QByteArray b1= QByteArray::fromBase64(signByteArray,QByteArray::Base64Encoding);
    QByteArray b1= signByteArray;
    std::string str=b1.toStdString();
    decrypted.append(QString::fromStdString( str));
    rsaResult=b;
    return rsaResult;
}
/**
 * @brief private_encrypt 私钥加密
 * @param data 待加密数据
 * @param keystr 私钥
 * @param encrypted 解密后的数据
 * @return
 */
int private_encrypt(QString &data,QString &keystr,QString &encrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int exppadding=rsasize;
    int rsaResult=-1;
//    QByteArray decdata=QByteArray::fromStdString(data.toStdString()).toBase64(QByteArray::Base64Encoding);
    QByteArray decdata=QByteArray::fromStdString(data.toStdString());
    QByteArray signByteArray;
    int data_len=decdata.length();
    if(data_len>exppadding-11)//padding占11位
        exppadding=exppadding-11;
    int b=0;
    int s=data_len/(exppadding);//片数
    if(data_len%(exppadding))
        s++;
    for(int i=0;i<s;i++)
    {
        //分片加密
        QByteArray subdata;
        subdata.clear();;
        for(int j=0;j<exppadding;j++)
        {
            if(i*exppadding+j>data_len)
                break;
            subdata[j]=decdata[j+i*exppadding];
        }
        unsigned char *smldata=(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        b +=RSA_private_encrypt(exppadding,smldata,smlencrypted,rsa,RSA_PKCS1_PADDING);
        if(b>0)
        {
            QByteArray subarray=QByteArray::fromRawData((const char *)smlencrypted,rsasize);
            signByteArray.append(subarray);
        }
        free(smldata);
    }
    QString str(signByteArray.toHex());
    qDebug()<<str;
    encrypted.append(str);
    rsaResult=b;
    return rsaResult;
}
/**
 * @brief public_decrypt 公钥解密
 * @param data 待解密数据
 * @param keystr 公钥
 * @param decrypted 解密后的数据
 * @return
 */
int public_decrypt(QString &data,QString &keystr,QString &decrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int rsaResult=-1;
    QByteArray encdata=QByteArray::fromHex(QByteArray::fromStdString( data.toStdString()));
    QByteArray signByteArray;
    int data_len=encdata.length();
    int b=0;
    int s=data_len/(rsasize);//片数
    if(data_len%(rsasize))
        s++;
    for(int i=0;i<s;i++)
    {
        QByteArray subdata;
        subdata.clear();
        for(int j=0;j<rsasize;j++)
        {
            if(i*rsasize+j>data_len)
                break;
            subdata[j]=encdata[j+i*rsasize];
        }
        unsigned char *smldata=(unsigned char*)subdata.data();//(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        b +=RSA_public_decrypt(rsasize,smldata,smlencrypted,rsa,RSA_PKCS1_PADDING);
        if(b>0)
        {
            QByteArray decdata((char*)smlencrypted);
            signByteArray.append(decdata);
        }
    }
//    QByteArray b1= QByteArray::fromBase64(signByteArray,QByteArray::Base64Encoding);
    QByteArray b1=signByteArray;
    std::string str=b1.toStdString();
    decrypted.append(QString::fromStdString( str));
    rsaResult=b;
    return rsaResult;
}
