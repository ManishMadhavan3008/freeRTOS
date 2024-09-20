/*
 * Copyright 2013-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES CCM authenticated encryption with additional data (AEAD)
 * demonstration program.
 */


#include "AES.h"
#include "main.h"

static uint8_t AEsErrorFlag = 0;
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
        test here ascii: https://www.javainuse.com/aesgenerator
                   hex: https://cryptii.com/pipes/aes-encryption
     */
   
    /* A 256 bit key */                        
    //unsigned char key []= "This-is-AESkey-256bitlong-forCB-";  //32 bytes  to test in ascii 
    unsigned char key []= {0x71,0x8d,0x65,0xa2,0x21,0xf0,0xb2,0xf1,0x2b,0x6c,0x92,0xb7,0xe5,0x45,0x01,0xdd,0x63,0xa8,0xe1,0x56,0xe0,0x3c,0xa0,0xe9,0x8e,0x73,0x65,0x3b,0x1d,0x0f,0x58,0xe5};  //32 bytes     

    /* A 128 bit IV */
                    
    unsigned char iv []={0xa5,0xfd,0xf9,0x10,0x76,0x6e,0x72,0x7e,0x21,0x00,0xfa,0x09,0xb7,0x57,0x86,0x85};//
    //unsigned char iv []="This-is-IV-key--";//16 bytes to test in ascii 

    /* Message to be encrypted */
    char plaintext []="The quick brown fox jumps over the lazy dog";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;
    
    

// int AES_EncryptData(KeyDerivFunc_t *AESData)
// {
    // encrypt((unsigned char *)AESData->PlainText, strlen(AESData->PlainText),AESData->AES_key,AESData->AES_Iv,AESData->AES_CipheredText);
// }

// int AES_DecryptData(KeyDerivFunc_t *AESData)
// {
    // decrypt(AESData->AES_CipheredText, strlen(AESData->PlainText),AESData->AES_key,AESData->AES_Iv,AESData->AES_CipheredText);
    
// }



int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, int *plaintext_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    
    //int plaintext_len;
    
    AEsErrorFlag =0;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    *plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    *plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return AEsErrorFlag;
}


void handleErrors(void)
{
    //printf("\n Decryption Error");
    AEsErrorFlag =1;
    //ERR_print_errors_fp(stderr);
    //abort();
}



/** @brief it will generate AES key and IV as per struct Key derivation Paramters

*  @param int iMenu()

*         information will be written.

*  @return eRES_OK.

*/
extern int AES_GetAESKeyAndIV(KeyDerivFunc_t *AESData)
{
    
    #if 1
    int ret = 0;
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;
    //unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    //const char password[] = "password";
    //const unsigned char *salt = NULL;
    int i,Len;
    //printf("\n");
    //printf("------------------------Get AES key and IV To test---------------------------------\n");
    //printf("AAD: "); for(i=0; i<32; ++i) { printf("%02x", AESData->AAD[i]); } printf("\n");
    //printf("SALT: "); for(i=0; i<8; ++i) { printf("%02x", AESData->Salt[i]); } printf("\n");
   // printf("Password :%s\n", AESData->Password);
   // printf("-----------------------------------------------------------------------------------\n");
    
    OpenSSL_add_all_algorithms();

    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher) { fprintf(stderr, "no such cipher\n"); return 1; }


    //dgst=EVP_get_digestbyname("md5");
    //if(!dgst) { fprintf(stderr, "no such digest\n"); return 1; }

    ret = EVP_BytesToKey(cipher, EVP_sha1(), AESData->Salt,
         (const unsigned char*)AESData->Password,
        strlen(AESData->Password), 1, AESData->AES_key, AESData->AES_Iv);
       //printf("\n size of the derived key:%d",ret); 
        
    if(ret ==0){
        fprintf(stderr, "\n EVP_BytesToKey failed\n");
        return 1;
    }
    
    //printf("\n");
    AESData->AES_keyLength = EVP_CIPHER_get_key_length(cipher);
    //printf("\nkeylen:%d",AESData->AES_keyLength);
    
    AESData->IV_Length = EVP_CIPHER_get_iv_length(cipher);
    //printf("\nIV len :%d",AESData->IV_Length);
    //printf("\n");
    
    //printf("\n Key: "); for(i=0; i<AESData->AES_keyLength; ++i) { printf("%02x ", AESData->AES_key[i]); } //printf("\n");
    //printf("Key hex: "); for(i=0; i<AESData->AES_keyLength; ++i) { printf("0x%02x,", AESData->AES_key[i]); } printf("\n");
    
    //printf("\n IV: "); for(i=0; i<AESData->IV_Length; ++i) { printf("%02x ", AESData->AES_Iv[i]); } //printf("\n");
    //printf("IV hex  "); for(i=0; i<AESData->IV_Length; ++i) { printf("0x%02x,", AESData->AES_Iv[i]); } printf("\n");
    #endif
    return 0;
}


int TestAES()
{
    KeyDerivFunc_t AESInit;
    strcpy(AESInit.Password,AES_Password);
    strcpy(AESInit.PlainText,plaintext);
    
    //memcpy(AESInit.AAD, AADData, sizeof(AADData));
    memcpy(AESInit.Salt,AES_Salt,sizeof(AES_Salt));
    //memcpy(AESInit.AEAD_TagValue,AeadTag,sizeof(AeadTag));
    
    AES_GetAESKeyAndIV(&AESInit);
    

    // printf("Get Key: "); for(i=0; i<AESData.AES_keyLength; ++i) { printf("%02x ", AESData.AES_key[i]); } printf("\n");
    
    // printf("Get IV: "); for(i=0; i<AESData.IV_Length; ++i) { printf("%02x ", AESData.AES_Iv[i]); } printf("\n");
    
    /* Encrypt the plaintext */
    //ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,ciphertext);
        /* Encrypt the plaintext */
    ciphertext_len = encrypt ((unsigned char *)AESInit.PlainText, strlen((char *)AESInit.PlainText), AESInit.AES_key, AESInit.AES_Iv, AESInit.AES_CipheredText);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)AESInit.AES_CipheredText, ciphertext_len);

    /* Decrypt the ciphertext */
    //decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,decryptedtext);
    
    decrypt(AESInit.AES_CipheredText, ciphertext_len, AESInit.AES_key, AESInit.AES_Iv,(uint8_t *)AESInit.AES_DecipheredText,&decryptedtext_len);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", AESInit.AES_DecipheredText);


    return 0; 
    
}



