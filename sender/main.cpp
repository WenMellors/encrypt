extern "C" {
#include "rsa.h" 
}
#include "sender.h"
#include "sha256.h"
#include <string>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include "aes.h"

int main(){
    int serv_sock=getServerSocket("192.168.116.128",8000);
    printf("Sender socket ready.\n");
    printf("Waiting for connection...\n");
    int clnt_sock=waitForConnection(serv_sock);
    printf("Connection built.\n");
    //1024-bits,RSA_F4-e_value,no callback
    struct public_key_class pub[1];
    struct private_key_class priv[1];
    RSA_gen_keys(pub, priv, PRIME_SOURCE_FILE);
    //print the rsa.
    printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->modulus, (long long) priv->exponent);
    printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
    
    // TOHEX
    char PublicKey[1024];
    sprintf(PublicKey, "%lld\0", pub->modulus);
    int len = strlen((const char *)PublicKey);
    sprintf(PublicKey + len, "0d%lld\0", pub->exponent);
    int PublicKeyLen = strlen((const char*)PublicKey);
    printf("PubKey: %s\n", PublicKey);
    // unsigned char PublicKey[1024];
    // unsigned char *PKey=PublicKey;
    // //Extract the public key information into buffer. In case of changes on the PublicKey, we use pointer PKey.
    // int PublicKeyLen=i2d_RSAPublicKey(ClientRSA, &PKey);
    // //print public key length, needed later.
    printf("PublicKeyBuff, Len=%d\n", PublicKeyLen);
    // //print public key information for comparison
    // for (int i=0; i<PublicKeyLen; i++)
    // {
    //     printf("0x%02x, ", *(PublicKey+i));
    // }
    // printf("\n");
    //send public key information and key length to receiver.
    sendKey((unsigned char *)PublicKey,PublicKeyLen,clnt_sock);
    //Again, for comparison.
    // PKey = PublicKey;
    // RSA *EncryptRsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&PKey, PublicKeyLen);
    printf("You can compare this with the public key on the receiver.\n");
    // RSA_print_fp(stdout,EncryptRsa,0);
    //receive the encrypted seed.
    unsigned char buffer[128*20];
    unsigned char *s_b=buffer;
    recvSeed(s_b,128*20,clnt_sock);
    printf("The encrypted seed is\n");
    //decrypt the seed.
    // unsigned char outseed[128];
    // memset(outseed, 0, sizeof(outseed));
    long long seed[128];
    int j = 0;
    for (int i = 0; i < 128; ++i) {
        long long num = 0;
        for (j; buffer[j] != '\n' && j < 128*20; ++j) {
            num = num * 10 + buffer[j] - '0';
        }
        seed[i] = num;
        j++;
        // printf("%lld\n", seed[i]);
    }
    char *outseed = rsa_decrypt(seed, 128, priv);
    if (!outseed){
        fprintf(stderr, "Error in decryption!\n");
        return 1;
    }
    printf("The origin seed is: ");
    for(int i=0; i < 128; i++){
        printf("%c", outseed[i]);
    } 
    printf("\n");
    // RSA_private_decrypt(128, (const unsigned char*)buffer, outseed, ClientRSA, RSA_NO_PADDING);
    // printf("The origin seed is %s\n",outseed);
    //aes-key
    unsigned char aesSeed[32]; //If you use no-padding while encrypting the origin seed, it must be 128bytes, but we only need the first 32bytes.
    strncpy((char*)aesSeed,(const char*)outseed,32);
    
    unsigned char aes_exp_key [11 * 16] = {0};
    aes_expand_key(aesSeed,aes_exp_key);

    printf("Negotiation completes.\n");
    unsigned char path[4097];
    unsigned char fname[4097];
    unsigned char data_to_encrypt[16];
    unsigned char data_after_encrypt[16];
    unsigned char *dae;
    unsigned long fsize;
    // jwj work
    BYTE buf[SHA256_BLOCK_SIZE];
    BYTE * text;
    CTX ctx;
    unsigned char shaPath[4097] = "sha256.txt";
    unsigned long shaSize;
    int i;
    FILE * sha;
    // jwj work
    while(1){
        memset(path,0,sizeof(path));
        printf("Please input path of the file you wanna send:\n");
        scanf("%s",path);
        FILE* fp;
        while((fp=fopen((const char*)path,"rb"))==NULL){
            memset(path,0,sizeof(path));
            printf("File error!\n");
            printf("Please input path of the file you wanna send:\n");
            scanf("%s",path);
        }
        printf("File opening...\n");
        fseek(fp,SEEK_SET,SEEK_END);
        fsize=ftell(fp);
        fseek(fp,0,SEEK_SET);
        // jwj work
        text = (BYTE *)malloc((fsize + 1) * sizeof(char)); // 因为 BYTE 就是 unsigned char 感觉没什么问题
        fsize = fread(text, 1, fsize, fp);
        text[fsize] = '\0';
        // 进行 hash 散列值计算
        sha256_init(&ctx);
        sha256_update(&ctx, text, fsize);
        sha256_final(&ctx, buf);
        fseek(fp,0,SEEK_SET);
        printf("sha256: 0x");
        sha = fopen("./sha256.txt", "w");
        for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
            printf("%x", buf[i]);
            fprintf(sha, "%x", buf[i]);
        }
        fclose(sha);
        free(text);
        sha = fopen("./sha256.txt", "rb");
        fseek(sha,SEEK_SET,SEEK_END);
        shaSize=ftell(sha);
        fseek(sha,0,SEEK_SET);
        memset(data_to_encrypt,0,sizeof(data_to_encrypt));
        sendFile(sha, shaSize, shaPath, data_to_encrypt, data_after_encrypt,&AESEncryptKey,clnt_sock);
        printf("sha path:%s\n", shaPath);
        fclose(sha);
        // jwj work
        memset(data_to_encrypt,0,sizeof(data_to_encrypt));
        sendFile(fp,fsize,path,data_to_encrypt,data_after_encrypt,aes_exp_key,clnt_sock);
        fclose(fp);
    }
    free(outseed);
    close(serv_sock);
    return 0;
}
