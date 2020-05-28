
extern "C" {
#include "rsa.h" 
}
#include "sha256.h"
#include "receiver.h"
#include "aes.h"

int main()
{
    //get socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    //connect sender
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;  //ipv4
    serv_addr.sin_addr.s_addr = inet_addr("192.168.255.129");  //ip address
    serv_addr.sin_port = htons(8000);  //port
    int result=connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if(result==-1){
        printf("errno for connection is %d\n",errno);
    }else{
        printf("connection built!\n");
    }
    //receive public key and key length
    unsigned char buffer[100000];
    unsigned char *b_f=buffer;
    int32_t pk_len=0;
    recvPKeyAndLen(b_f,&pk_len,sock);

    //print public key information for comparison
    for (int i=0; i<ntohl(pk_len); i++)
    {
        printf("%c", *(buffer+i));
    }
    printf("\npklen from server:%d\n",ntohl(pk_len));
    //generate public key
    unsigned char *PKey=buffer;
    int flag = 0;
    long long modulus = 0;
    long long exponent = 0;
    for (int i = 0; i < ntohl(pk_len); ++i) {
        if (buffer[i] == '0' && buffer[i + 1] == 'd') {
            flag = 1;
            i += 2;
        }
        if (flag == 0) {
            modulus = modulus * 10 + buffer[i] - '0';
        } else {
            exponent = exponent * 10 + buffer[i] - '0';
        }

    }
    struct public_key_class pub[1];
    pub->modulus = modulus;
    pub->exponent = exponent;
    // RSA *EncryptRsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&PKey, ntohl(pk_len));
    // if(EncryptRsa==NULL){
    //     printf("EncryptRsa error!\n");
    // }

    printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
    //encrypt process
    unsigned char seed[SEED_LEN];
    unsigned char ranstr[SEED_LEN];
    memset(ranstr,0,128);
    genSeed(ranstr);
    strcpy((char*)seed,(const char*)ranstr);
    
    printf("Seed:%s\n", seed);
    long long *encrypted = rsa_encrypt((const char *)seed, SEED_LEN, pub);
    if (!encrypted){
        fprintf(stderr, "Error in encryption!\n");
        return 1;
    }
    char outseed[SEED_LEN * 20];
    // printf("Encrypted:\n");
    int offset = 0;
    char tmp[20];
    int j = 0;
    for(int i = 0; i < SEED_LEN; i++){
        // printf("%lld\n", (long long)encrypted[i]);
        // sprintf(outseed + offset, "%lld\n", (long long)encrypted[i]);
        sprintf(tmp, "%lld\0", (long long)encrypted[i]);
        int k = 0;
        for (j; j < SEED_LEN * 20 && tmp[k] != '\0'; ++j, ++k) {
            outseed[j] = tmp[k];
        }
        outseed[j++] = '\n';
        // printf("%d\n", offset);
        // offset += strlen(tmp);
        // printf("%s\n", outseed);
    }
    // printf("outseed:\n %s", outseed);
    // if(RSA_public_encrypt(SEED_LEN, (const unsigned char*)seed, outseed, EncryptRsa, RSA_NO_PADDING)==-1)
    // {
    //     printf("encrypt failed!\n");
    //     char szErrMsg[1024] = {0};
    //     printf("error for encrypt is %s\n",ERR_error_string(ERR_get_error(),szErrMsg));
    // }
    // else{
    //     printf("The seed is %s\n\n\n\n\n",seed);
    //     //printf("The seed after encryption is %s\n\n\n\n\n",outseed);
    // }
    //send encrypted seed
    sendSeed((unsigned char*)outseed,SEED_LEN * 20,sock);
    unsigned char data_after_encrypt[16];
    unsigned char data_after_decrypt[16];
    unsigned char aesSeed[32];
    // jwj work
    bool isSHA = true; // 第一次收到的文件是 sha
    char fn[256];
    BYTE buf[SHA256_BLOCK_SIZE];
    BYTE * text;
    FILE * fp;
    FILE * sha;
    char sha_r[64];
    char sha_s[64];
    int fsize;
    int i;
    CTX ctx;
    // jwj work
    /***aes***/ 
    strncpy((char*)aesSeed,(const char*)seed,32);

    unsigned char aes_exp_key [11 * 16] = {0};
    aes_expand_key(aesSeed, aes_exp_key);

    aes_decryption_keys(aes_exp_key);

    while(1){
        //receive data
        printf("Wainting For File...\n");
        memset(data_after_encrypt,0,sizeof(data_after_encrypt));
        recvFile(data_after_encrypt,data_after_decrypt,aes_exp_key,sock, fn);
        // jwj work
        if (isSHA) {
            isSHA = false;
        } else {
            // calculate sha
            fp=fopen((const char*)fn,"r");
            fseek(fp,SEEK_SET,SEEK_END);
            fsize=ftell(fp);
            fseek(fp,0,SEEK_SET);
            text = (BYTE *)malloc((fsize + 1) * sizeof(char)); // 因为 BYTE 就是 unsigned char 感觉没什么问题
            fsize = fread(text, 1, fsize, fp);
            text[fsize] = '\0';
            sha256_init(&ctx);
            sha256_update(&ctx, text, fsize);
            sha256_final(&ctx, buf);
            sha = fopen("./sha256_rec.txt", "w");
            for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
                fprintf(sha, "%x", buf[i]);
            }
            fclose(sha);
            fclose(fp);
            free(text);
            // compare sha256 and sha256_rec
            fp = fopen("./sha256.txt", "r");
            sha = fopen("./sha256_rec.txt", "r");
            fread(sha_s, 1, 63, fp);
            fread(sha_r, 1, 63, sha);
            sha_s[63] = '\0';
            sha_r[63] = '\0';
            if (strcmp(sha_r, sha_s) != 0) {
                printf("\n sha check fail\n");
            } else {
                printf("\n sha check pass\n");
            }
            isSHA = true;
        }
        // jwj work
    }
    free(encrypted);
    close(sock);
    return 0;
}
