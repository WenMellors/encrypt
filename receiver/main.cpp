#include "sha256.h"
#include "receiver.h"
#include <cstring>
int main()
{
    //get socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    //connect sender
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;  //ipv4
    serv_addr.sin_addr.s_addr = inet_addr("192.168.255.128");  //ip address
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
        printf("0x%02x, ", *(buffer+i));
    }
    printf("\npklen from server:%d\n",ntohl(pk_len));
    //generate public key
    unsigned char *PKey=buffer;
    RSA *EncryptRsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&PKey, ntohl(pk_len));
    if(EncryptRsa==NULL){
        printf("EncryptRsa error!\n");
    }
    RSA_print_fp(stdout,EncryptRsa,0);

    //encrypt process
    unsigned char seed[SEED_LEN],outseed[SEED_LEN];
    unsigned char ranstr[SEED_LEN];
    memset(ranstr,0,128);
    genSeed(ranstr);
    strcpy((char*)seed,(const char*)ranstr);
    if(RSA_public_encrypt(SEED_LEN, (const unsigned char*)seed, outseed, EncryptRsa, RSA_NO_PADDING)==-1)
    {
        printf("encrypt failed!\n");
        char szErrMsg[1024] = {0};
        printf("error for encrypt is %s\n",ERR_error_string(ERR_get_error(),szErrMsg));
    }
    else{
        printf("The seed is %s\n\n\n\n\n",seed);
        //printf("The seed after encryption is %s\n\n\n\n\n",outseed);
    }
    //send encrypted seed
    sendSeed(outseed,SEED_LEN,sock);
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
    strncpy((char*)aesSeed,(const char*)seed,32);
    AES_KEY AESDecryptKey;
    AES_set_decrypt_key(aesSeed, 256, &AESDecryptKey);
    while(1){
        //receive data
        printf("Wainting For File...\n");
        memset(data_after_encrypt,0,sizeof(data_after_encrypt));
        recvFile(data_after_encrypt,data_after_decrypt,&AESDecryptKey,sock, fn);
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
    RSA_free(EncryptRsa);
    close(sock);
    return 0;
}
