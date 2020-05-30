#include "mythread.h"
#include <QDebug>
#include <QFile>
#include <QTextStream>

MyThread::MyThread()
{
    stopped = false;
}

void MyThread::run()
{
    QFile aFile("place.tmp");
    int servSock = 0;
    if (aFile.open(QIODevice::ReadOnly|QIODevice::Text)) {
        QTextStream aStream(&aFile);
        ipAddr = aStream.readLine();
        port = aStream.readLine();
        mode = aStream.readLine();
    }
    if (mode == "receive") {
        sock = socketConnect(ipAddr.toStdString().c_str(), port.toUInt());
        qDebug() << sock << endl;
    }
    else if(mode == "send") {
        servSock = getServerSocket(ipAddr.toStdString().c_str(), port.toUInt());
        sock = waitForConnection(servSock);
    }
    connectionEstablished(sock, ipAddr, port, mode);

    if (mode == "receive") {
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
        strncpy((char*)seed,(const char*)ranstr, SEED_LEN);

        printf("Seed:%s\n", seed);
        long long *encrypted = rsa_encrypt((const char *)seed, SEED_LEN, pub);
        if (!encrypted){
            printf("Error in encryption!\n");
            exit(1);
        }
        char outseed[SEED_LEN * 20];
        printf("Encrypted:\n");
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
        //printf("outseed:\n %s", outseed);
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
        printf("send seed...\n");
        sendSeed((unsigned char*)outseed,SEED_LEN * 20,sock);
        unsigned char data_after_encrypt[16];
        unsigned char data_after_decrypt[16];
        unsigned char aesSeed[32];

        // jwj work
        bool isSHA = true; // 第一次收到的文件是 sha
        char fn[256];
        BYTE buf[SHA256_BLOCK_SIZE];
        BYTE * text;
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

        unsigned char* key = (unsigned char*)malloc(180*sizeof(unsigned char));
        memcpy((char *)key, (const char *)aes_exp_key, 11*16*sizeof(unsigned char));
        key[176] = 0;
        negotiationComplete(servSock, sock, key);

        aes_decryption_keys(aes_exp_key);

        // AES_KEY AESDecryptKey;
        // AES_set_decrypt_key(aesSeed, 256, &AESDecryptKey);

        // AES_KEY AESEncryptKey;
        // AES_set_encrypt_key(aesSeed, 256, &AESEncryptKey);
        printf("Negotiation completes.\n");

        while(1){
            //receive data
            printf("Waiting for text...\n");
            memset(data_after_encrypt,0,sizeof(data_after_encrypt));
            recvFile(data_after_encrypt,data_after_decrypt,aes_exp_key,sock, fn);
            FILE* fp;
            // jwj work
            if (isSHA) {
                isSHA = false;
            } else {
                // calculate sha
                fp=fopen("send.tmp","r");
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
                if((fp=fopen("send.tmp","r"))==NULL){
                    printf("File error!\nEnding the program!\n");
                    exit(0);
                }
                char text_buffer[4100];
                fseek(fp,SEEK_SET,SEEK_END);
                int fsize=ftell(fp);
                fseek(fp,0,SEEK_SET);
                fread(text_buffer, 1, fsize, fp);
                text_buffer[fsize] = 0;
                fclose(fp);
                QString qstr(text_buffer);
                receiveMessage(qstr);
            }
            // jwj work

        }
        free(encrypted);
        close(sock);
    }
    else if(mode == "send") {
        //1024-bits,RSA_F4-e_value,no callback
        struct public_key_class pub[1];
        struct private_key_class priv[1];
        RSA_gen_keys(pub, priv, (char *)"primes.txt");
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
        sendKey((unsigned char *)PublicKey,PublicKeyLen,sock);
        //Again, for comparison.
        // PKey = PublicKey;
        // RSA *EncryptRsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&PKey, PublicKeyLen);
        printf("You can compare this with the public key on the receiver.\n");
        // RSA_print_fp(stdout,EncryptRsa,0);
        //receive the encrypted seed.
        unsigned char buffer[128*20];
        unsigned char *s_b=buffer;
        recvSeed(s_b,128*20,sock);
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
            exit(0);
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

        // jwj work
        bool isSHA = true; // 第一次收到的文件是 sha
        char fn[256];
        BYTE buf[SHA256_BLOCK_SIZE];
        BYTE * text;
        FILE * sha;
        char sha_r[64];
        char sha_s[64];
        int fsize;
        int i;
        CTX ctx;
        // jwj work

        strncpy((char*)aesSeed,(const char*)outseed,32);

        unsigned char aes_exp_key [11 * 16] = {0};
        aes_expand_key(aesSeed,aes_exp_key);

        // AES_KEY AESEncryptKey;
        // AES_set_encrypt_key(aesSeed, 256, &AESEncryptKey);
        printf("Negotiation completes.\n");
        unsigned char* key = (unsigned char*)malloc(180*sizeof(unsigned char));
        memcpy((char *)key, (const char *)aes_exp_key, 11*16*sizeof(unsigned char));
        key[176] = 0;
        negotiationComplete(servSock, sock, key);

        unsigned char data_after_encrypt[16];
        unsigned char data_after_decrypt[16];
        aes_decryption_keys(aes_exp_key);

        while(1){
            //receive data
            printf("Waiting for text...\n");
            memset(data_after_encrypt,0,sizeof(data_after_encrypt));
            recvFile(data_after_encrypt,data_after_decrypt,aes_exp_key,sock, fn);
            FILE* fp;
            // jwj work
            if (isSHA) {
                isSHA = false;
            } else {
                // calculate sha
                fp=fopen("send.tmp","r");
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
                if((fp=fopen("send.tmp","r"))==NULL){
                    printf("File error!\nEnding the program!\n");
                    exit(0);
                }
                char text_buffer[4100];
                fseek(fp,SEEK_SET,SEEK_END);
                int fsize=ftell(fp);
                fseek(fp,0,SEEK_SET);
                fread(text_buffer, 1, fsize, fp);
                text_buffer[fsize] = 0;
                fclose(fp);
                QString qstr(text_buffer);
                receiveMessage(qstr);
            }
            // jwj work

        }
        free(outseed);
        close(sock);
    }
}
