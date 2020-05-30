#ifndef SHA256_H
#define SHA256_H

#include <cstddef>

#define SHA256_BLOCK_SIZE 32 // 32 字节，8 字


typedef unsigned char BYTE; // 1 字节
typedef unsigned int  WORD; // 4 字节

typedef struct {
	BYTE data[64]; // 数据块
	WORD datalen; // 用于标识 data 数组的有效下标
	unsigned long long bitlen; // 处理的消息的总长度
	WORD state[8]; // hash 散列值
} CTX;


void sha256_init(CTX *ctx); // 初始化消息块
void sha256_update(CTX *ctx, const BYTE data[], size_t len); // 根据输入的信息，迭代计算 hash 散列值
void sha256_final(CTX *ctx, BYTE hash[]); // 完成附加填充比特与长度信息，并将结果存储在 hash 内返回

#endif   // SHA256_H
