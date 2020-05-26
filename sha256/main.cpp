#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "sha256.h"

int main() {
  BYTE buf[SHA256_BLOCK_SIZE];
  BYTE * text;
  FILE * file;
  FILE * sha;
  CTX ctx;
  int i = 0;
  int flength = 0;
  // 读取文件数据
  file = fopen("./test.txt", "r");
  fseek(file, 0, SEEK_END);
	flength = ftell(file);
  text = (BYTE *)malloc((flength + 1) * sizeof(char)); // 因为 BYTE 就是 unsigned char 感觉没什么问题
  rewind(file);
	flength = fread(text, 1, flength, file);
	text[flength] = '\0';
  printf("content: %s\n", text);
  // 进行 hash 散列值计算
  sha256_init(&ctx);
  sha256_update(&ctx, text, flength);
	sha256_final(&ctx, buf);
  // 输出加密后的 hash 值
  printf("sha256: 0x");
  sha = fopen("./sha256.txt", "w");
  for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
    printf("%x", buf[i]);
    fprintf(sha, "%x", buf[i]);
  }
  printf("\n");
  return 0;
}