/* Unishox2 decompressor for received Meshtastic compressed text (lora_unishox.c). */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lora_unishox.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 4096) return -1;
  uint8_t *in = (uint8_t *)malloc(size ? size : 1);
  memcpy(in, data, size);
  char *out = (char *)malloc(512);
  lora_unishox_decompress(in, (int)size, out, 512);
  free(out);
  free(in);
  return 0;
}
