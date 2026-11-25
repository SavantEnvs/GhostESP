/* NFC tag memory decoding: Type 2 tag layout (ntag_t2.c) and the NDEF
 * TLV/record decoder (ndef.c) for URI, text, Wi-Fi and smart-poster records.
 * Input: byte0 = path selector/model, bytes 1-7 = UID, rest = tag memory. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "managers/nfc/ndef.h"
#include "managers/nfc/ntag_t2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return -1;
  uint8_t sel = data[0];
  uint8_t uid[7];
  memcpy(uid, data + 1, 7);
  size_t len = size - 8;
  uint8_t *mem = (uint8_t *)malloc(len ? len : 1);
  memcpy(mem, data + 8, len);
  char *s = NULL;
  switch (sel & 3) {
  case 0: s = ndef_build_details_from_tlv(mem, len, uid, 7, "Tag"); break;
  case 1: s = ndef_build_details_from_message(mem, len, uid, 7, "Tag"); break;
  default:
    s = ntag_t2_build_details_from_mem(mem, len, uid, 7, (NTAG2XX_MODEL)(sel >> 2) % 4);
    break;
  }
  free(s);
  free(mem);
  return 0;
}
