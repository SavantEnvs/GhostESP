/* Flipper supported-card parsers (flipper_nfc_compat.c + flipper_parsers/*.c:
 * transit, hotel, toy and access cards) over a MIFARE Classic dump, as run on
 * a card the reader just dumped. Input: byte0 = card type (mod 3), byte1 = UID
 * length (mod 11), 10 UID bytes, 32-byte block-read mask, then block data. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "managers/nfc/flipper_nfc_compat.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 44) return -1;
  MfClassicData *d = (MfClassicData *)calloc(1, sizeof(MfClassicData));
  d->type = (MfClassicType)(data[0] % 3);
  d->uid_len = data[1] % 11;
  memcpy(d->uid, data + 2, 10);
  memcpy(d->block_read_mask, data + 12, 32);
  size_t n = size - 44;
  if (n > sizeof d->block) n = sizeof d->block;
  memcpy(d->block, data + 44, n);
  /* Key masks mirror which sector trailers were read. */
  for (int s = 0; s < 40; s++) {
    uint8_t first = mf_classic_get_first_block_num_of_sector((uint8_t)s);
    uint8_t trailer = (uint8_t)(first + (s < 32 ? 3 : 15));
    if (!mf_classic_is_block_read(d, trailer)) continue;
    memcpy(d->keys.key_a[s].data, d->block[trailer].data, 6);
    memcpy(d->keys.key_b[s].data, d->block[trailer].data + 10, 6);
    if (s < 64) { d->keys.key_a_mask |= 1ull << s; d->keys.key_b_mask |= 1ull << s; }
  }
  char *s = flipper_nfc_try_parse_mfclassic_from_cache(d);
  free(s);
  free(d);
  return 0;
}
