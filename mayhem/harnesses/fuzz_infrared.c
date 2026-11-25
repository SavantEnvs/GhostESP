/* IR protocol decoders (infrared_decoder.c / infrared_common.c) over received
 * level/timing pairs. Input: u32le timings; levels alternate, starting high. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "managers/infrared_decoder.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  InfraredDecoderContext *d = infrared_decoder_alloc();
  if (!d) return 0;
  bool level = true;
  for (size_t i = 0; i + 4 <= size; i += 4) {
    uint32_t t;
    memcpy(&t, data + i, 4);
    (void)infrared_decoder_decode(d, level, t);
    level = !level;
  }
  infrared_decoder_free(d);
  return 0;
}
