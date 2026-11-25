/* Sub-GHz protocol decoders (subghz_decoders.c) over received pulse timings:
 * the batch decoder and the streaming engine. Input: int32 durations
 * (sign = level, as in the firmware's RAW captures). */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "managers/subghz_decoders.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t n = size / 4;
  if (n == 0) return -1;
  int32_t *dur = (int32_t *)malloc(n * sizeof(int32_t));
  memcpy(dur, data, n * sizeof(int32_t));
  subghz_decoded_signal_t res;
  memset(&res, 0, sizeof res);
  subghz_decode_signal(dur, n, &res);
  free(res.preserved_extra);

  static subghz_decoder_engine_t eng;
  subghz_engine_init(&eng);
  for (size_t i = 0; i < n; i++) {
    int32_t d = dur[i];
    bool level = d > 0;
    uint32_t mag = d < 0 ? (uint32_t)0 - (uint32_t)d : (uint32_t)d;
    subghz_engine_feed(&eng, level, mag);
    const subghz_stream_decoder_t *r = subghz_engine_get_result(&eng);
    if (r) {
      char out[256];
      subghz_stream_decoder_format_result(r, out, sizeof out);
      subghz_engine_reset(&eng);
    }
  }
  free(dur);
  return 0;
}
