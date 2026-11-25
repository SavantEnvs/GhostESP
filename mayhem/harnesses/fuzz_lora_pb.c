/* Meshtastic protobuf reader (lora_pb.c): ToRadio messages the phone app sends
 * over BLE (pb_parse_toradio) and LoRaConfig extras (pb_parse_lora_extras),
 * plus the raw field walker. byte0 selects the entry point; the rest is the
 * encoded message. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "managers/lora_pb.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1 || size > 0xffff) return -1;
  uint8_t sel = data[0];
  uint16_t len = (uint16_t)(size - 1);
  uint8_t *p = (uint8_t *)malloc(len ? len : 1);
  memcpy(p, data + 1, len);
  if (sel & 1) {
    toradio_t *tr = (toradio_t *)calloc(1, sizeof(toradio_t));
    pb_parse_toradio(p, len, tr);
    free(tr);
  } else {
    pb_lora_extras_t ex;
    memset(&ex, 0, sizeof ex);
    pb_parse_lora_extras(p, len, &ex);
    uint8_t out[512];
    pb_w_t w;
    pb_w_init(&w, out, sizeof out);
    pb_w_lora_extras(&w, &ex);
  }
  pb_r_t r;
  pb_r_init(&r, p, len);
  uint8_t field, wire;
  uint32_t v;
  const uint8_t *b;
  uint16_t bl;
  while (pb_r_next(&r, &field, &wire, &v, &b, &bl)) {
    if (wire == 2) {
      if (b < p || b + bl > p + len) abort(); /* LEN fields point into the input */
      pb_r_t in;
      pb_r_init(&in, b, bl);
      while (pb_r_next(&in, &field, &wire, &v, &b, &bl)) {}
    }
  }
  free(p);
  return 0;
}
