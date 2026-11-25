/* MeshCore LoRa packet deserializer (meshcore_packet.c): read a received frame,
 * then re-serialize and dedup-hash it as the repeater does. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "managers/meshcore_packet.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 255) return -1; /* the radio frame length is a u8 (mc_packet_read_from) */
  uint8_t *in = (uint8_t *)malloc(size ? size : 1);
  memcpy(in, data, size);
  mc_packet_t p;
  mc_packet_init(&p);
  if (mc_packet_read_from(&p, in, (uint8_t)size)) {
    uint8_t out[512];
    (void)mc_packet_raw_length(&p);
    (void)mc_packet_write_to(&p, out);
    (void)mc_packet_path_byte_len(&p);
    uint8_t h[MC_MAX_HASH_SIZE]; /* the receive path's dedup hash (meshcore_mesh.c dedup_seen) */
    mc_packet_calculate_hash(&p, h);
  }
  free(in);
  return 0;
}
