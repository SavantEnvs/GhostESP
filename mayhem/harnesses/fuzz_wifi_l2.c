/* 802.11 data-frame L2 parser (wifi_l2.c): header geometry, LLC/SNAP and VLAN
 * unwrapping, used on sniffed frames by the EAPOL and ARP paths. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "vendor/wifi_l2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *frame = (uint8_t *)malloc(size ? size : 1);
  memcpy(frame, data, size);
  wifi_l2_info_t info;
  (void)wifi_l2_data_header_len(frame, size);
  if (wifi_l2_parse(frame, size, &info)) {
    /* The parser's contract: the payload it reports lies inside the frame. */
    if (info.payload_offset > size || info.llc_offset > info.payload_offset) abort();
    if (info.vlan_depth > WIFI_L2_MAX_VLAN_DEPTH) abort();
  }
  free(frame);
  return 0;
}
