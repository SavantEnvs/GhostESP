/* Capture path: frames handed to pcap.c by the promiscuous/BLE callbacks.
 * Input: byte0 = capture type (bits 0-1, mod 3) | verbatim (bit 2) | has radio
 * metadata (bit 3); bytes 1-6 = radiotap metadata; then frames as
 * [u16le length][bytes]. Every frame goes through pcap_write_packet_to_buffer_meta
 * (calculate_wifi_frame_length / is_valid_tag_length / radiotap_build / buffer
 * flush), the capture is closed, and the written file is read back by the
 * hc22000 scanner. Each input opens, fills and closes its own capture. */
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include "vendor/pcap.h"
#include "fuzz_scratch.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 7) return -1;
  const char *dir = fuzz_scratch_dir();
  pcap_capture_type_t type = (pcap_capture_type_t)((data[0] & 3) % 3);
  radiotap_meta_t meta = {0};
  meta.rssi = (int8_t)data[1];
  meta.rate = data[2];
  meta.channel = data[3];
  meta.band = (radiotap_band_t)(data[4] & 3);
  meta.antenna = data[5];
  meta.has_rssi = data[6] & 1;
  meta.has_rate = data[6] & 2;
  meta.has_channel = data[6] & 4;
  meta.has_antenna = data[6] & 8;
  const radiotap_meta_t *mp = (data[0] & 8) ? &meta : NULL;

  if (pcap_file_open_in_dir("fz", dir, type) != ESP_OK) return 0;
  pcap_set_write_frames_verbatim(data[0] & 4);
  size_t off = 7;
  while (off + 2 <= size) {
    size_t len = (size_t)data[off] | ((size_t)data[off + 1] << 8);
    off += 2;
    if (len > size - off) len = size - off;
    /* Copy so ASan sees the exact frame bounds the radio would hand over. */
    uint8_t *frame = (uint8_t *)malloc(len ? len : 1);
    memcpy(frame, data + off, len);
    pcap_write_packet_to_buffer_meta(frame, len, type, mp);
    free(frame);
    off += len;
  }
  pcap_flush_buffer_to_file();
  pcap_file_close();

  char path[640];
  snprintf(path, sizeof path, "%s/fz_0.pcap", dir);
  (void)pcap_has_hc22000_material(path);
  unlink(path);
  return 0;
}
