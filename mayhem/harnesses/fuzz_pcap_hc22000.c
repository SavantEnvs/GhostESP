/* hashcat 22000 export of a pcap file from the SD card (pcap_export_hc22000):
 * pcap reader, radiotap skip, beacon SSIDs, EAPOL M2/M3 and PMKID extraction.
 * The input is the pcap file. */
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include "vendor/pcap.h"
#include "fuzz_scratch.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char path[640], out[700];
  snprintf(path, sizeof path, "%s/in.pcap", fuzz_scratch_dir());
  FILE *f = fopen(path, "wb");
  if (!f) abort();
  fwrite(data, 1, size, f);
  fclose(f);
  int pmkid = 0, hs = 0;
  out[0] = 0;
  pcap_export_hc22000(path, out, sizeof out, &pmkid, &hs);
  unlink(path);
  if (out[0]) unlink(out);
  return 0;
}
