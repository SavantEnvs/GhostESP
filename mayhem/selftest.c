/* Known-answer tests for the parsers the fuzz targets exercise, built with
 * normal flags against the same sources (mayhem/build.sh) and run by test.sh.
 * Prints one "PASS <name>" / "FAIL <name>" line per test. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "vendor/wifi_l2.h"
#include "vendor/pcap.h"
#include "vendor/GPS/minmea.h"
#include "managers/hid_script_parser.h"
#include "managers/nfc/ndef.h"

static int g_fail;
#define CHECK(name, cond) do { if (cond) printf("PASS %s\n", name); \
  else { printf("FAIL %s\n", name); g_fail++; } } while (0)

static void test_wifi_l2(void) {
  uint8_t f[40] = {0x08, 0x01};
  memcpy(f + 24, "\xAA\xAA\x03\x00\x00\x00\x88\x8E", 8);
  wifi_l2_info_t i;
  bool ok = wifi_l2_parse(f, 32, &i);
  CHECK("wifi_l2_eapol", ok && i.llc_offset == 24 && i.payload_offset == 32 &&
        i.ethertype == 0x888E && i.vlan_depth == 0);
  memcpy(f + 24, "\xAA\xAA\x03\x00\x00\x00\x81\x00\x20\x05\x08\x00", 12);
  ok = wifi_l2_parse(f, 36, &i);
  CHECK("wifi_l2_vlan", ok && i.payload_offset == 36 && i.ethertype == 0x0800 &&
        i.vlan_depth == 1 && i.vlan_tci[0] == 0x2005);
  CHECK("wifi_l2_short", !wifi_l2_parse(f, 20, &i));
}

static void test_minmea(void) {
  const char *s = "$GPRMC,081836,A,3751.65,S,14507.36,E,000.0,360.0,130998,011.3,E*62";
  struct minmea_sentence_rmc r;
  CHECK("minmea_id", minmea_sentence_id(s, true) == MINMEA_SENTENCE_RMC);
  bool ok = minmea_parse_rmc(&r, s);
  CHECK("minmea_rmc", ok && r.valid && r.date.day == 13 && r.date.month == 9 &&
        r.time.hours == 8 && r.time.minutes == 18 && r.latitude.value == -375165);
  CHECK("minmea_bad_checksum", minmea_sentence_id("$GPRMC,1*00", true) == MINMEA_INVALID);
}

static long write_capture(const char *dir, const uint8_t *frame, size_t len, bool verbatim,
                          uint32_t *incl_len) {
  char path[600];
  if (pcap_file_open_in_dir("t", dir, PCAP_CAPTURE_WIFI) != ESP_OK) return -1;
  pcap_set_write_frames_verbatim(verbatim);
  pcap_write_packet_to_buffer(frame, len, PCAP_CAPTURE_WIFI);
  pcap_file_close();
  snprintf(path, sizeof path, "%s/t_0.pcap", dir);
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  uint8_t buf[256];
  long n = (long)fread(buf, 1, sizeof buf, f);
  fclose(f);
  unlink(path);
  if (n >= 40) memcpy(incl_len, buf + 24 + 8, 4);
  if (n < 4 || memcmp(buf, "\xd4\xc3\xb2\xa1", 4) != 0) return -2;
  return n;
}

static void test_pcap(void) {
  char dir[] = "/tmp/ghostesp-selftest-XXXXXX";
  if (!mkdtemp(dir)) { CHECK("pcap_tmpdir", 0); return; }
  uint8_t b[47] = {0x80, 0x00};
  memcpy(b + 36, "\x00\x04test", 6);    /* SSID IE */
  memcpy(b + 42, "\x2d\x03\x01\x02\x03", 5); /* HT caps with a bad length */
  uint32_t incl = 0;
  long n = write_capture(dir, b, sizeof b, false, &incl);
  CHECK("pcap_beacon_trimmed", n == 24 + 16 + 8 + 42 && incl == 8 + 42);
  n = write_capture(dir, b, sizeof b, true, &incl);
  CHECK("pcap_verbatim_full", n == 24 + 16 + 8 + 47 && incl == 8 + 47);
  rmdir(dir);
}

static int g_strings;
static char g_last[64];
static bool sk(uint8_t m, uint8_t k, void *c) { (void)m; (void)k; (void)c; return true; }
static bool ss(const char *t, size_t l, void *c) {
  (void)c; g_strings++;
  snprintf(g_last, sizeof g_last, "%.*s", (int)l, t);
  return true;
}
static void dl(uint32_t ms, void *c) { (void)ms; (void)c; }
static bool rl(void *c) { (void)c; return true; }
static bool cn(void *c) { (void)c; return false; }

static void test_hid(void) {
  CHECK("hid_keyname_enter", hid_key_name_to_keycode("ENTER") == 0x28);
  hid_transport_t t = { sk, ss, dl, rl, cn, NULL };
  char script[] = "REM hi\nSTRING hello\nENTER\n";
  g_strings = 0; g_last[0] = 0;
  hid_script_execute(script, &t);
  CHECK("hid_script_string", g_strings >= 1 && strstr(g_last, "hello") != NULL);
}

static void test_ndef(void) {
  const uint8_t tlv[] = {0x03, 0x0B, 0xD1, 0x01, 0x07, 0x55, 0x04,
                         'e', 'x', '.', 'c', 'o', 'm', 0xFE};
  const uint8_t uid[7] = {1, 2, 3, 4, 5, 6, 7};
  char *s = ndef_build_details_from_tlv(tlv, sizeof tlv, uid, 7, "NTAG");
  CHECK("ndef_uri", s && strstr(s, "https://ex.com") != NULL);
  free(s);
}

int main(void) {
  test_wifi_l2();
  test_minmea();
  test_pcap();
  test_hid();
  test_ndef();
  return g_fail ? 1 : 0;
}
