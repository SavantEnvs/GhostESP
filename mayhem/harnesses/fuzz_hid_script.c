/* BadUSB / DuckyScript interpreter (hid_script_parser.c), as run on a script
 * from the SD card. The transport is a no-op keyboard. Layout is reset per
 * input because scripts can change it.
 * The transport's is_cancelled() is the user's stop button: on the device a
 * script like "REPEAT 2000000000" types until the operator cancels it. The
 * harness models that by cancelling after a fixed number of transport calls
 * (cancel polls included)
 * (a deterministic per-input count, reset every input; not a timer), so a
 * long-but-legitimate script does not read as a hang. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "managers/hid_script_parser.h"

#define OPERATOR_STOP_AFTER 100000u
static unsigned g_calls;
static bool send_key(uint8_t m, uint8_t k, void *c) { (void)m; (void)k; (void)c; g_calls++; return true; }
static bool send_string(const char *t, size_t l, void *c) { (void)t; (void)l; (void)c; g_calls++; return true; }
static void delay(uint32_t ms, void *c) { (void)ms; (void)c; g_calls++; }
static bool release(void *c) { (void)c; return true; }
static bool cancelled(void *c) { (void)c; return ++g_calls > OPERATOR_STOP_AFTER; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 16384) return -1;
  char *s = (char *)malloc(size + 1);
  memcpy(s, data, size);
  s[size] = 0;
  hid_transport_t t = { send_key, send_string, delay, release, cancelled, NULL };
  g_calls = 0;
  hid_set_keyboard_layout(0);
  hid_script_execute(s, &t);
  free(s);
  return 0;
}
