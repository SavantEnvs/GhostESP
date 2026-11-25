/* Host implementations of the firmware services the parsers under test call.
 * Console/radio/UI side effects are no-ops; SD access maps onto the host
 * filesystem so pcap.c writes real files that can be read back. */
#include "ghost_stubs.h"
#include <stdarg.h>
#include <sys/stat.h>

static struct ghost_sem g_sems[8];
static int g_sem_next;

SemaphoreHandle_t xSemaphoreCreateMutex(void) {
  for (int i = 0; i < 8; i++) {
    int k = (g_sem_next + i) % 8;
    if (g_sems[k].held < 0 || g_sems[k].held == 0) {
      g_sems[k].held = 0;
      g_sem_next = k + 1;
      return &g_sems[k];
    }
  }
  return &g_sems[0];
}
BaseType_t xSemaphoreTake(SemaphoreHandle_t s, TickType_t t) {
  (void)t;
  if (!s || s->held) return pdFALSE;
  s->held = 1;
  return pdTRUE;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t s) {
  if (!s) return pdFALSE;
  s->held = 0;
  return pdTRUE;
}
void vSemaphoreDelete(SemaphoreHandle_t s) { if (s) s->held = 0; }
void vTaskDelay(TickType_t t) { (void)t; }
void vTaskDelete(TaskHandle_t t) { (void)t; }
void vTaskDeleteWithCaps(TaskHandle_t t) { (void)t; }
BaseType_t xTaskCreate(void (*fn)(void *), const char *name, uint32_t stack, void *arg,
                       UBaseType_t prio, TaskHandle_t *out) {
  (void)fn; (void)name; (void)stack; (void)arg; (void)prio;
  if (out) *out = NULL;
  return pdFALSE; /* no scheduler on the host: background tasks never start */
}
BaseType_t xTaskCreateWithCaps(void (*fn)(void *), const char *name, uint32_t stack, void *arg,
                               UBaseType_t prio, TaskHandle_t *out, uint32_t caps) {
  (void)caps;
  return xTaskCreate(fn, name, stack, arg, prio, out);
}
BaseType_t xTaskCreate_psram(void (*fn)(void *), const char *name, uint32_t stack, void *arg,
                             UBaseType_t prio, TaskHandle_t *out) {
  return xTaskCreate(fn, name, stack, arg, prio, out);
}
TickType_t xTaskGetTickCount(void) { return 0; }

int uart_write_bytes(int port, const void *src, size_t size) { (void)port; (void)src; return (int)size; }
esp_err_t uart_wait_tx_done(int port, TickType_t t) { (void)port; (void)t; return ESP_OK; }

void glog(const char *fmt, ...) { (void)fmt; }
void glog_console_hold(void) {}
void glog_console_release(void) {}
void serial_manager_write_bytes(const void *data, size_t len) { (void)data; (void)len; }

bool sd_card_exists(const char *path) {
  struct stat st;
  return path && stat(path, &st) == 0;
}
bool sd_card_needs_jit_mount(void) { return false; }
esp_err_t sd_card_mount_for_flush(bool *display_was_suspended) {
  if (display_was_suspended) *display_was_suspended = false;
  return ESP_OK;
}
void sd_card_unmount_after_flush(bool display_was_suspended) { (void)display_was_suspended; }
int get_next_file_index(const char *dir, const char *base, const char *ext) {
  (void)dir; (void)base; (void)ext;
  return 0;
}
void toast_show(const char *msg, toast_type_t type) { (void)msg; (void)type; }
void ghostchi_manager_add_xp(int xp) { (void)xp; }
void ghostscript_emit_event(const char *name, const char *payload) { (void)name; (void)payload; }
void ghostscript_emit_event_escaped(const char *name, const char *payload) { (void)name; (void)payload; }
void cleanup_pcap_queue(void) {}
void pcap_reset_queue_drop_stats(void) {}
void pcap_get_queue_drop_stats(uint32_t *too_big, uint32_t *no_slot, uint32_t *queue_full) {
  if (too_big) *too_big = 0;
  if (no_slot) *no_slot = 0;
  if (queue_full) *queue_full = 0;
}

/* meshcore_packet.c references mc_sha256_2 from mc_packet_calculate_hash
 * (meshcore_crypto.c needs mbedtls). Not a real SHA-256: it folds every byte of
 * both spans into the output, so ASan sees an out-of-bounds span. */
void mc_sha256_2(uint8_t *out, size_t out_len, const uint8_t *a, size_t al,
                 const uint8_t *b, size_t bl) {
  memset(out, 0, out_len);
  if (!out_len) return;
  for (size_t i = 0; i < al; i++) out[i % out_len] ^= a[i];
  for (size_t i = 0; i < bl; i++) out[i % out_len] ^= b[i];
}

esp_err_t esp_read_mac(uint8_t *mac, esp_mac_type_t type) {
  static const uint8_t m[6] = {0x24, 0x0a, 0xc4, 0x12, 0x34, 0x56};
  (void)type;
  memcpy(mac, m, 6);
  return ESP_OK;
}
int64_t esp_timer_get_time(void) { return 0; }
