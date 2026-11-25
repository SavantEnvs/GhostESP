/* Host-build stand-ins for the ESP-IDF / FreeRTOS / firmware-manager headers that
 * the parsers under test include. Only what those translation units reference. */
#ifndef GHOST_STUBS_H
#define GHOST_STUBS_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_ERR_NOT_SUPPORTED 0x106
#define ESP_ERR_TIMEOUT 0x107
#define ESP_LOGE(tag, ...) ((void)(tag))
#define ESP_LOGW(tag, ...) ((void)(tag))
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGD(tag, ...) ((void)(tag))
#define ESP_LOGV(tag, ...) ((void)(tag))
#define IRAM_ATTR
#define DRAM_ATTR
#define RTC_DATA_ATTR
#define EXT_RAM_BSS_ATTR
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define MALLOC_CAP_INTERNAL 4
#define MALLOC_CAP_DEFAULT 8
static inline void *heap_caps_malloc(size_t n, uint32_t caps) { (void)caps; return malloc(n); }
static inline void *heap_caps_calloc(size_t c, size_t n, uint32_t caps) { (void)caps; return calloc(c, n); }
static inline void heap_caps_free(void *p) { free(p); }
/* FreeRTOS: single-threaded host, a mutex is a counter. */
typedef uint32_t TickType_t;
typedef int BaseType_t;
typedef unsigned UBaseType_t;
typedef void *TaskHandle_t;
typedef struct ghost_sem { int held; } *SemaphoreHandle_t;
#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY 0xffffffffu
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
#define portTICK_PERIOD_MS 1
SemaphoreHandle_t xSemaphoreCreateMutex(void);
BaseType_t xSemaphoreTake(SemaphoreHandle_t s, TickType_t t);
BaseType_t xSemaphoreGive(SemaphoreHandle_t s);
void vSemaphoreDelete(SemaphoreHandle_t s);
void vTaskDelay(TickType_t t);
void vTaskDelete(TaskHandle_t t);
void vTaskDeleteWithCaps(TaskHandle_t t);
BaseType_t xTaskCreate(void (*fn)(void *), const char *name, uint32_t stack, void *arg,
                       UBaseType_t prio, TaskHandle_t *out);
BaseType_t xTaskCreateWithCaps(void (*fn)(void *), const char *name, uint32_t stack, void *arg,
                               UBaseType_t prio, TaskHandle_t *out, uint32_t caps);
TickType_t xTaskGetTickCount(void);
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define taskENTER_CRITICAL(m) ((void)(m))
#define taskEXIT_CRITICAL(m) ((void)(m))
BaseType_t xTaskCreate_psram(void (*fn)(void *), const char *name, uint32_t stack, void *arg,
                             UBaseType_t prio, TaskHandle_t *out);
void pcap_get_queue_drop_stats(uint32_t *too_big, uint32_t *no_slot, uint32_t *queue_full);
typedef enum { ESP_MAC_WIFI_STA, ESP_MAC_WIFI_SOFTAP, ESP_MAC_BT, ESP_MAC_ETH } esp_mac_type_t;
esp_err_t esp_read_mac(uint8_t *mac, esp_mac_type_t type);
int64_t esp_timer_get_time(void);
/* UART */
#define UART_NUM_0 0
int uart_write_bytes(int port, const void *src, size_t size);
esp_err_t uart_wait_tx_done(int port, TickType_t t);
/* firmware managers */
#define SD_DIR_PCAPS "/tmp"
void glog(const char *fmt, ...);
void glog_console_hold(void);
void glog_console_release(void);
void serial_manager_write_bytes(const void *data, size_t len);
bool sd_card_exists(const char *path);
bool sd_card_needs_jit_mount(void);
esp_err_t sd_card_mount_for_flush(bool *display_was_suspended);
void sd_card_unmount_after_flush(bool display_was_suspended);
int get_next_file_index(const char *dir, const char *base, const char *ext);
typedef enum { TOAST_INFO, TOAST_SUCCESS, TOAST_WARNING, TOAST_ERROR } toast_type_t;
void toast_show(const char *msg, toast_type_t type);
void ghostchi_manager_add_xp(int xp);
void ghostscript_emit_event(const char *name, const char *payload);
void ghostscript_emit_event_escaped(const char *name, const char *payload);
void cleanup_pcap_queue(void);
void pcap_reset_queue_drop_stats(void);
#ifdef __cplusplus
}
#endif
#endif
