/* NMEA sentences from the GPS UART (minmea.c). */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "vendor/GPS/minmea.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *s = (char *)malloc(size + 1);
  memcpy(s, data, size);
  s[size] = 0;
  for (int strict = 0; strict < 2; strict++) {
    switch (minmea_sentence_id(s, strict)) {
    case MINMEA_SENTENCE_GBS: { struct minmea_sentence_gbs f; minmea_parse_gbs(&f, s); break; }
    case MINMEA_SENTENCE_RMC: { struct minmea_sentence_rmc f; minmea_parse_rmc(&f, s); break; }
    case MINMEA_SENTENCE_GGA: { struct minmea_sentence_gga f; minmea_parse_gga(&f, s); break; }
    case MINMEA_SENTENCE_GSA: { struct minmea_sentence_gsa f; minmea_parse_gsa(&f, s); break; }
    case MINMEA_SENTENCE_GLL: { struct minmea_sentence_gll f; minmea_parse_gll(&f, s); break; }
    case MINMEA_SENTENCE_GST: { struct minmea_sentence_gst f; minmea_parse_gst(&f, s); break; }
    case MINMEA_SENTENCE_GSV: { struct minmea_sentence_gsv f; minmea_parse_gsv(&f, s); break; }
    case MINMEA_SENTENCE_VTG: { struct minmea_sentence_vtg f; minmea_parse_vtg(&f, s); break; }
    case MINMEA_SENTENCE_ZDA: { struct minmea_sentence_zda f; minmea_parse_zda(&f, s); break; }
    default: break;
    }
  }
  free(s);
  return 0;
}
