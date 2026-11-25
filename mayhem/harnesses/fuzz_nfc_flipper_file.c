/* Saved Flipper .nfc files on the SD card: the DESFire and EMV loaders
 * (desfire_load_flipper_file / emv_load_flipper_file) and the supported-card
 * parsers they feed (flipper_nfc_try_parse_mfdesfire / _emv). The input is the
 * file. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "managers/nfc/flipper_nfc_compat.h"
#include "managers/nfc/desfire.h"
#include "managers/nfc/emv.h"
#include "fuzz_scratch.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char path[640];
  snprintf(path, sizeof path, "%s/card.nfc", fuzz_scratch_dir());
  FILE *f = fopen(path, "wb");
  if (!f) abort();
  fwrite(data, 1, size, f);
  fclose(f);

  desfire_version_t ver;
  bool have_ver = false;
  MfDesfireData *tree = desfire_load_flipper_file(path, &ver, &have_ver);
  if (tree) {
    char *s = flipper_nfc_try_parse_mfdesfire(tree);
    free(s);
    uint8_t uid[7] = {4, 1, 2, 3, 4, 5, 6};
    s = desfire_build_flipper_text(tree, uid, 7, 0x0344, 0x20, have_ver ? &ver : NULL);
    free(s);
    desfire_tree_free(tree);
  }

  EmvData *emv = (EmvData *)calloc(1, sizeof(EmvData));
  uint8_t uid[10], uid_len = 0, sak = 0;
  uint16_t atqa = 0;
  if (emv_load_flipper_file(path, emv, uid, &uid_len, &atqa, &sak)) {
    char *s = flipper_nfc_try_parse_emv(emv);
    free(s);
  }
  free(emv);
  unlink(path);
  return 0;
}
