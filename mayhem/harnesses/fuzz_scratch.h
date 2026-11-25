/* Per-process scratch directory under $TMPDIR (Mayhem runs targets with a
 * writable /tmp; the image dir is read-only). */
#ifndef FUZZ_SCRATCH_H
#define FUZZ_SCRATCH_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char g_scratch[512];
static const char *fuzz_scratch_dir(void) {
  if (!g_scratch[0]) {
    const char *t = getenv("TMPDIR");
    if (!t || !*t) t = "/tmp";
    snprintf(g_scratch, sizeof g_scratch, "%s/ghostesp-fuzz-XXXXXX", t);
    if (!mkdtemp(g_scratch)) abort();
  }
  return g_scratch;
}
#endif
