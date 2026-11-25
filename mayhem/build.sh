#!/usr/bin/env bash
#
# mayhem/build.sh — GhostESP is ESP-IDF firmware with no host build. The parsers
# that read untrusted data (pcap capture/export, 802.11 L2, NMEA, Sub-GHz and IR
# decoders, Unishox, Meshtastic protobufs, DuckyScript, MeshCore packets, NFC NDEF/Type 2, MIFARE Classic
# supported-card parsers, saved DESFire/EMV .nfc files) are plain C
# files; they are compiled here for the host against mayhem/stubs, which stands in
# for the ESP-IDF/FreeRTOS/firmware-manager headers they include. mbedtls (SHA-1 for
# the Disney Infinity parser) comes from apt, libmbedtls-dev.
# Outputs (all under the gitignored mayhem/build/):
#   mayhem/build/fuzz_<t>             libFuzzer targets (ASan+UBSan, DWARF 3)
#   mayhem/build/fuzz_<t>-standalone  run-once reproducers
#   mayhem/build/selftest             known-answer suite, normal flags (test.sh)
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
cd "$SRC"

OUT=mayhem/build
mkdir -p "$OUT/obj" "$OUT/obj-test"
INC=(-Imayhem/stubs -Iinclude -Imain -Iinclude/vendor/GPS -Imain/managers)
DEFS=(-DCONFIG_HAS_BADUSB=1 -DCONFIG_HAS_MESHCORE=1 -DCONFIG_HAS_LORA=1)

# The supported-card parsers upstream registers (main/CMakeLists.txt lists the
# same set: all_in_one, sonicare, trt and ventra are not built upstream either).
NFC_PARSERS=$(ls main/managers/nfc/flipper_parsers/*.c | grep -v -e /all_in_one.c -e /sonicare.c -e /trt.c -e /ventra.c)
NFC_COMPAT="main/managers/nfc/flipper_nfc_compat.c $(echo $NFC_PARSERS)"

# name -> project sources it links
declare -A SRCS=(
  [pcap_write]="main/vendor/pcap.c main/vendor/radiotap.c"
  [pcap_hc22000]="main/vendor/pcap.c main/vendor/radiotap.c"
  [wifi_l2]="main/vendor/wifi_l2.c"
  [minmea]="main/vendor/GPS/minmea.c"
  [subghz]="main/managers/subghz_decoders.c"
  [infrared]="main/managers/infrared_decoder.c main/managers/infrared_common.c"
  [unishox]="main/managers/lora_unishox.c"
  [hid_script]="main/managers/hid_script_parser.c"
  [meshcore_packet]="main/managers/meshcore_packet.c"
  [nfc_ndef]="main/managers/nfc/ndef.c main/managers/nfc/ntag_t2.c"
  [lora_pb]="main/managers/lora_pb.c"
  [nfc_mfclassic]="$NFC_COMPAT"
  [nfc_flipper_file]="$NFC_COMPAT main/managers/nfc/desfire.c main/managers/nfc/emv.c"
)

obj() { # obj <dir> <src> -> object path
  local o="$1/$(echo "$2" | tr '/' '_').o"
  echo "$o"
}

# 1) Project sources + stubs, sanitized (the fuzzed code is instrumented).
ALL=$(printf '%s\n' "${SRCS[@]}" | tr ' ' '\n' | sort -u)
for s in $ALL mayhem/stubs/ghost_stubs.c; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${INC[@]}" "${DEFS[@]}" \
    -c "$s" -o "$(obj "$OUT/obj" "$s")"
done
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$OUT/obj/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/obj/standalone_main.o"

# 2) Each harness twice: libFuzzer binary + standalone reproducer.
for t in "${!SRCS[@]}"; do
  objs=("$OUT/obj/lsan_off.o" "$(obj "$OUT/obj" mayhem/stubs/ghost_stubs.c)")
  for s in ${SRCS[$t]}; do objs+=("$(obj "$OUT/obj" "$s")"); done
  h="mayhem/harnesses/fuzz_$t.c"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${INC[@]}" "${DEFS[@]}" \
    "$h" "${objs[@]}" -lmbedcrypto -lm -o "$OUT/fuzz_$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${INC[@]}" "${DEFS[@]}" \
    "$h" "$OUT/obj/standalone_main.o" "${objs[@]}" -lmbedcrypto -lm -o "$OUT/fuzz_$t-standalone"
done

# 3) Known-answer suite with normal flags (no sanitizers) for test.sh.
TSRC="main/vendor/wifi_l2.c main/vendor/pcap.c main/vendor/radiotap.c main/vendor/GPS/minmea.c
      main/managers/hid_script_parser.c main/managers/nfc/ndef.c mayhem/stubs/ghost_stubs.c"
tobjs=()
for s in $TSRC; do
  o="$(obj "$OUT/obj-test" "$s")"
  $CC -O1 -g $COVERAGE_FLAGS "${INC[@]}" "${DEFS[@]}" -c "$s" -o "$o"
  tobjs+=("$o")
done
$CC -O1 -g $COVERAGE_FLAGS "${INC[@]}" "${DEFS[@]}" mayhem/selftest.c "${tobjs[@]}" -lm \
  -o "$OUT/selftest"
