#!/bin/sh
# Linker wrapper for Rust cdylib builds under musl
# Replaces -lgcc_s (dynamic) with libgcc.a (static)
# Prevents DT_NEEDED(libgcc_s.so.1) in output .so files

LIBGCC_A=""
for candidate in /usr/lib/gcc/*/*/libgcc.a; do
  if [ -f "$candidate" ]; then
    LIBGCC_A="$candidate"
    break
  fi
done
if [ -z "$LIBGCC_A" ]; then
  LIBGCC_A="$(cc --print-libgcc-file-name 2>/dev/null)"
fi

# Write modified args to response file to avoid shell parsing issues
RESP_FILE="$(mktemp /tmp/ld-args.XXXXXX)"
> "$RESP_FILE"
for arg in "$@"; do
  case "$arg" in
    -lgcc_s)
      printf '%s\n' "-Wl,-Bstatic" >> "$RESP_FILE"
      printf '%s\n' "$LIBGCC_A" >> "$RESP_FILE"
      printf '%s\n' "-Wl,-Bdynamic" >> "$RESP_FILE"
      ;;
    *)
      printf '%s\n' "$arg" >> "$RESP_FILE"
      ;;
  esac
done

exec cc "@${RESP_FILE}"
