#!/bin/bash -eu

# Install the runtime dependency from GreenGap's hash-locked manifest.  The
# source tree itself stays on PYTHONPATH, so no unpinned local-package pip
# command is needed during the fuzzer build.
pip3 install --require-hashes -r "$SRC/greengap/.github/requirements-runtime.txt"
export PYTHONPATH="$SRC/greengap/src${PYTHONPATH:+:$PYTHONPATH}"

# ClusterFuzzLite discovers executable targets copied into $OUT. PyInstaller
# keeps the target independent from the builder's Python environment.
for fuzzer in $(find "$SRC" -name '*_fuzzer.py'); do
  fuzzer_basename=$(basename -s .py "$fuzzer")
  fuzzer_package="${fuzzer_basename}.pkg"
  pyinstaller --distpath "$OUT" --onefile --name "$fuzzer_package" "$fuzzer"
  printf '%s\n' '#!/bin/sh' \
    'this_dir=$(dirname "$0")' \
    "exec \"\$this_dir/$fuzzer_package\" \"\$@\"" \
    > "$OUT/$fuzzer_basename"
  chmod +x "$OUT/$fuzzer_basename"
done
