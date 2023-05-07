#!/usr/bin/env bash

file_scan_result=false
dir_scan_result=true

current_dir=$(pwd)
target_dir=$current_dir/../optee_examples


for node in "$target_dir"/*; do
  if [ -d "$node" ]; then
    echo "[*] Scanning the C Files In Directory: $node/ta"
    header=($(find "$node"/ta -name 'user_ta_header_defines.h'))
    if grep -Eq '#define.*TA_FLAGS.*(TA_FLAG_SINGLE_INSTANCE.*TA_FLAG_MULTI_SESSION|TA_FLAG_MULTI_SESSION.*TA_FLAG_SINGLE_INSTANCE)' "$header"; then
    echo "    [-] TA_FLAGS is TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION"
    files=($(find "$node"/ta -type f \( -name "*.c" -o -name "*.h" \)))
    for file in "${files[@]}"; do
      $target_dir/clang-query "$file" -f $target_dir/conf -- | grep -Psiq "0 matches\." && file_scan_result=true || file_scan_result=false
      echo "    [-] $file: $file_scan_result"
      if [ "$file_scan_result" = false ]; then
        dir_scan_result=false
      fi
    done
    else
    dir_scan_result=true
    echo "    [-] TA_FLAGS is not TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION"
    fi
    if [ "$dir_scan_result" = true ]; then
      echo "    ###### Dir Result: True ######"
    else
      echo "    ###### Dir Result: False ######"
      if [ "$node" != "$target_dir/hpe_victim" ]; then
      	exit 1
      else
      	echo "    ###### hpe_victim can skip the check ######"
      fi
    fi
  fi
  file_scan_result=false
  dir_scan_result=true
done
