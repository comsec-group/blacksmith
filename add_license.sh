#!/bin/bash

prepend_license_info() {
  for file in include/**/*.hpp; do
    echo "Processing $file..."
    # check whether "MIT License" is already present in file
    grep -q "MIT License" "$file"
    if [ $? -ne 0 ]; then
      # if string is not present, append license information to file
      cat LICENSE_HEADER "$file" >tempfile && mv tempfile $file
    fi
  done
}

remove_license_info() {
  for file in include/**/*.hpp; do
    echo "Processing $file..."
    # check whether "MIT License" is already present in file
    grep -q "MIT License" "$file"
    if [ $? -eq 0 ]; then
      sed -e '1,5d' <"$file" >tempfile && mv tempfile "$file"
    fi
  done
}

# enable calling the script's functions from terminal, e.g.:
#   ./add_license.sh prepend_license_info
"$@"
