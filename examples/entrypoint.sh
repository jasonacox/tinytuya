#!/bin/bash
#
# jasonacox/tinytuya-cli:latest
#
# TinyTuya entrypoint script for a Docker container
# This script will run the wizard or a scan based on user input
#
# Author: Jason A. Cox
# For more information see https://github.com/jasonacox/tinytuya

# Ask users if they want to run wizard or a scan
read -n 1 -r -p "TinyTuya (w)izard, (s)can or (b)ash shell? [w/s/B] " choice
echo ""
if [[ "$choice" =~ ^([wW])$ ]]; then
  echo "Running the wizard..."
  python -m tinytuya wizard
elif [[ "$choice" =~ ^([sS])$ ]]; then
  echo "Running a scan..."
  python -m tinytuya scan
else
  echo "Running bash shell..."
  /bin/bash
fi

