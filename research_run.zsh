#!/bin/zsh

# Path to your Python script
PY_SCRIPT="./cloud_detect.py"

# Array of domains (one per line for readability)
domains=(
  google.com
  microsoft.com
  github.com
  amazon.com
  openai.com
)

# Loop over array and run the Python script
for d in "${domains[@]}"; do
  echo "🔎 Checking $d ..."
  python3 "$PY_SCRIPT" "$d" "--json" > "${d//./_}.json"
  echo "-----------------------------------"
done