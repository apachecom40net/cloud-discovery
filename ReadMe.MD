# Requirements

1. Python Env 
1. Optimized for WSL
1. Optimized fror run on zhs instead of bash

# Create a Python environment and activate it

````
python3 -m venv ./vnev && . ./.venv/bin/activate

pip install -r requirements.txt
````

# Execute the command
````
# Update Domain Array

<!-- 
--------------------
domains=(
  google.com
  microsoft.com
  github.com
  amazon.com
  openai.com
)
-------------------- -->

# Execute Command
chmod +x ./research_run.zsh
./research_run.zsh
````