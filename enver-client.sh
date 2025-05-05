#!/bin/bash

save_env_file() {
  local output="$1"

  # Check if output starts with "Error:"
  if [[ "$output" == Error:* ]]; then
    echo "$output"
    return 1
  fi

  # Read the first line as filename
  local filename=$(echo "$output" | head -n 1)

  # Extract the content (all lines except the first)
  local content=$(echo "$output" | tail -n +2)

  # Check if we have a filename and content
  if [[ -z "$filename" || -z "$content" ]]; then
    echo "Failed to read filename and env content. The output was $output"
    return 1
  fi

  # Save content to file
  echo "$content" > "$filename"
  echo "Secrets has been saved successfully into your disk as $filename"
  return 0
}

server_ip=65.109.167.148

project_id="$1"
server_user="enver_$project_id"
ssh_conn_str="$server_user@$server_ip"
method="$2"
shift 1

result=$(ssh $ssh_conn_str "$@")

if [[ "$method" == "export" ]]; then
  save_env_file "$result"
else
  echo "$result"
fi
