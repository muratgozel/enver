#!/bin/bash

print_help() {
  echo "usage (user ): enver set|get|export|remove project/mode/[key] [value] [...extra]"
  exit 0
}

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

server_ip=188.245.119.40

method="$1"

case "$method" in
  "set"|"get"|"export"|"remove")
    # resolve path-like syntax
    IFS='/' read -ra parts <<< "$2"
    project_id=${parts[0]}
    mode=${parts[1]}
    key=${parts[2]:-""} # defaults to empty string if key doesn't exist

    # setup ssh connection string
    server_user="enver_$project_id"
    ssh_conn_str="$server_user@$server_ip"
    shift 2
    # execute
    result=$(ssh $ssh_conn_str "$method" "$mode" "$key" "$@")

    if [[ "$method" == "export" ]]; then
      save_env_file "$result"
    else
      echo "$result"
    fi
  ;;
  "usage"|"help")
    print_help
    ;;
  *)
    echo "Invalid option: $1"
    print_help
    ;;
esac
