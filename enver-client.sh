#!/bin/bash

server_ip=65.109.167.148

project_id="$1"
server_user="enver_$project_id"
ssh_conn_str="$server_user@$server_ip"
method="$2"
shift 1

result=$(ssh $ssh_conn_str "$@")
echo "$result"
