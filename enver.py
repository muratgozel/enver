#!/usr/bin/env python3
import os
import sys
import json
import argparse
import subprocess
import logging
import redis
import datetime
import re
import pwd
import grp
import base64
import clickhouse_connect
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

load_dotenv()

if os.environ.get('REDIS_PORT') is None or os.environ.get('CLICKHOUSE_PORT') is None:
    raise RuntimeError('Missing environment variables.')

os.makedirs("/var/log/enver", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("/var/log/enver/enver.log"), logging.StreamHandler()],
)
logger = logging.getLogger("enver")

# Constants
ENVER_GROUP = "enver"
ENVER_USER_PREFIX = "enver_"
ENVER_HOME_BASE = "/home/enver"
DEFAULT_MODES = ["development", "test", "production"]
ENV_FILE_TEMPLATE = ".env.{mode}"
REDIS_HOST = os.environ.get('REDIS_HOST')
REDIS_PORT = int(os.environ.get('REDIS_PORT'))
REDIS_DB = 0
CLICKHOUSE_HOST = os.environ.get('CLICKHOUSE_HOST')
CLICKHOUSE_PORT = int(os.environ.get('CLICKHOUSE_PORT'))
CLICKHOUSE_USER = os.environ.get('CLICKHOUSE_USER')
CLICKHOUSE_PASSWORD = ""
CLICKHOUSE_DATABASE = os.environ.get('CLICKHOUSE_DB')


# Redis connection
def get_redis_connection():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)


# ClickHouse connection
def get_clickhouse_connection():
    return clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        # create database in advance
        database=CLICKHOUSE_DATABASE,
    )


# Initialize ClickHouse tables
def init_clickhouse():
    client = get_clickhouse_connection()

    # Create logs table
    client.command(
        f"""
                   CREATE TABLE IF NOT EXISTS logs
                   (
                       Timestamp Datetime64(9) CODEC(Delta(8), ZSTD(1)),
                       UserId LowCardinality(String) CODEC(ZSTD(1)),
                       ProjectId LowCardinality(String) CODEC(ZSTD(1)),
                       Mode LowCardinality(String) CODEC(ZSTD(1)),
                       Action LowCardinality(String) CODEC(ZSTD(1)),
                       SecretKey LowCardinality(String) CODEC(ZSTD(1)),
                       Status LowCardinality(String) CODEC(ZSTD(1)),
                       IpAddress LowCardinality(String) CODEC(ZSTD(1)),
                       Details LowCardinality(Nullable(String)) CODEC(ZSTD(1))
                   ) ENGINE = MergeTree
                   (
                   )
                       ORDER BY
                   (
                       Timestamp,
                       ProjectId,
                       UserId
                   )
                   """
    )


# Log action to ClickHouse
def log_action(
    user_id, project_id, mode, action, secret_key, status, ip_address, details=""
):
    try:
        client = get_clickhouse_connection()
        client.insert(table='logs', data=[[
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            user_id,
            project_id,
            mode,
            action,
            secret_key,
            status,
            ip_address,
            details
        ]], column_names=[
            'Timestamp',
            'UserId',
            'ProjectId',
            'Mode',
            'Action',
            'SecretKey',
            'Status',
            'IpAddress',
            'Details',
        ])
    except Exception as e:
        logger.error(f"Failed to log action: {e}")


# Generate encryption key for project/mode combination
def generate_encryption_key(project_id, mode, salt=None):
    if not salt:
        salt = os.urandom(16)

    # Use project_id and mode to derive a key
    key_material = f"{project_id}:{mode}".encode()

    # Key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(key_material))
    return key, salt


# Get Fernet encryption object for a project/mode
def get_fernet(project_id, mode):
    redis_conn = get_redis_connection()
    salt_key = f"enver:salt:{project_id}:{mode}"

    # Get or create salt
    salt = redis_conn.get(salt_key)
    if not salt:
        _, salt = generate_encryption_key(project_id, mode)
        redis_conn.set(salt_key, salt)

    key, _ = generate_encryption_key(project_id, mode, salt)
    return Fernet(key)


# Encrypt a value
def encrypt_value(value, project_id, mode):
    fernet = get_fernet(project_id, mode)
    return fernet.encrypt(value.encode()).decode()


# Decrypt a value
def decrypt_value(encrypted_value, project_id, mode):
    fernet = get_fernet(project_id, mode)
    return fernet.decrypt(encrypted_value.encode()).decode()


# Create OS group if not exists
def ensure_group_exists():
    try:
        grp.getgrnam(ENVER_GROUP)
        logger.info(f"Group {ENVER_GROUP} already exists")
    except KeyError:
        subprocess.run(["groupadd", ENVER_GROUP], check=True)
        logger.info(f"Created group {ENVER_GROUP}")


# Create OS user for a project
def create_project_user(project_id):
    username = f"{ENVER_USER_PREFIX}{project_id}"
    home_dir = f"{ENVER_HOME_BASE}/{project_id}"

    try:
        pwd.getpwnam(username)
        logger.info(f"User {username} already exists")
    except KeyError:
        # Create home directory if it doesn't exist
        os.makedirs(home_dir, exist_ok=True)

        # Create user
        subprocess.run(
            [
                "useradd",
                "-g",
                ENVER_GROUP,
                "-d",
                home_dir,
                "-m",
                "-s",
                "/bin/bash",
                username,
            ],
            check=True,
        )

        # Set proper permissions
        os.chmod(home_dir, 0o750)

        # Create SSH directory
        ssh_dir = f"{home_dir}/.ssh"
        os.makedirs(ssh_dir, exist_ok=True)

        # Create authorized_keys file
        with open(f"{ssh_dir}/authorized_keys", "w") as f:
            pass

        # Set proper permissions
        os.chmod(ssh_dir, 0o700)
        os.chmod(f"{ssh_dir}/authorized_keys", 0o600)

        # Change ownership
        subprocess.run(
            ["chown", "-R", f"{username}:{ENVER_GROUP}", home_dir], check=True
        )

        logger.info(f"Created user {username} with home directory {home_dir}")

    return username, home_dir


# Add developer's SSH key to project
def add_developer_to_project(project_id, developer_id, public_key, modes=None):
    if not modes:
        modes = ["development"]

    # Get project user
    username = f"{ENVER_USER_PREFIX}{project_id}"

    try:
        pwd.getpwnam(username)
    except KeyError:
        logger.error(f"Project user {username} does not exist")
        return False

    # Update Redis with developer access
    redis_conn = get_redis_connection()
    dev_key = f"enver:developers:{project_id}:{developer_id}"

    # Store developer info
    redis_conn.hset(dev_key, "public_key", public_key)
    redis_conn.hset(dev_key, "modes", json.dumps(modes))

    # Update authorized_keys file
    home_dir = f"{ENVER_HOME_BASE}/{project_id}"
    auth_keys_file = f"{home_dir}/.ssh/authorized_keys"

    # Command restriction: Only allow enver-client to be executed
    command_restriction = f'command="/usr/local/bin/enver-ssh-wrapper {developer_id} {project_id}",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty {public_key}'

    with open(auth_keys_file, "a") as f:
        f.write(f"{command_restriction}\n")

    logger.info(
        f"Added developer {developer_id} to project {project_id} with modes: {modes}"
    )
    return True


# Check if developer has access to the specified mode
def check_developer_access(project_id, developer_id, mode):
    redis_conn = get_redis_connection()
    dev_key = f"enver:developers:{project_id}:{developer_id}"

    if not redis_conn.exists(dev_key):
        return False

    modes_json = redis_conn.hget(dev_key, "modes")
    if not modes_json:
        return False

    modes = json.loads(modes_json)
    return mode in modes


# Set a secret
def set_secret(project_id, mode, key, value, user_id, ip_address):
    # Check developer access
    if not check_developer_access(project_id, user_id, mode):
        logger.warning(
            f"Access denied: {user_id} tried to set {key} for {project_id}/{mode}"
        )
        log_action(user_id, project_id, mode, "set", key, "denied", ip_address)
        return False

    # Encrypt the value
    encrypted_value = encrypt_value(value, project_id, mode)

    # Store in Redis
    redis_conn = get_redis_connection()
    secret_key = f"enver:secrets:{project_id}:{mode}:{key}"
    redis_conn.set(secret_key, encrypted_value)

    # Log the action
    log_action(user_id, project_id, mode, "set", key, "success", ip_address)

    return True


# Get a secret
def get_secret(project_id, mode, key, user_id, ip_address):
    # Check developer access
    if not check_developer_access(project_id, user_id, mode):
        logger.warning(
            f"Access denied: {user_id} tried to get {key} for {project_id}/{mode}"
        )
        log_action(user_id, project_id, mode, "get", key, "denied", ip_address)
        return None

    # Get from Redis
    redis_conn = get_redis_connection()
    secret_key = f"enver:secrets:{project_id}:{mode}:{key}"
    encrypted_value = redis_conn.get(secret_key)

    if not encrypted_value:
        log_action(user_id, project_id, mode, "get", key, "not_found", ip_address)
        return None

    # Decrypt and return
    decrypted_value = decrypt_value(encrypted_value.decode(), project_id, mode)

    # Log the action
    log_action(user_id, project_id, mode, "get", key, "success", ip_address)

    return decrypted_value


# List all secrets for a project/mode
def list_secrets(project_id, mode, user_id, ip_address):
    # Check developer access
    if not check_developer_access(project_id, user_id, mode):
        logger.warning(
            f"Access denied: {user_id} tried to list secrets for {project_id}/{mode}"
        )
        log_action(user_id, project_id, mode, "list", "*", "denied", ip_address)
        return {}

    # Get from Redis
    redis_conn = get_redis_connection()
    prefix = f"enver:secrets:{project_id}:{mode}:"

    # Find all keys with this prefix
    all_keys = []
    cursor = 0
    while True:
        cursor, keys = redis_conn.scan(cursor, f"{prefix}*", 100)
        all_keys.extend([k.decode() for k in keys])
        if cursor == 0:
            break

    # Get and decrypt values
    secrets = {}
    for full_key in all_keys:
        key = full_key.replace(prefix, "")
        encrypted_value = redis_conn.get(full_key)
        if encrypted_value:
            secrets[key] = decrypt_value(encrypted_value.decode(), project_id, mode)

    # Log the action
    log_action(user_id, project_id, mode, "list", "*", "success", ip_address)

    return secrets


# Resolve references in a secret value
def resolve_references(value, secrets):
    ref_pattern = r"\${([A-Za-z0-9_]+)}"

    def replace_ref(match):
        ref_key = match.group(1)
        if ref_key in secrets:
            return secrets[ref_key]
        return match.group(0)

    resolved = re.sub(ref_pattern, replace_ref, value)

    # Check if we need to resolve nested references
    if "${" in resolved:
        return resolve_references(resolved, secrets)

    return resolved


# Export secrets to env file
def export_secrets(project_id, mode, user_id, ip_address):
    # Get all secrets
    secrets = list_secrets(project_id, mode, user_id, ip_address)
    if not secrets:
        return False, "No secrets found or access denied"

    # Resolve references
    resolved_secrets = {}
    for key, value in secrets.items():
        resolved_secrets[key] = resolve_references(value, secrets)

    # Format env file
    env_content = ""
    for key, value in resolved_secrets.items():
        # Escape special characters for POSIX compliance
        escaped_value = value.replace("'", "'\\''")
        env_content += f"{key}='{escaped_value}'\n"

    # Generate filename
    filename = ENV_FILE_TEMPLATE.format(mode=mode)

    # Log the action
    log_action(user_id, project_id, mode, "export", "*", "success", ip_address)

    return True, (filename, env_content)


# Create a new project
def create_project(project_id, modes=None):
    if not project_id.isalnum():
        return False, "Project ID must be alphanumeric"

    if not modes:
        modes = DEFAULT_MODES

    # Ensure enver group exists
    ensure_group_exists()

    # Create OS user for project
    username, home_dir = create_project_user(project_id)

    # Initialize encryption keys for each mode
    redis_conn = get_redis_connection()
    for mode in modes:
        # Generate and store salt
        _, salt = generate_encryption_key(project_id, mode)
        salt_key = f"enver:salt:{project_id}:{mode}"
        redis_conn.set(salt_key, salt)

    # Store project info
    project_key = f"enver:projects:{project_id}"
    redis_conn.hset(project_key, "modes", json.dumps(modes))
    redis_conn.hset(project_key, "created_at", datetime.datetime.now().isoformat())

    logger.info(f"Created project {project_id} with modes: {modes}")
    return True, f"Project {project_id} created successfully with modes: {modes}"


# Add new mode to project
def add_project_mode(project_id, mode):
    redis_conn = get_redis_connection()
    project_key = f"enver:projects:{project_id}"

    if not redis_conn.exists(project_key):
        return False, f"Project {project_id} does not exist"

    # Get current modes
    modes_json = redis_conn.hget(project_key, "modes")
    if not modes_json:
        modes = DEFAULT_MODES
    else:
        modes = json.loads(modes_json.decode())

    # Check if mode already exists
    if mode in modes:
        return False, f"Mode {mode} already exists for project {project_id}"

    # Add new mode
    modes.append(mode)
    redis_conn.hset(project_key, "modes", json.dumps(modes))

    # Initialize encryption key for the new mode
    _, salt = generate_encryption_key(project_id, mode)
    salt_key = f"enver:salt:{project_id}:{mode}"
    redis_conn.set(salt_key, salt)

    logger.info(f"Added mode {mode} to project {project_id}")
    return True, f"Mode {mode} added to project {project_id}"


def get_client_ip():
    return os.environ.get('SSH_CLIENT', '').split(' ')[0] if 'SSH_CLIENT' in os.environ else 'unknown'


# Main function to parse CLI arguments
def main():
    parser = argparse.ArgumentParser(prog="Enver", description="Secret manager", epilog="")
    parser.add_argument('--developer-id', help="The id of the developer who is executing a non-admin command.")
    parser.add_argument('--project-id', help="The id of the project.")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create project command
    create_parser = subparsers.add_parser("create-project", help="Create a new project")
    create_parser.add_argument("project_id", help="Project identifier (alphanumeric)")
    create_parser.add_argument(
        "--modes",
        nargs="+",
        help="List of modes (default: development, test, production)",
    )

    # Add mode command
    mode_parser = subparsers.add_parser("add-mode", help="Add a new mode to a project")
    mode_parser.add_argument("project_id", help="Project identifier")
    mode_parser.add_argument("mode", help="Mode name")

    # Add developer command
    dev_parser = subparsers.add_parser(
        "add-developer", help="Add a developer to a project"
    )
    dev_parser.add_argument("project_id", help="Project identifier")
    dev_parser.add_argument("developer_id", help="Developer identifier")
    dev_parser.add_argument(
        "--public-key-file", required=True, help="Path to developer's public SSH key"
    )
    dev_parser.add_argument(
        "--modes",
        nargs="+",
        help="List of modes the developer can access (default: development)",
    )

    # Set secret command
    set_parser = subparsers.add_parser("set", help="Set a secret")
    set_parser.add_argument("mode", help="Mode (development, test, production, etc.)")
    set_parser.add_argument("key", help="Key")
    set_parser.add_argument("value", help="Value")

    # Get secret command
    get_parser = subparsers.add_parser("get", help="Get a secret")
    get_parser.add_argument("mode", help="Mode (development, test, production, etc.)")
    get_parser.add_argument("key", help="Key")

    # Export secrets command
    export_parser = subparsers.add_parser("export", help="Export secrets to a .env file")
    export_parser.add_argument("mode", help="Environment mode (development, test, production, etc.)")
    export_parser.add_argument("--output", help="Output filename (default: .env.<mode>)")

    # Initialize command
    init_parser = subparsers.add_parser("init", help="Initialize Enver system")

    args = parser.parse_args()

    if args.command == "create-project":
        success, message = create_project(args.project_id, args.modes)
        if success:
            print(message)
        else:
            print(f"Error: {message}")
            sys.exit(1)

    elif args.command == "add-mode":
        success, message = add_project_mode(args.project_id, args.mode)
        if success:
            print(message)
        else:
            print(f"Error: {message}")
            sys.exit(1)

    elif args.command == "add-developer":
        try:
            with open(args.public_key_file, "r") as f:
                public_key = f.read().strip()

            if add_developer_to_project(
                args.project_id, args.developer_id, public_key, args.modes
            ):
                print(
                    f"Developer {args.developer_id} added to project {args.project_id}"
                )
            else:
                print(f"Failed to add developer {args.developer_id}")
                sys.exit(1)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "init":
        ensure_group_exists()
        os.makedirs(ENVER_HOME_BASE, exist_ok=True)
        os.makedirs("/var/log/enver", exist_ok=True)
        init_clickhouse()
        print("Enver system initialized")

    elif args.command == "set":
        set_secret(args.project_id, args.mode, args.key, args.value, args.developer_id, get_client_ip())
        print("Secret has been saved successfully.")

    elif args.command == "get":
        result = get_secret(args.project_id, args.mode, args.key, args.developer_id, get_client_ip())
        print(f"{result}")

    elif args.command == "export":
        success, result = export_secrets(args.project_id, args.mode, args.developer_id, get_client_ip())
        if success:
            print(result[0])
            print(result[1])
        else:
            print(f"Error: {result}")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
