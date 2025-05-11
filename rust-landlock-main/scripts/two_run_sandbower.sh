#!/usr/bin/env bash
#
# two_run_sandboxer.sh
#
# 1) Loads & updates "app_policy" in PostgreSQL (with updated_at)
# 2) Logs to "sandbox_events" each denied operation and user’s choice
# 3) Captures the actual syscall name (e.g. openat) for the operation column
# 4) Uses exact path checks, preventing partial substring matches

########################################
# 0) Check arguments
########################################
if [ $# -lt 1 ]; then
  echo "Usage: $0 <application> [args...]"
  exit 1
fi

APP_CMD="$(basename "$1")"
shift  # The rest are the app's args

########################################
# Postgres Credentials
########################################
PGHOST="127.0.0.1"
PGPORT="5432"
PGUSER="sandboxuser"
PGDATABASE="sandboxdb"
PGPASSWORD="supernanny"

########################################
# 1) Load DB rules (if exist)
########################################
echo "[DEBUG] Checking Postgres for default rules for '$APP_CMD'..."

DB_RESULT="$(
  PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" \
    -U "$PGUSER" -d "$PGDATABASE" -w -A -t <<EOF
SELECT default_ro || '|' || default_rw || '|' || tcp_bind || '|' || tcp_connect
FROM app_policy
WHERE app_name = '$APP_CMD';
EOF
)"

if [ -n "$DB_RESULT" ]; then
  IFS='|' read -r LL_FS_RO LL_FS_RW LL_TCP_BIND LL_TCP_CONNECT <<< "$DB_RESULT"
  echo "[DEBUG] Found DB rules for $APP_CMD:"
  echo "       RO=$LL_FS_RO"
  echo "       RW=$LL_FS_RW"
  echo "       BIND=$LL_TCP_BIND"
  echo "       CONNECT=$LL_TCP_CONNECT"
else
  echo "[DEBUG] No DB entry for $APP_CMD. Using fallback defaults."
  LL_FS_RO="/bin:/lib:/usr:/proc:/etc:/dev/urandom"
  LL_FS_RW="/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp"
  LL_TCP_BIND="9418"
  LL_TCP_CONNECT="80:443"
fi

########################################
# 2) Additional settings
########################################
SANDBOXER_PATH="/home/alexandre/Documents/master_project/rust-landlock-main/target/release/examples/sandboxer"
LOG_PREFIX="/tmp/sandboxer.log"

########################################
# Helper function: exact path check
########################################
already_in_ro_or_rw() {
  local path_to_check="$1"

  # Check LL_FS_RO
  IFS=':' read -ra ro_array <<< "$LL_FS_RO"
  for p in "${ro_array[@]}"; do
    if [ "$p" = "$path_to_check" ]; then
      return 0
    fi
  done

  # Check LL_FS_RW
  IFS=':' read -ra rw_array <<< "$LL_FS_RW"
  for p in "${rw_array[@]}"; do
    if [ "$p" = "$path_to_check" ]; then
      return 0
    fi
  done

  return 1
}

########################################
# Helper: run sandbox + strace
########################################
run_sandbox() {
  local label="$1"
  shift

  rm -f "$LOG_PREFIX".*

  echo "Running sandbox ($label) for app '$APP_CMD'..."
  echo "Perform some commands inside, then exit."

  {
    strace -ff -e trace=all -o "$LOG_PREFIX" \
      "$SANDBOXER_PATH" "$APP_CMD" "$@"
  } 2>&1 | grep -v "No such file or directory (os error 2)"
}

########################################
# 3) First run
########################################
echo "========================================"
echo "FIRST RUN FOR APP: $APP_CMD"
echo "========================================"
echo "Environment Settings:"
echo "  Read-Only Paths: $LL_FS_RO"
echo "  Read-Write Paths: $LL_FS_RW"
echo "  TCP Bind:        $LL_TCP_BIND"
echo "  TCP Connect:     $LL_TCP_CONNECT"
echo ""

export LL_FS_RO LL_FS_RW LL_TCP_BIND LL_TCP_CONNECT
run_sandbox "first time" "$@"

echo ""
echo "First run completed. Checking for denied operations..."
echo "========================================"

########################################
# 4) Parse logs for EACCES/EPERM
########################################
DENIED_LINES="$(
  grep -EH ' = -[0-9]+ (EACCES|EPERM)' "$LOG_PREFIX".* 2>/dev/null \
    | grep -v ' = -2 ENOENT' \
    | grep -v '(No such file or directory)'
)"

if [ -z "$DENIED_LINES" ]; then
  echo "No denied operations found in the first run."
  echo "No second run needed."
else
  echo "Denied operations found. Updating rules..."

  NEW_RO=""
  NEW_RW=""
  PROMPTED_PATHS=""

  while IFS= read -r line; do
    # Extract the raw path from quotes
    raw_path="$(echo "$line" | sed -nE 's/.*"([^"]+)".*/\1/p')"
    [ -z "$raw_path" ] && continue

    # Convert to absolute
    abs_path="$(realpath -m "$raw_path" 2>/dev/null || true)"
    if [ -z "$abs_path" ]; then
      echo "Could not resolve an absolute path for '$raw_path'; skipping."
      continue
    fi
    if [ ! -e "$abs_path" ]; then
      echo "Path '$abs_path' does not exist; skipping."
      continue
    fi
    if [ -L "$abs_path" ]; then
      echo "Path '$abs_path' is a symlink; skipping for security reasons."
      continue
    fi

    # Extract the syscall name
    current_operation="$(echo "$line" \
      | sed -E 's/^.*://; s/\(.*$//; s/\s+$//')"
    [ -z "$current_operation" ] && current_operation="unknown"

    # Insert "denied" event
    PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" \
      -U "$PGUSER" -d "$PGDATABASE" -w <<EOF
INSERT INTO sandbox_events (hostname, app_name, denied_path, operation, result)
VALUES ('$(hostname)', '$APP_CMD', '$abs_path', '$current_operation', 'denied');
EOF

    # Check if user was already asked
    if echo "$PROMPTED_PATHS" | grep -Fqx "$abs_path"; then
      continue
    fi
    PROMPTED_PATHS="$PROMPTED_PATHS
$abs_path"

    # If path is truly in LL_FS_RO or LL_FS_RW, skip
    if already_in_ro_or_rw "$abs_path"; then
      continue
    fi

    # Prompt user
    echo "Denied path: '$abs_path'"
    echo "Add to [r]ead-only, [w]riteable, or skip [s]?"
    read -r choice < /dev/tty
    case "$choice" in
      [Rr])
        NEW_RO="$NEW_RO:$abs_path"
        # Insert a "granted_ro" event reusing same operation
        PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" \
          -U "$PGUSER" -d "$PGDATABASE" -w <<EOF
INSERT INTO sandbox_events (hostname, app_name, denied_path, operation, result)
VALUES ('$(hostname)', '$APP_CMD', '$abs_path', '$current_operation', 'granted_ro');
EOF
        ;;
      [Ww])
        NEW_RW="$NEW_RW:$abs_path"
        # Insert a "granted_rw" event
        PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" \
          -U "$PGUSER" -d "$PGDATABASE" -w <<EOF
INSERT INTO sandbox_events (hostname, app_name, denied_path, operation, result)
VALUES ('$(hostname)', '$APP_CMD', '$abs_path', '$current_operation', 'granted_rw');
EOF
        ;;
      *)
        echo "Skipping '$abs_path'"
        # Insert a "skipped" event
        PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" \
          -U "$PGUSER" -d "$PGDATABASE" -w <<EOF
INSERT INTO sandbox_events (hostname, app_name, denied_path, operation, result)
VALUES ('$(hostname)', '$APP_CMD', '$abs_path', '$current_operation', 'skipped');
EOF
        ;;
    esac
  done <<< "$DENIED_LINES"

  if [ -n "$NEW_RO" ]; then
    LL_FS_RO="$LL_FS_RO$NEW_RO"
  fi
  if [ -n "$NEW_RW" ]; then
    LL_FS_RW="$LL_FS_RW$NEW_RW"
  fi

  echo ""
  echo "Updated Environment for $APP_CMD:"
  echo "  Read-Only: $LL_FS_RO"
  echo "  Read-Write: $LL_FS_RW"
  echo "========================================"

  ########################################
  # 5) Second run
  ########################################
  echo "SECOND RUN FOR APP: $APP_CMD"
  echo "========================================"

  export LL_FS_RO LL_FS_RW LL_TCP_BIND LL_TCP_CONNECT
  run_sandbox "second time" "$@"

  echo ""
  echo "Second run completed. Checking for denied operations..."
  echo "========================================"

  DENIED_LINES_SECOND="$(
    grep -EH ' = -[0-9]+ (EACCES|EPERM)' "$LOG_PREFIX".* 2>/dev/null \
      | grep -v ' = -2 ENOENT' \
      | grep -v '(No such file or directory)'
  )"

  if [ -z "$DENIED_LINES_SECOND" ]; then
    echo "No denied operations found in the second run."
  else
    echo "Denied operations still detected in the second run."
    echo "You may need further updates if you want those paths allowed."
  fi
fi

########################################
# 6) Persist Updated Rules BACK to Postgres
########################################
echo ""
echo "Updating rules in Postgres for '$APP_CMD'..."

SQL="
INSERT INTO app_policy (app_name, default_ro, default_rw, tcp_bind, tcp_connect, updated_at)
VALUES ('$APP_CMD', '$LL_FS_RO', '$LL_FS_RW', '$LL_TCP_BIND', '$LL_TCP_CONNECT', NOW())
ON CONFLICT (app_name)
DO UPDATE SET
  default_ro = EXCLUDED.default_ro,
  default_rw = EXCLUDED.default_rw,
  tcp_bind   = EXCLUDED.tcp_bind,
  tcp_connect= EXCLUDED.tcp_connect,
  updated_at = NOW();
"

PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" \
  -U "$PGUSER" -d "$PGDATABASE" -w <<EOF
$SQL
EOF

echo "Rules for '$APP_CMD' have been saved/updated in the DB."
echo "Done."
