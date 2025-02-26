#!/usr/bin/env bash
#
# two_run_sandbower.sh
#
# 1) Determine application name from $1
# 2) Load or create a separate rules.<app>.env in application_conf/ for that application
# 3) First run with those rules
# 4) Parse strace logs for EACCES/EPERM (ignore ENOENT)
# 5) Prompt user to update rules (storing *absolute*, verified paths)
#    - We reject symlinks and paths that don't exist, to avoid malicious expansions
# 6) If needed, do a second run
# 7) Persist changes in that app’s file
#
# Also filters out "No such file or directory (os error 2)" from console output
# and never executes commands outside the sandbox.

########################################
# 0) Determine application name & shift
########################################
if [ $# -lt 1 ]; then
  echo "Usage: $0 <application> [args...]"
  exit 1
fi

APP_CMD="$(basename "$1")"
shift  # Now $@ = application arguments

########################################
# 1) Directory to store rules.*.env files
########################################
RULES_DIR="/home/alexandre/Documents/master_project/rust-landlock-main/application_conf"
mkdir -p "$RULES_DIR"

RULES_FILE="$RULES_DIR/rules.$APP_CMD.env"

########################################
# Load or create a rules file for $APP_CMD
########################################
if [ -f "$RULES_FILE" ]; then
  echo "[DEBUG] Loading existing rules from $RULES_FILE"
  # shellcheck disable=SC1090
  source "$RULES_FILE"
else
  echo "[DEBUG] No existing $RULES_FILE. Using defaults."
  LL_FS_RO="${LL_FS_RO:-/bin:/lib:/usr:/proc:/etc:/dev/urandom}"
  LL_FS_RW="${LL_FS_RW:-/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp}"
  LL_TCP_BIND="${LL_TCP_BIND:-9418}"
  LL_TCP_CONNECT="${LL_TCP_CONNECT:-80:443}"
fi

########################################
# Additional script settings
########################################
SANDBOXER_PATH="/home/alexandre/Documents/master_project/rust-landlock-main/target/release/examples/sandboxer"
LOG_PREFIX="/tmp/sandboxer.log"

########################################
# Helper: run sandbox + strace, filtering
# out "No such file or directory (os error 2)"
########################################
run_sandbox() {
  local label="$1"  # e.g. "first time", "second time"
  shift            # the rest are application args

  rm -f "$LOG_PREFIX".*

  echo "Running sandbox ($label) for app '$APP_CMD'..."
  echo "Perform some commands inside, then exit."

  {
    strace -ff -e trace=all -o "$LOG_PREFIX" \
      "$SANDBOXER_PATH" "$APP_CMD" "$@"
  } 2>&1 | grep -v "No such file or directory (os error 2)"
}

########################################
# 2) First run
########################################
echo "========================================"
echo "FIRST RUN FOR APP: $APP_CMD"
echo "========================================"
echo "Environment Settings:"
echo "  Read-Only Paths: $LL_FS_RO"
echo "  Read-Write Paths: $LL_FS_RW"
echo "  TCP Bind:        ${LL_TCP_BIND}"
echo "  TCP Connect:     ${LL_TCP_CONNECT}"
echo ""

# Export env so strace won't parse them as files
export LL_FS_RO LL_FS_RW LL_TCP_BIND LL_TCP_CONNECT

run_sandbox "first time" "$@"

echo ""
echo "First run completed. Checking for denied operations..."
echo "========================================"

########################################
# 3) Parse logs for EACCES/EPERM, ignoring ENOENT
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

  # We'll parse each line that matched EACCES/EPERM
  while IFS= read -r line; do
    # Extract the raw path in quotes
    raw_path="$(echo "$line" | sed -nE 's/.*"([^"]+)".*/\1/p')"
    [ -z "$raw_path" ] && continue

    ############################################################
    # Convert to absolute path, disallow symlinks & must exist #
    ############################################################
    abs_path="$(realpath -m "$raw_path" 2>/dev/null || true)"
    if [ -z "$abs_path" ]; then
      echo "Could not resolve an absolute path for '$raw_path'; skipping."
      continue
    fi

    # Check if file or directory actually exists
    if [ ! -e "$abs_path" ]; then
      echo "Path '$abs_path' does not exist on the filesystem; skipping."
      continue
    fi

    # Disallow symlinks to avoid malicious expansions
    # You can also skip if test -h or test -L
    if [ -L "$abs_path" ]; then
      echo "Path '$abs_path' is a symlink; skipping for security reasons."
      continue
    fi

    # Already prompted for this absolute path?
    if echo "$PROMPTED_PATHS" | grep -Fqx "$abs_path"; then
      continue
    fi
    PROMPTED_PATHS="$PROMPTED_PATHS
$abs_path"

    # If path is already in LL_FS_RO or LL_FS_RW, skip
    if echo "$LL_FS_RO" | grep -Fq "$abs_path" || echo "$LL_FS_RW" | grep -Fq "$abs_path"; then
      continue
    fi

    echo "Denied path: '$abs_path'"
    echo "Add to [r]ead-only, [w]riteable, or [s]kip?"
    read -r choice < /dev/tty
    case "$choice" in
      [Rr])
        NEW_RO="$NEW_RO:$abs_path"
        ;;
      [Ww])
        NEW_RW="$NEW_RW:$abs_path"
        ;;
      *)
        echo "Skipping '$abs_path'"
        ;;
    esac
  done <<< "$DENIED_LINES"

  # Append newly chosen absolute paths to environment
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
  # 4) Second run if needed
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
# 5) Persist Updated Rules (per-app)
########################################
echo ""
echo "Persisting updated rules to $RULES_FILE ..."
cat <<EOF > "$RULES_FILE"
export LL_FS_RO="$LL_FS_RO"
export LL_FS_RW="$LL_FS_RW"
export LL_TCP_BIND="$LL_TCP_BIND"
export LL_TCP_CONNECT="$LL_TCP_CONNECT"
EOF

echo "Saved. No commands will be executed outside the sandbox."
echo "Done."
