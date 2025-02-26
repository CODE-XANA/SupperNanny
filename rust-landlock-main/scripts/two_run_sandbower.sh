#!/usr/bin/env bash
#
# two_run_sandbower.sh
#
# 1) Determine application name from $1
# 2) Load or create a separate rules.<app>.env for that application
# 3) First run with those rules
# 4) Parse strace logs for EACCES/EPERM (ignore ENOENT)
# 5) Prompt user to update rules (and store them in rules.<app>.env)
# 6) If needed, do a second run
# 7) Persist changes in that app’s file

########################################
# 0. Determine the application name & shift
########################################

if [ $# -lt 1 ]; then
  echo "Usage: $0 <application> [args...]"
  exit 1
fi

APP_CMD="$(basename "$1")"
shift  # Now $@ are the arguments to that application

########################################
# 1. Load or create a rules file per-app
########################################

# e.g. rules.firefox.env if the user typed "firefox"
RULES_FILE="/home/alexandre/Documents/master_project/rust-landlock-main/rules.$APP_CMD.env"

if [ -f "$RULES_FILE" ]; then
  # If we already have a rules.*.env for this app, load it
  echo "[DEBUG] Loading existing rules from $RULES_FILE"
  source "$RULES_FILE"
else
  # Otherwise, set default Landlock environment for this app
  echo "[DEBUG] No existing $RULES_FILE. Using defaults."
  LL_FS_RO="${LL_FS_RO:-/bin:/proc:/var:/lib:/usr:/proc:/etc:/dev/urandom}"
  LL_FS_RW="${LL_FS_RW:-/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp}"
  LL_TCP_BIND="${LL_TCP_BIND:-9418}"
  LL_TCP_CONNECT="${LL_TCP_CONNECT:-80:443}"
fi

########################################
# 2. Additional global script settings
########################################

SANDBOXER_PATH="/home/alexandre/Documents/master_project/rust-landlock-main/target/release/examples/sandboxer"
LOG_PREFIX="/tmp/sandboxer.log"

########################################
# Helper: run the sandbox + strace
# and filter out "No such file or directory (os error 2)"
########################################
run_sandbox () {
  local label="$1"   # "first run", "second run", etc.
  shift             # The rest are the arguments for the app

  rm -f "$LOG_PREFIX".*

  echo "Running sandbox ($label) for app '$APP_CMD'..."
  echo "Perform some commands inside, then exit."
  {
    strace -ff -e trace=all -o "$LOG_PREFIX" \
      "$SANDBOXER_PATH" "$@"
  } 2>&1 | grep -v "No such file or directory (os error 2)"
}

########################################
# 3. First run with the app’s environment
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

run_sandbox "first time" "$APP_CMD" "$@"

echo ""
echo "First run completed. Checking for denied operations..."
echo "========================================"

########################################
# 4. Parse logs for EACCES/EPERM, ignoring ENOENT
########################################
DENIED_LINES="$(
  grep -EH ' = -[0-9]+ (EACCES|EPERM)' "$LOG_PREFIX".* 2>/dev/null \
    | grep -v ' = -2 ENOENT' \
    | grep -v '(No such file or directory)' \
    || true
)"

if [ -z "$DENIED_LINES" ]; then
  echo "No denied operations found in the first run. No second run needed."
else
  echo "Denied operations found. Updating rules..."
  NEW_RO=""
  NEW_RW=""
  PROMPTED_PATHS=""

  while IFS= read -r line; do
    # Extract the path in quotes
    path="$(echo "$line" | sed -nE 's/.*"([^"]+)".*/\1/p')"
    [ -z "$path" ] && continue

    # If we've already prompted, skip
    if echo "$PROMPTED_PATHS" | grep -Fqx "$path"; then
      continue
    fi
    PROMPTED_PATHS="$PROMPTED_PATHS
$path"

    # Skip if path is already in LL_FS_RO or LL_FS_RW
    if echo "$LL_FS_RO" | grep -Fq "$path" || echo "$LL_FS_RW" | grep -Fq "$path"; then
      continue
    fi

    echo "Denied path: '$path'"
    echo "Add to [r]ead-only, [w]riteable, or [s]kip?"
    read -r choice < /dev/tty
    case "$choice" in
      [Rr]) NEW_RO="$NEW_RO:$path" ;;
      [Ww]) NEW_RW="$NEW_RW:$path" ;;
      *)    echo "Skipping $path" ;;
    esac
  done <<< "$(printf '%s\n' "$DENIED_LINES")"

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
  # 5. Second run if needed
  ########################################
  echo "SECOND RUN FOR APP: $APP_CMD"
  echo "========================================"
  export LL_FS_RO LL_FS_RW LL_TCP_BIND LL_TCP_CONNECT

  run_sandbox "second time" "$APP_CMD" "$@"

  echo ""
  echo "Second run completed. Checking for denied operations..."
  echo "========================================"

  DENIED_LINES_SECOND="$(
    grep -EH ' = -[0-9]+ (EACCES|EPERM)' "$LOG_PREFIX".* 2>/dev/null \
      | grep -v ' = -2 ENOENT' \
      | grep -v '(No such file or directory)' \
      || true
  )"

  if [ -z "$DENIED_LINES_SECOND" ]; then
    echo "No denied operations found in the second run."
  else
    echo "Denied operations still detected in the second run."
    echo "You may need further updates if you want those paths allowed."
  fi
fi

########################################
# 6. Persist updated rules for just that app
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
