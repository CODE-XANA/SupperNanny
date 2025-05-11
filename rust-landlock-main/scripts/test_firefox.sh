#!/usr/bin/env bash
#
# two_run_sandbower.sh
#
# 1) First run with default/predefined Landlock rules
# 2) Parse logs for EACCES/EPERM, ignoring ENOENT
# 3) Second run with updated rules (only if needed)
# 4) Persist the rule set across executions
#
# Additionally:
# - Filters out "No such file or directory (os error 2)" from
#   the sandboxed application's console output so it won't appear.

RULES_FILE="/home/alexandre/Documents/master_project/rust-landlock-main/rules.env"

########################################
# 0. Load or set environment rules
########################################
if [ -f "$RULES_FILE" ]; then
  source "$RULES_FILE"
else
  # Default rules if no saved rules
  LL_FS_RO="${LL_FS_RO:-/bin:/var:/lib:/usr:/proc:/etc:/dev/urandom}"
  LL_FS_RW="${LL_FS_RW:-/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp}"
  LL_TCP_BIND="${LL_TCP_BIND:-9418}"
  LL_TCP_CONNECT="${LL_TCP_CONNECT:-80:443}"
fi

SANDBOXER_PATH="/home/alexandre/Documents/master_project/rust-landlock-main/target/release/examples/sandboxer"
LOG_PREFIX="/tmp/sandboxer.log"

########################################
# Helper: run the sandbox command + strace,
# and suppress "No such file or directory (os error 2)" from console
########################################
run_sandbox () {
  local label="$1"   # e.g. "first time" or "second time"

  rm -f "$LOG_PREFIX".*

  echo "Running sandbox ($label)..."
  echo "Perform your commands inside, then exit."
  # We pipe the combined stdout/stderr to grep -v:
  {
    strace -ff -e trace=all -o "$LOG_PREFIX" \
      "$SANDBOXER_PATH" "${@:2}"
  } 2>&1 | grep -v "No such file or directory (os error 2)"
  # ^ This hides *any* line containing "No such file or directory (os error 2)"
  # from the sandboxed application's console output.
}

########################################
# 1) First Run
########################################
echo "========================================"
echo "FIRST RUN WITH DEFAULT RULES"
echo "========================================"
echo "Environment Settings:"
echo "  Read-Only Paths: $LL_FS_RO"
echo "  Read-Write Paths: $LL_FS_RW"
echo "  TCP Bind:        $LL_TCP_BIND"
echo "  TCP Connect:     $LL_TCP_CONNECT"
echo ""

# Export env so strace won't parse them as files
export LL_FS_RO LL_FS_RW LL_TCP_BIND LL_TCP_CONNECT

# First run
run_sandbox "first time" "$@"

echo ""
echo "First run completed. Analyzing logs for denied operations..."
echo "========================================"

########################################
# 2) Parse logs for EACCES/EPERM, ignoring ENOENT
########################################
DENIED_LINES="$(
  grep -EH ' = -[0-9]+ (EACCES|EPERM)' "$LOG_PREFIX".* 2>/dev/null \
    | grep -v ' = -2 ENOENT' \
    | grep -v '(No such file or directory)' \
    || true
)"

if [ -z "$DENIED_LINES" ]; then
  echo "No denied operations found in the first run."
  echo "No further sandbox runs needed."
else
  echo "Denied operations detected. Updating rules..."
  NEW_RO=""
  NEW_RW=""
  PROMPTED_PATHS=""

  while IFS= read -r line; do
    # Extract path from quotes
    path="$(echo "$line" | sed -nE 's/.*"([^"]+)".*/\1/p')"
    [ -z "$path" ] && continue

    # Skip if we've already prompted
    if echo "$PROMPTED_PATHS" | grep -Fqx "$path"; then
      continue
    fi
    PROMPTED_PATHS="$PROMPTED_PATHS
$path"

    # Skip if path already in LL_FS_RO or LL_FS_RW
    if echo "$LL_FS_RO" | grep -Fq "$path" || echo "$LL_FS_RW" | grep -Fq "$path"; then
      continue
    fi

    echo "Denied access to: '$path'"
    echo "Allow as [r]ead-only, [w]riteable, or [s]kip?"
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
  echo "Updated Environment Settings:"
  echo "  Read-Only Paths: $LL_FS_RO"
  echo "  Read-Write Paths: $LL_FS_RW"
  echo "========================================"
fi

########################################
# 3) Second Run if we had Denials
########################################
if [ -n "$DENIED_LINES" ]; then
  echo "SECOND RUN WITH UPDATED RULES"
  echo "========================================"
  export LL_FS_RO LL_FS_RW LL_TCP_BIND LL_TCP_CONNECT

  run_sandbox "second time" "$@"

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
# 4) Persist Updated Rules
########################################
echo ""
echo "Persisting updated rules to $RULES_FILE..."
cat <<EOF > "$RULES_FILE"
export LL_FS_RO="$LL_FS_RO"
export LL_FS_RW="$LL_FS_RW"
export LL_TCP_BIND="$LL_TCP_BIND"
export LL_TCP_CONNECT="$LL_TCP_CONNECT"
EOF

echo "Rules saved. No commands will be executed outside the sandbox."
echo "Done."
