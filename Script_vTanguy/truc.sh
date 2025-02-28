#!/usr/bin/env bash
#
# two_run_sandbower.sh
#
# 1) Determine application name from $1
# 2) Load or create a separate rules.<app>.env in application_conf/ for that application
# 3) First run with those rules
# 4) Parse strace logs for EACCES/EPERM (ignore ENOENT)
# 5) Prompt user to update rules (and store them in rules.<app>.env)
# 6) If needed, do a second run
# 7) Persist changes in that app’s file
#
# Ce script utilise le fichier cookies.txt pour extraire automatiquement
# les tokens "access_token" et "csrf_token" au format Netscape.

########################################
# 0. Récupérer les tokens depuis cookies.txt (format Netscape)
########################################
COOKIE_FILE="/home/vmubuntu/Bureau/ezgfafeaz/appapi/cookies.txt"

if [ -f "$COOKIE_FILE" ]; then
  export ACCESS_TOKEN=$(awk '$6=="access_token" {print $7; exit}' "$COOKIE_FILE")
  export CSRF_TOKEN=$(awk '$6=="csrf_token" {print $7; exit}' "$COOKIE_FILE")
fi

echo "ACCESS_TOKEN: $ACCESS_TOKEN"
echo "CSRF_TOKEN: $CSRF_TOKEN"

if [ -z "$ACCESS_TOKEN" ] || [ -z "$CSRF_TOKEN" ]; then
  echo "Erreur : les variables ACCESS_TOKEN et CSRF_TOKEN ne sont pas définies. Vérifiez le fichier $COOKIE_FILE."
  exit 1
fi

########################################
# 1. Determine application name & shift
########################################
if [ $# -lt 1 ]; then
  echo "Usage: $0 <application> [args...]"
  exit 1
fi

APP_CMD="$(basename "$1")"
shift  # Now $@ are the arguments to that application

########################################
# 2. Directory to store rules.*.env files
########################################
RULES_DIR="/home/vmubuntu/Bureau/rust-landlock/application_conf"
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
  LL_FS_RO="${LL_FS_RO:-/bin:/var:/lib:/usr:/proc:/etc:/dev/urandom}"
  LL_FS_RW="${LL_FS_RW:-/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp}"
  LL_TCP_BIND="${LL_TCP_BIND:-9418}"
  LL_TCP_CONNECT="${LL_TCP_CONNECT:-80:443}"
fi

########################################
# 3. Additional script settings
########################################
SANDBOXER_PATH="/home/vmubuntu/Bureau/rust-landlock/target/release/examples/sandboxer"
LOG_PREFIX="/tmp/sandboxer.log"

########################################
# Helper: run sandbox + strace, filter out
# "No such file or directory (os error 2)"
########################################
run_sandbox() {
  local label="$1"  # e.g. "first time", "second time"
  shift            # the rest are application args

  rm -f "$LOG_PREFIX".*

  echo "Running sandbox ($label) for app '$APP_CMD'..."
  echo "Perform some commands inside, then exit."

  {
    strace -ff -e trace=all -o "$LOG_PREFIX" "$SANDBOXER_PATH" "$APP_CMD" "$@"
  } 2>&1 | grep -v "No such file or directory (os error 2)"
}

########################################
# 4. First run
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

export LL_FS_RO LL_FS_RW LL_TCP_BIND LL_TCP_CONNECT

run_sandbox "first time" "$@"

echo ""
echo "First run completed. Checking for denied operations..."
echo "========================================"

########################################
# 5. Parse logs for EACCES/EPERM, ignoring ENOENT
########################################
DENIED_LINES="$(
  grep -EH ' = -[0-9]+ (EACCES|EPERM)' "$LOG_PREFIX".* 2>/dev/null \
    | grep -v ' = -2 ENOENT' \
    | grep -v '(No such file or directory)' \
    || true
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
    path="$(echo "$line" | sed -nE 's/.*"([^"]+)".*/\1/p')"
    [ -z "$path" ] && continue

    if echo "$PROMPTED_PATHS" | grep -Fqx "$path"; then
      continue
    fi
    PROMPTED_PATHS="$PROMPTED_PATHS
$path"

    if echo "$LL_FS_RO" | grep -Fq "$path" || echo "$LL_FS_RW" | grep -Fq "$path"; then
      continue
    fi

    echo "Denied path: '$path'"

    echo "DEBUG: Envoi du prompt pour le path '$path'"
    curl -X POST \
      -H "Content-Type: application/json" \
      -H "X-CSRF-Token: $CSRF_TOKEN" \
      -b "access_token=$ACCESS_TOKEN; csrf_token=$CSRF_TOKEN" \
      -d "{\"path\": \"$path\", \"app\": \"$APP_CMD\"}" \
      http://127.0.0.1:8080/script_prompt

    echo "Add to [r]ead-only, [w]riteable, or [s]kip?"

    choice=""
    while [ -z "$choice" ]; do
      choice=$(curl -s \
        -H "X-CSRF-Token: $CSRF_TOKEN" \
        -b "access_token=$ACCESS_TOKEN; csrf_token=$CSRF_TOKEN" \
        "http://127.0.0.1:8080/get_choice?path=$path&app=$APP_CMD")
      sleep 1
    done

    echo "Received choice: $choice"
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
  # 6. Second run if needed
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
# 7. Persist Updated Rules (per-app)
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

