#!/usr/bin/env bash
# sandbox_wrapper.sh

# Path to the sandboxer script
SANDBOXER_SCRIPT="/home/alexandre/Documents/master_project/rust-landlock-main/two_run_sandbower.sh"

# Execute the command through the sandboxer
"$SANDBOXER_SCRIPT" "$@"
