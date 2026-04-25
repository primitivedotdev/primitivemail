# Inject a read-only /etc/letsencrypt mount into the primitivemail service's
# `volumes:` block in docker-compose.yml. Used by install.sh --enable-letsencrypt.
#
# Idempotent and assumption-checked: emits the rewritten file on stdout, and
# exits non-zero (with a diagnostic on stderr) if the compose file does not
# match the layout we expect (missing `primitivemail:` service header, no
# `./maildata:/mail/incoming` mount line under it, flow-style volumes, etc.).
# Callers must check the exit code; printing success without verifying that
# injection actually happened was the previous bug.
#
# Exit codes:
#   0 - injection performed
#   2 - mount already present (no-op success)
#   3 - primitivemail service block not found
#   4 - primitivemail block found but no maildata anchor inside it
#
# Implementation: two-pass over the input file. Pass 1 (NR==FNR) detects an
# existing /etc/letsencrypt mount line so we can skip injection without
# emitting a duplicate; pass 2 emits the rewritten body and tracks whether
# we are inside the primitivemail service block. Single-pass would re-insert
# whenever the existing mount line came AFTER the ./maildata anchor.
#
# Anchoring: we insert AFTER the `./maildata:/mail/incoming` line and only
# while the in_pm flag is set. The flag turns on at the line that matches
# `^  primitivemail:` (two-space indent, exact name, colon, optional spaces)
# and back off at the next two-space-indented service header. This keeps the
# injection from landing in another service if compose is reordered.
#
# Invoke as:  awk -f inject-compose-mount.awk <compose-file> <compose-file>
# install.sh wraps that argument-doubling.

BEGIN {
    in_pm = 0
    inserted = 0
    seen_pm_header = 0
    already_present = 0
}

# Pass 1: scan for an existing mount line, do not emit anything.
NR == FNR {
    if ($0 ~ /^[[:space:]]*-[[:space:]]*\/etc\/letsencrypt:\/etc\/letsencrypt(:ro)?[[:space:]]*$/) {
        already_present = 1
    }
    next
}

# Pass 2 below.

# Service header: two-space indent, identifier, colon, optional trailing space.
/^[[:space:]]{2}[A-Za-z0-9_-]+:[[:space:]]*$/ {
    if ($0 ~ /^[[:space:]]{2}primitivemail:[[:space:]]*$/) {
        in_pm = 1
        seen_pm_header = 1
    } else {
        in_pm = 0
    }
}

{
    print $0
    if (!already_present && in_pm && !inserted && $0 ~ /^[[:space:]]*-[[:space:]]*\.\/maildata:\/mail\/incoming[[:space:]]*$/) {
        match($0, /^[[:space:]]*/)
        indent = substr($0, RSTART, RLENGTH)
        printf "%s- /etc/letsencrypt:/etc/letsencrypt:ro\n", indent
        inserted = 1
    }
}

END {
    if (already_present) {
        # Pre-existing mount; pass 2 emitted the file verbatim. Distinct
        # exit code so callers can log "already mounted" instead of
        # "injected".
        exit 2
    }
    if (!seen_pm_header) {
        print "inject-compose-mount: primitivemail service block not found" > "/dev/stderr"
        exit 3
    }
    if (!inserted) {
        print "inject-compose-mount: primitivemail block found but no ./maildata:/mail/incoming anchor inside it" > "/dev/stderr"
        exit 4
    }
    exit 0
}
