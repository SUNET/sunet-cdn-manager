#!/bin/bash
set -e

# Make sure pgbackrest is initialized at database creation to match compose
# file archiving setup.
#
# Error seen:
# ```
# P00  ERROR: [103]: unable to find a valid repository:
#             repo1: [FileMissingError] unable to load info file '/var/lib/pgbackrest/repo1/archive/cdn/archive.info' or '/var/lib/pgbackrest/repo1/archive/cdn/archive.info.copy':
#             FileMissingError: unable to open missing file '/var/lib/pgbackrest/repo1/archive/cdn/archive.info' for read
#             FileMissingError: unable to open missing file '/var/lib/pgbackrest/repo1/archive/cdn/archive.info.copy' for read
#             HINT: archive.info cannot be opened but is required to push/get WAL segments.
#             HINT: is archive_command configured correctly in postgresql.conf?
#             HINT: has a stanza-create been performed?
#             HINT: use --no-archive-check to disable archive checks during backup if you have an alternate archiving scheme.
# P00   INFO: archive-push command end: aborted with exception [103]
# UTC [62] LOG:  archive command failed with exit code 103
# UTC [62] DETAIL:  The failed archive command was: pgbackrest --stanza=cdn archive-push pg_wal/000000010000000000000001
# ```
pgbackrest --stanza=cdn stanza-create
