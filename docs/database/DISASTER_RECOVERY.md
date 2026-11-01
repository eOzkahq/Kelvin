# Database Backup and Disaster Recovery

**Status:** Initial operational design (Compose reference implementation)  
**Scope:** PostgreSQL 15+ database, schema migrations, roles, RLS policies, findings and audit history.

## Objectives and policy

- **RPO: 15 minutes maximum.** In the reference Compose setup, PostgreSQL archives WAL continuously and forces a segment switch every five minutes. The operational alert threshold is ten minutes since the last successful archive, leaving five minutes of margin. Production must monitor archive freshness and page on threshold breach; a configured archive command without successful uploads does not meet the objective.
- **RTO: 60 minutes maximum.** The target assumes the PostgreSQL-compatible infrastructure and encryption keys are available. Restoration and integrity checks must complete within 45 minutes, leaving 15 minutes for application reconnection and sign-off. Measure this in each drill; report a miss rather than claiming compliance.
- Retain seven full backups plus the WAL needed to recover to each retained backup. Run a full physical backup daily. Run a logical `pg_dump` daily for portable recovery and migration-independent inspection.
- Encrypt physical repository data with pgBackRest AES-256 and logical dump streams with GPG AES-256 (integrity-protected). Use distinct, high-entropy secrets from a secret manager; never store keys beside backups or in source control. Use TLS in transit. The local Compose volume is for development/drills only, not a disaster-recovery copy.
- Production repository: isolated object storage account/bucket, TLS, versioning and Object Lock/WORM retention. Use cloud KMS or an isolated secrets manager to protect the repository encryption key. Deny delete/overwrite to the database identity; grant restore access separately. Replicate to a second failure domain and alert on archive age, failed jobs, repository capacity, and retention drift.

## Reference implementation

`docker-compose.backup.yml` is an opt-in overlay for the existing local Compose deployment. It adds pgBackRest to PostgreSQL, enables WAL archiving, and stores encrypted repository data in a separate named Docker volume. The overlay refuses to start without `PGBACKREST_REPO1_CIPHER_PASS`.

Set the secret in the deployment environment (prefer an injected secret, not a committed `.env`), build/start both Compose files, then initialize the stanza once:

```sh
export PGBACKREST_REPO1_CIPHER_PASS='retrieve-from-secret-manager'
docker compose -f docker-compose.yml -f docker-compose.backup.yml up -d --build postgres
./scripts/database/backup.sh --init
```

Schedule `scripts/database/backup.sh` daily at 02:00 UTC using the host scheduler. Its execution environment must receive `PGBACKREST_REPO1_CIPHER_PASS` from the secret manager (for example, a systemd credential or scheduler secret integration); never put the literal secret in a crontab. The command creates a compressed pgBackRest full backup. PostgreSQL continuously ships completed WAL segments; `archive_timeout=300s` bounds the time a partially filled segment waits before archival. The pgBackRest repository is AES-256 encrypted. Monitor command exit status and `pg_stat_archiver`; alert if `last_archived_time` is more than ten minutes old or `failed_count` increases.

For a portable logical copy, set `KELVIN_LOGICAL_BACKUP_KEY` from a separate secret-manager entry and schedule `scripts/database/logical-backup.sh` daily. The host needs GnuPG installed. The script writes an integrity-protected AES-256 GPG file locally; copy output to the isolated offsite vault over TLS. It does not itself provide offsite replication or immutability. Decrypt with `gpg --batch --pinentry-mode loopback --passphrase-fd 3 --decrypt --output restore.dump file.dump.gpg` (supply the secret on file descriptor 3, not on the command line), then use `pg_restore` against a newly created database.

The Compose reference repository is on the same host and is not sufficient for production. For production, configure pgBackRest `repo1-type=s3`, `repo1-s3-bucket`, `repo1-s3-endpoint`, `repo1-s3-region`, and workload-identity credentials; set the bucket's Object Lock retention and KMS policy independently. Put the repository encryption passphrase in the production secret manager. Use a scheduled job in the deployment platform to run the daily full backup and retain the archive monitoring/alerting described above.

## Restore procedure

1. Declare the incident, record the desired recovery timestamp, and stop application writers. Preserve the damaged database and logs for investigation. Confirm the latest usable base backup and WAL timestamp in the vault, and retrieve the encryption secret through the approved secret manager.
2. Provision an isolated PostgreSQL 15+ target with adequate disk space. Block application/network access. Install the matching pgBackRest version and configure the repository, TLS, credentials, and encryption secret. Never restore over the only surviving copy.
3. Restore the latest full backup with WAL replay to the incident timestamp (or latest available):

   ```sh
   pgbackrest --stanza=kelvin --set=<backup-set> --type=time \
     --target='2026-10-31 12:00:00+00' --target-action=promote restore
   ```

   Omit `--target`/`--target-action` to recover to the latest archived WAL. Start PostgreSQL and wait for recovery to finish. For an encrypted logical dump, decrypt to a protected temporary file with the matching key and use `pg_restore --clean --if-exists --no-owner` against a newly created database; recreate required cluster roles from approved infrastructure definitions before granting application access.
4. Verify with the drill checks below, confirm the migration version is clean, compare expected row counts and business-level invariants, and inspect server logs for recovery errors. Confirm the recovered time meets RPO and elapsed restoration time meets RTO.
5. Keep the target isolated until security and data owners sign off. Repoint applications, verify health and tenant isolation, then resume writes. Preserve the incident copy according to evidence-retention policy.

## Isolated restoration and integrity drill

Run a drill after initial setup, monthly, after PostgreSQL/pgBackRest upgrades, and after material schema changes. The executable drill restores into an ephemeral container and verifies database readiness, migration version 3, tenant RLS enabled and forced, and the tenant isolation policy:

```sh
export PGBACKREST_REPO1_CIPHER_PASS='retrieve-from-secret-manager'
./scripts/database/restore-drill.sh
```

Run it against the production vault in a separate network/account for the production sign-off. Record the backup ID, WAL recovery timestamp, start/end times, RPO, RTO, check output, and operator. The script's current checks establish basic schema/RLS recovery; production sign-off also requires expected table counts, representative tenant-scoped queries, audit-log invariants, and application smoke checks. A successful local-volume drill is not evidence that the offsite vault is restorable.

## Operational acceptance and ownership

Before declaring production compliance, verify: archive freshness stays under ten minutes during normal load; a daily full backup and WAL objects arrive in the isolated vault; object retention/delete controls and key recovery work; and a monthly isolated restore completes within the 45-minute restoration budget. Platform Engineering owns alert response and restore execution; Security/Data owners approve recovered evidence and tenant checks. Record exceptions and the next corrective action in the incident log.
