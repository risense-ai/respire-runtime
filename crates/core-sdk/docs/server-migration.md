# Change servers and copy a local library

Use the host terminal. Keep the original account selected, including its session and original unlock factors. Do not delete `session.json` or overwrite its server address.

```sh
rsrs login --addr https://api.rsrs.rs --migrate-local
```

Authorize the target account in the browser, unlock its vault with its Super password, and unlock the source library when prompted. The source and target may have different passwords and data keys. The source server does not need to be reachable when its complete encrypted library and unlock factors are available locally.

For a custom server, also pass `--dashboard https://your-dashboard.example`. Login requires HTTPS except for loopback fixtures. The target cloud account must already have a vault; create/register it before transferring a library.

In TUI Accounts > Login, enter the target server and confirm copying the selected local memories. Answering no only logs in. A matching remote identity uses its existing library; a different server or differently cased username uses a separate profile. Identity checks and key verification remain mandatory.

After `logout --full`, logging back into the same account can recover its retained local library only after the authorized cloud data key decrypts its live records. A library encrypted with another account's key is not reused.

Migration first synchronizes the target library so cloud-only records participate in deduplication. If this preflight fails or the target has not converged, copying stops and the original selection is restored. It then copies a committed source snapshot, decrypts it in memory and reencrypts it for the target. No plaintext export file is created. The source is retained. Existing target bodies are kept; exact duplicate bodies are skipped, and new parent/association references are remapped. Different content remains distinct. Changed source records after the snapshot are not part of that transfer.

The login result includes import counts and a sync result. Exit code 2 with a sync warning after successful login means the local copy remains available; inspect the reported error and retry `rsrs sync` when connectivity returns. It does not mean the source was removed. A failed profile commit restores the previous selection. Repeating a transfer skips bodies already copied.

For support, collect `rsrs --version`, `rsrs --json status`, `rsrs --json account list`, `rsrs --json config` and `rsrs --json doctor`. Include the command, failed stage and target origin. Redact personal paths/usernames when unnecessary. Never send session files, Super passwords, account secrets, tokens or private keys.
