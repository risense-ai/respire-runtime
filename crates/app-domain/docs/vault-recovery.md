# Recovering access to an encrypted vault

Cloud login and vault decryption are separate checks. Successful browser,
password or TOTP authorization does not recover the encryption data key.
Cancelled login, a missing recovery factor or an incorrect factor must preserve
the previously selected account and its session.

For a v4 vault, retry `rsrs login --interactive` with the original system-generated
`A3-` recovery code. If another trusted device can still unlock the same vault,
use its `rsrs keys-export --out <private-file>` flow and the documented login
prompts to transfer recovery material securely. Keep the export private; do not
paste its contents or a recovery code into an issue, chat, command log or support
attachment. A legacy v3 vault needs its original super password and Secret Key;
preserve those and its original files before an explicit vault migration.

If the supplied factor is correct but the wrapped key is damaged, preserve the
current profile and any backups. Use an intact copy of the same vault's recovery
material from a trusted device or backup. Do not overwrite the current profile,
delete the cloud vault, or repeatedly generate new keys as a repair attempt.

`rsrs super-reset` rotates recovery protection **after the existing vault data
key can be unlocked**. It cannot recover an unknown data key. Account password
resets and server operators cannot decrypt a vault when all usable recovery
material and trusted-device copies have been lost.

`rsrs keygen --force` creates unrelated offline keys and drops the cloud session.
It is an explicit switch to an offline identity, not a way to reconnect to the
old encrypted cloud account. Preserve the original profile and backups before
choosing it. The removed `login --reset-vault` and `login --secret-key` flags are
not supported recovery interfaces; clients must not recreate them or suggest a
destructive reset as automatic recovery.
