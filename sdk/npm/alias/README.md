# Short npm entry

`rsrs-cli` is the primary install entry for the Respire CLI.
It forwards arguments and the process exit code through the existing launcher.
The launcher continues to select and verify the native platform package.

Build with `node npm/scripts/pack-alias.mjs`. The resulting package is under
`npm/dist/rsrs-cli`. Publish only after the matching launcher package at the exact
dependency version is publicly available. Use `dev` for a development version
and `latest` for a formal version. Publishing this package requires its own npm
authorization; the launcher package's trusted publisher does not automatically
authorize it.

After the initial publication, configure `risense-ai/respire-cli` with workflow
`npm-alias.yml` as this package's trusted publisher. Dispatch **Publish short
npm entry** to publish future formal versions after the launcher package is public.
Alias-only changes do not trigger the four-target native release workflow.

The user install command is `npm install -g rsrs-cli`.
To switch from another install entry, first uninstall the previously installed
npm package to avoid both packages claiming the same global `rsrs` command.
This does not remove account data or model files.
