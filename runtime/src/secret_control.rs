//! Fixed private reads. The caller owns authorization, scope locks and parent watching.
//! No store is opened, no session is changed, and no result is journaled here.

use anyhow::{Context, Result};
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest};
use respire_protocol::secret_control::{
    HostKeysExportReadParams, HostKeysExportReadResult, HostSecretReadParams,
    HostSecretReadResult, HostSecretSession, HOST_KEYS_EXPORT_READ_METHOD,
    HOST_SECRET_READ_METHOD, HOST_SECRET_SCHEMA_V,
};

pub(crate) enum SecretRequest {
    Read(HostSecretReadParams),
    KeysExport(HostKeysExportReadParams),
}

impl SecretRequest {
    pub(crate) fn parse(request: &RpcRequest) -> Result<Self> {
        let id = uuid::Uuid::parse_str(&request.id).context("invalid secret read request ID")?;
        anyhow::ensure!(request.v == respire_commands::rpc_client::PROTOCOL_V
            && id.get_version_num() == 4 && id.to_string() == request.id
            && request.args.len() == 1 && request.scope.is_none()
            && request.operation_id.is_none() && request.idempotency_key.is_none()
            && request.parent_operation_id.is_none() && request.queue_wait_ms.is_none()
            && request.lifecycle.is_none(), "invalid private secret read request");
        let (parsed, schema) = match request.method.as_str() {
            HOST_SECRET_READ_METHOD => {
                let params: HostSecretReadParams = serde_json::from_str(&request.args[0])
                    .map_err(|_| anyhow::anyhow!("invalid secret read parameters"))?;
                let schema = params.schema_version;
                (Self::Read(params), schema)
            }
            HOST_KEYS_EXPORT_READ_METHOD => {
                let params: HostKeysExportReadParams = serde_json::from_str(&request.args[0])
                    .map_err(|_| anyhow::anyhow!("invalid key export read parameters"))?;
                let schema = params.schema_version;
                (Self::KeysExport(params), schema)
            }
            _ => anyhow::bail!("unsupported private secret read method"),
        };
        anyhow::ensure!(schema == HOST_SECRET_SCHEMA_V, "unsupported private secret read schema");
        Ok(parsed)
    }

    pub(crate) fn binding(&self) -> &ControlBinding {
        match self { Self::Read(params) => &params.binding, Self::KeysExport(params) => &params.binding }
    }

    pub(crate) fn identity(&self) -> &HostAuthIdentity {
        match self { Self::Read(params) => &params.identity, Self::KeysExport(params) => &params.identity }
    }

    /// Call only with ownership held and identity checked before/after execution.
    /// The returned envelope goes directly to the private response, never progress/receipts.
    pub(crate) fn execute(
        &self,
        _ownership: &respire_app::login_transaction::AuthOwnership,
    ) -> Result<ResultEnvelope> {
        let (command, details) = match self {
            Self::Read(params) => ("secret-read", serde_json::to_value(read_secret(params.reveal)?)),
            Self::KeysExport(_) => {
                respire_app::service::ensure_writable()?;
                ("keys-export-read", serde_json::to_value(read_keys_export()?))
            },
        };
        let mut envelope = ResultEnvelope::new(command, Status::Ok, serde_json::json!({}), Vec::new());
        envelope.details = details.map_err(|_| anyhow::anyhow!("private secret read result encoding failed"))?;
        Ok(envelope)
    }
}

fn read_secret(reveal: bool) -> Result<HostSecretReadResult> {
    let info = respire_app::service::session_info();
    let (secret, five) = if info.has_session && reveal {
        (Some(respire_app::service::session_secret_full()?), Some(respire_app::service::session_five_keys()?))
    } else { (None, None) };
    Ok(HostSecretReadResult {
        session: HostSecretSession { has_session: info.has_session, user: info.user, addr: info.addr,
            has_token: info.has_token, secret_masked: info.secret_masked, has_local_keys: info.has_local_keys },
        secret, five,
    })
}

fn read_keys_export() -> Result<HostKeysExportReadResult> {
    let data = respire_app::auth::read_session_json()?;
    let user = data["user"].as_str().unwrap_or("").to_owned();
    let addr = data["addr"].as_str().unwrap_or("").to_owned();
    let version = data["vault_version"].as_i64().unwrap_or(0);
    let kdf_salt = data["kdf_salt"].as_str().unwrap_or("").to_owned();
    let wrapped_urk = data["wrapped_urk"].as_str().unwrap_or("").to_owned();
    let urk_nonce = data["urk_nonce"].as_str().unwrap_or("").to_owned();
    if wrapped_urk.is_empty() {
        anyhow::bail!("no local key material (session.json missing wrapped_urk) - this machine never ran register/keys");
    }
    let is_v4 = version >= 4;
    // v4: super password = session["secret_key"] or the keyring; v3: passphrase + Secret Key two-factor
    let super_key = data["secret_key"].as_str().unwrap_or("").to_owned();
    let legacy_super = data["super"]
        .as_str()
        .map(ToOwned::to_owned)
        .or_else(|| respire_app::keystore::load_super(&user))
        .unwrap_or_default();
    let super_key = if is_v4 && super_key.is_empty() {
        respire_app::keystore::load_super(&user).unwrap_or_default()
    } else {
        super_key
    };
    if is_v4 && super_key.is_empty() {
        anyhow::bail!(
            "this machine has no super password (session and keyring are both empty) - \
             if the old machine can still unlock, run rsrs keys-export there; or rsrs super-reset with the current code"
        );
    }
    let is_v3 = version == 3;
    let body = if version == 1 {
        let account_secret = data["secret"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "v1 Account Secret is missing; retain the original device and library"
                )
            })?;
        format!(
            "rsrs v1 key-recovery notes (keep private; losing the original factors makes data unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- original v1 decrypt factors (no independent super password) --\n\
             original login password: required, not included in this export\n\
             Account Secret: {account_secret}\n\n\
             -- unchanged vault wrap material --\n\
             vault_version: 1\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- new device, after explicit full-library and cloud migration --\n\
             rsrs login --interactive --user {user} --pass <original-login-password>\n\
             Enter the original Account Secret when prompted; do not use --super or ordinary --secret-key.\n\n\
             -- select the explicitly migrated library and publish the same v1 factors --\n\
             rsrs migrate --vault --user {user} --pass <original-login-password> --secret-key <original-account-secret>\n"
        )
    } else if is_v4 {
        format!(
            "rsrs key-recovery notes (leak = loss of the store; lost super password = cloud data permanently unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- super password (decrypt depends on this; v4 single factor) --\n\
             super password: {super_key}\n\n\
             -- vault wrap material (a new machine login fetches this; listed for lookup) --\n\
             vault_version: {version}\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- import on a new machine --\n\
             rsrs login --interactive --user {user} --pass <login-password> --super {super_key}\n\
             (or fill the same super password on the website Keys & Recovery page after login)\n"
        )
    } else {
        format!(
            "rsrs key-recovery notes (leak = loss of the store; lost super password = cloud data permanently unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- original decrypt factors (migration retains the vault version and factors) --\n\
             super password (passphrase): {legacy_super}\n\
             Secret Key (recovery code): {super_key}\n\n\
             -- vault wrap material (listed for lookup) --\n\
             vault_version: {version}\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- explicitly migrate the full library, select it, then publish its unchanged-factor vault --\n\
             rsrs migrate --vault --user {user} --pass <login-password> --super \"{legacy_super}\" --secret-key {super_key}\n"
        )
    };
    Ok(HostKeysExportReadResult { version, user, body, legacy_warning: !(is_v4 || is_v3) })
}
