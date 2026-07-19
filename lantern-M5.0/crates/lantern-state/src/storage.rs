use lantern_store::{ColumnFamily, ReadStore};
use lantern_types::{
    AppStateCommitmentV1, CaStateV1, Ed25519PublicKey, Hash32, Nonce16, TimestampV1,
    TransactionResultV1, WireObject,
};

use crate::{Error, Result};

pub(crate) const GLOBAL_STATE_KEY: &[u8] = b"lantern/state/v1/global";
pub(crate) const STATE_CONFIG_KEY: &[u8] = b"lantern/state/v1/config";
const CA_STATE_PREFIX: &[u8] = b"lantern/state/v1/ca/";
const PREAUTH_PREFIX: &[u8] = b"lantern/state/v1/preauth/";
const IDEMPOTENCY_PREFIX: &[u8] = b"lantern/state/v1/idempotency/";
const RECORD_PREFIX: &[u8] = b"lantern/state/v1/record/";
const CA_VERSION_PREFIX: &[u8] = b"lantern/state/v1/ca-version/";
const MANIFEST_PREFIX: &[u8] = b"lantern/state/v1/manifest/";
const ARCHIVE_PREFIX: &[u8] = b"lantern/state/v1/publication/";
const CONTROL_ARCHIVE_PREFIX: &[u8] = b"lantern/state/v1/control/";
const HEAD_PREFIX: &[u8] = b"lantern/state/v1/head/";
const GLOBAL_MAGIC: &[u8; 4] = b"LNS4";
const IDEMPOTENCY_MAGIC: &[u8; 4] = b"LNID";
const PREAUTH_MAGIC: &[u8; 4] = b"LNPA";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistentState {
    pub last_block_time: TimestampV1,
    pub open_epoch: u64,
    pub epoch_bundle_hash: Hash32,
    pub epoch_admitted_count: u64,
    pub app_state: AppStateCommitmentV1,
}

impl PersistentState {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.last_block_time.validate()?;
        self.app_state.validate()?;
        let app = self.app_state.to_canonical_cbor()?;
        let app_len = u32::try_from(app.len())
            .map_err(|_| Error::InvalidInput("AppState encoding exceeds u32".into()))?;
        let mut bytes = Vec::with_capacity(70 + app.len());
        bytes.extend_from_slice(GLOBAL_MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&self.last_block_time.seconds.to_be_bytes());
        bytes.extend_from_slice(&self.last_block_time.nanos.to_be_bytes());
        bytes.extend_from_slice(&self.open_epoch.to_be_bytes());
        bytes.extend_from_slice(self.epoch_bundle_hash.as_bytes());
        bytes.extend_from_slice(&self.epoch_admitted_count.to_be_bytes());
        bytes.extend_from_slice(&app_len.to_be_bytes());
        bytes.extend_from_slice(&app);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 70 || bytes.get(..4) != Some(GLOBAL_MAGIC) {
            return Err(Error::CorruptState(
                "global state prefix/length is invalid".into(),
            ));
        }
        if read_u16(bytes, 4)? != 1 {
            return Err(Error::CorruptState(
                "global state version is not one".into(),
            ));
        }
        let app_len = usize::try_from(read_u32(bytes, 66)?)
            .map_err(|_| Error::CorruptState("AppState length overflows usize".into()))?;
        if bytes.len() != 70 + app_len {
            return Err(Error::CorruptState(
                "global AppState length is inconsistent".into(),
            ));
        }
        let value = Self {
            last_block_time: TimestampV1::new(read_i64(bytes, 6)?, read_u32(bytes, 14)?)?,
            open_epoch: read_u64(bytes, 18)?,
            epoch_bundle_hash: read_hash(bytes, 26)?,
            epoch_admitted_count: read_u64(bytes, 58)?,
            app_state: AppStateCommitmentV1::from_canonical_cbor(&bytes[70..])?,
        };
        let expected_open = value
            .app_state
            .last_closed_epoch
            .map_or(0, |epoch| epoch.saturating_add(1));
        if value.open_epoch != expected_open {
            return Err(Error::CorruptState(format!(
                "open epoch {} disagrees with last closed epoch {:?}",
                value.open_epoch, value.app_state.last_closed_epoch
            )));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Preauthorization {
    pub admin_key: Ed25519PublicKey,
    pub predecessor_ca_id: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdempotencyEntry {
    pub transaction_id: Hash32,
    pub result: TransactionResultV1,
}

pub(crate) fn read_persistent<S: ReadStore + ?Sized>(store: &S) -> Result<Option<PersistentState>> {
    store
        .get(ColumnFamily::ConfigReconfiguration, GLOBAL_STATE_KEY)?
        .map(|bytes| PersistentState::decode(&bytes))
        .transpose()
}

pub(crate) fn read_config<S: ReadStore + ?Sized>(store: &S) -> Result<Option<Vec<u8>>> {
    Ok(store.get(ColumnFamily::ConfigReconfiguration, STATE_CONFIG_KEY)?)
}

pub(crate) fn ca_state_key(ca_id: Hash32) -> Vec<u8> {
    prefixed(CA_STATE_PREFIX, ca_id.as_bytes())
}

pub(crate) fn read_ca_state<S: ReadStore + ?Sized>(
    store: &S,
    ca_id: Hash32,
) -> Result<Option<CaStateV1>> {
    store
        .get(ColumnFamily::ConfigReconfiguration, &ca_state_key(ca_id))?
        .map(|bytes| CaStateV1::from_canonical_cbor(&bytes).map_err(Error::from))
        .transpose()
}

pub(crate) fn preauth_key(ca_id: Hash32) -> Vec<u8> {
    prefixed(PREAUTH_PREFIX, ca_id.as_bytes())
}

pub(crate) fn encode_preauthorization(value: Preauthorization) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(68);
    bytes.extend_from_slice(PREAUTH_MAGIC);
    bytes.extend_from_slice(value.admin_key.as_bytes());
    bytes.extend_from_slice(value.predecessor_ca_id.as_bytes());
    bytes
}

pub(crate) fn read_preauthorization<S: ReadStore + ?Sized>(
    store: &S,
    ca_id: Hash32,
) -> Result<Option<Preauthorization>> {
    store
        .get(ColumnFamily::ConfigReconfiguration, &preauth_key(ca_id))?
        .map(|bytes| {
            if bytes.len() != 68 || bytes.get(..4) != Some(PREAUTH_MAGIC) {
                return Err(Error::CorruptState(
                    "preauthorization encoding is invalid".into(),
                ));
            }
            Ok(Preauthorization {
                admin_key: Ed25519PublicKey::new(read_fixed::<32>(&bytes, 4)?),
                predecessor_ca_id: Hash32::new(read_fixed::<32>(&bytes, 36)?),
            })
        })
        .transpose()
}

pub(crate) fn idempotency_key(ca_id: Hash32, nonce: Nonce16) -> Vec<u8> {
    let mut key = Vec::with_capacity(IDEMPOTENCY_PREFIX.len() + 48);
    key.extend_from_slice(IDEMPOTENCY_PREFIX);
    key.extend_from_slice(ca_id.as_bytes());
    key.extend_from_slice(nonce.as_bytes());
    key
}

pub(crate) fn encode_idempotency(entry: &IdempotencyEntry) -> Result<Vec<u8>> {
    let result = entry.result.to_canonical_cbor()?;
    let result_len = u32::try_from(result.len())
        .map_err(|_| Error::InvalidInput("transaction result encoding exceeds u32".into()))?;
    let mut bytes = Vec::with_capacity(40 + result.len());
    bytes.extend_from_slice(IDEMPOTENCY_MAGIC);
    bytes.extend_from_slice(entry.transaction_id.as_bytes());
    bytes.extend_from_slice(&result_len.to_be_bytes());
    bytes.extend_from_slice(&result);
    Ok(bytes)
}

pub(crate) fn read_idempotency<S: ReadStore + ?Sized>(
    store: &S,
    ca_id: Hash32,
    nonce: Nonce16,
) -> Result<Option<IdempotencyEntry>> {
    store
        .get(ColumnFamily::Idempotency, &idempotency_key(ca_id, nonce))?
        .map(|bytes| {
            if bytes.len() < 40 || bytes.get(..4) != Some(IDEMPOTENCY_MAGIC) {
                return Err(Error::CorruptState(
                    "idempotency encoding is invalid".into(),
                ));
            }
            let result_len = usize::try_from(read_u32(&bytes, 36)?)
                .map_err(|_| Error::CorruptState("result length overflows usize".into()))?;
            if bytes.len() != 40 + result_len {
                return Err(Error::CorruptState(
                    "idempotency result length is inconsistent".into(),
                ));
            }
            Ok(IdempotencyEntry {
                transaction_id: read_hash(&bytes, 4)?,
                result: TransactionResultV1::from_canonical_cbor(&bytes[40..])?,
            })
        })
        .transpose()
}

pub(crate) fn record_key(index: u64) -> Vec<u8> {
    prefixed(RECORD_PREFIX, &index.to_be_bytes())
}

pub(crate) fn ca_version_key(ca_id: Hash32, version: u64) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(40);
    suffix.extend_from_slice(ca_id.as_bytes());
    suffix.extend_from_slice(&version.to_be_bytes());
    prefixed(CA_VERSION_PREFIX, &suffix)
}

pub(crate) fn manifest_key(ca_id: Hash32, manifest_hash: Hash32) -> Vec<u8> {
    let mut suffix = Vec::with_capacity(64);
    suffix.extend_from_slice(ca_id.as_bytes());
    suffix.extend_from_slice(manifest_hash.as_bytes());
    prefixed(MANIFEST_PREFIX, &suffix)
}

pub(crate) fn archive_key(transaction_id: Hash32) -> Vec<u8> {
    prefixed(ARCHIVE_PREFIX, transaction_id.as_bytes())
}

pub(crate) fn control_archive_key(control_event_id: Hash32) -> Vec<u8> {
    prefixed(CONTROL_ARCHIVE_PREFIX, control_event_id.as_bytes())
}

pub(crate) fn head_key(epoch: u64) -> Vec<u8> {
    prefixed(HEAD_PREFIX, &epoch.to_be_bytes())
}

fn prefixed(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + suffix.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| Error::CorruptState("fixed-width value is truncated".into()))?
        .try_into()
        .map_err(|_| Error::CorruptState("fixed-width conversion failed".into()))
}

fn read_hash(bytes: &[u8], offset: usize) -> Result<Hash32> {
    read_fixed(bytes, offset).map(Hash32::new)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    read_fixed(bytes, offset).map(u16::from_be_bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    read_fixed(bytes, offset).map(u32::from_be_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    read_fixed(bytes, offset).map(u64::from_be_bytes)
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64> {
    read_fixed(bytes, offset).map(i64::from_be_bytes)
}
