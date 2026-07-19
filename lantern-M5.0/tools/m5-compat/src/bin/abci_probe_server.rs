use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tendermint_abci::{Application, ServerBuilder};
use tendermint_proto::v0_38::abci::{
    ExecTxResult, RequestFinalizeBlock, RequestInfo, ResponseCommit, ResponseFinalizeBlock,
    ResponseInfo,
};

#[derive(Clone, Debug, Default, Serialize)]
struct ProbeState {
    info_calls: u64,
    finalize_calls: u64,
    commit_calls: u64,
    tx_count: usize,
    pending_height: Option<i64>,
    pending_app_hash_hex: Option<String>,
    committed_height: i64,
    committed_app_hash_hex: String,
}

#[derive(Clone)]
struct ProbeApp {
    state: Arc<Mutex<ProbeState>>,
    transcript_path: Arc<PathBuf>,
}

impl ProbeApp {
    fn new(transcript_path: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(ProbeState::default())),
            transcript_path: Arc::new(transcript_path),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, ProbeState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("M5.0 probe mutex was poisoned; preserving state for diagnostics");
                poisoned.into_inner()
            }
        }
    }

    fn write_transcript(&self, state: &ProbeState) {
        let encoded = match serde_json::to_vec_pretty(state) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("cannot encode M5.0 ABCI transcript: {error}");
                return;
            }
        };
        if let Err(error) = fs::write(self.transcript_path.as_ref(), encoded) {
            eprintln!("cannot write M5.0 ABCI transcript: {error}");
        }
    }

    fn app_hash(height: i64, txs: &[prost::bytes::Bytes]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"lantern/m5.0/abci-v0.38\0");
        hasher.update(height.to_be_bytes());
        for tx in txs {
            hasher.update(u64::try_from(tx.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(tx);
        }
        hasher.finalize().to_vec()
    }
}

impl Application for ProbeApp {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        let mut state = self.lock_state();
        state.info_calls = state.info_calls.saturating_add(1);
        self.write_transcript(&state);
        ResponseInfo {
            data: "lantern-m5.0-compat".to_owned(),
            version: "0.1.0".to_owned(),
            app_version: 1,
            last_block_height: state.committed_height,
            last_block_app_hash: hex::decode(&state.committed_app_hash_hex)
                .unwrap_or_default()
                .into(),
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let mut state = self.lock_state();
        let height = if request.height > 0 {
            request.height
        } else {
            state.committed_height.saturating_add(1)
        };
        let app_hash = Self::app_hash(height, &request.txs);
        state.finalize_calls = state.finalize_calls.saturating_add(1);
        state.tx_count = state.tx_count.saturating_add(request.txs.len());
        state.pending_height = Some(height);
        state.pending_app_hash_hex = Some(hex::encode(&app_hash));
        self.write_transcript(&state);

        let tx_results = request
            .txs
            .iter()
            .map(|tx| ExecTxResult {
                code: 0,
                data: Sha256::digest(tx).to_vec().into(),
                log: String::new(),
                info: "m5.0-wire-ok".to_owned(),
                gas_wanted: 0,
                gas_used: 0,
                events: Vec::new(),
                codespace: String::new(),
            })
            .collect();
        ResponseFinalizeBlock {
            events: Vec::new(),
            tx_results,
            validator_updates: Vec::new(),
            consensus_param_updates: None,
            app_hash: app_hash.into(),
        }
    }

    fn commit(&self) -> ResponseCommit {
        let mut state = self.lock_state();
        state.commit_calls = state.commit_calls.saturating_add(1);
        if let (Some(height), Some(app_hash)) = (
            state.pending_height.take(),
            state.pending_app_hash_hex.take(),
        ) {
            state.committed_height = height;
            state.committed_app_hash_hex = app_hash;
        }
        self.write_transcript(&state);
        ResponseCommit { retain_height: 0 }
    }
}

fn parse_args() -> Result<(String, PathBuf)> {
    let mut args = env::args_os().skip(1);
    let address = args
        .next()
        .context("usage: m5-abci-probe-server LISTEN_ADDRESS TRANSCRIPT.json")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("listen address is not valid UTF-8"))?;
    let transcript = args
        .next()
        .map(PathBuf::from)
        .context("usage: m5-abci-probe-server LISTEN_ADDRESS TRANSCRIPT.json")?;
    if args.next().is_some() {
        bail!("usage: m5-abci-probe-server LISTEN_ADDRESS TRANSCRIPT.json");
    }
    Ok((address, transcript))
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create transcript directory {}", parent.display()))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let (address, transcript_path) = parse_args()?;
    ensure_parent(&transcript_path)?;
    let app = ProbeApp::new(transcript_path);
    let server = ServerBuilder::default()
        .bind(&address, app)
        .with_context(|| format!("bind M5.0 ABCI probe at {address}"))?;
    println!("READY {}", server.local_addr());
    io::stdout().flush().context("flush READY marker")?;
    server.listen().context("serve M5.0 ABCI probe")
}
