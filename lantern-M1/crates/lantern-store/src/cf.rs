/// Logical `RocksDB` column families frozen by the M1 storage contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnFamily {
    /// Schema, identity, height, roots, counts, and `AppHash`.
    Metadata,
    /// Immutable accepted state-transition records.
    Records,
    /// Canonical publication intents retained for audit and proof serving.
    IntentArchive,
    /// Latest-state authenticated-map nodes (owned by M2).
    LatestTreeNodes,
    /// Append-only MMR nodes (owned by M3).
    MmrNodes,
    /// Proof lookup indices derived from committed state.
    ProofIndex,
    /// Replay/idempotency keys and their committed outcomes.
    Idempotency,
    /// Deterministic application and reconfiguration data.
    ConfigReconfiguration,
    /// Snapshot-manifest archive entries.
    SnapshotsManifest,
}

impl ColumnFamily {
    /// All required non-default column families in canonical order.
    pub const ALL: [Self; 9] = [
        Self::Metadata,
        Self::Records,
        Self::IntentArchive,
        Self::LatestTreeNodes,
        Self::MmrNodes,
        Self::ProofIndex,
        Self::Idempotency,
        Self::ConfigReconfiguration,
        Self::SnapshotsManifest,
    ];

    /// Returns the stable on-disk name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Records => "records",
            Self::IntentArchive => "intent_archive",
            Self::LatestTreeNodes => "latest_tree_nodes",
            Self::MmrNodes => "mmr_nodes",
            Self::ProofIndex => "proof_index",
            Self::Idempotency => "idempotency",
            Self::ConfigReconfiguration => "config_reconfiguration",
            Self::SnapshotsManifest => "snapshots_manifest",
        }
    }
}

/// Required non-default column-family names in canonical order.
pub const REQUIRED_COLUMN_FAMILY_NAMES: [&str; 9] = [
    "metadata",
    "records",
    "intent_archive",
    "latest_tree_nodes",
    "mmr_nodes",
    "proof_index",
    "idempotency",
    "config_reconfiguration",
    "snapshots_manifest",
];
