use std::collections::BTreeMap;

use lantern_history::{HistoryLog, empty_history_root};
use lantern_latest_map::{LatestMap, LatestMutationV1, empty_latest_root};
use lantern_store::{
    BlockStore, ColumnFamily, CommitMetadataV1, CommitReceipt, Durability, ReadStore, StoreBatch,
    read_commit_metadata,
};
use lantern_types::{
    AppStateCommitmentV1, CaStateV1, CaStatusV1, ControlActionV1, DomainV1, Hash32, HeadBodyV1,
    HistoryEventTypeV1, HistoryRecordV1, PROTOCOL_VERSION_V1, StateConfigV1, StateTransactionV1,
    TimestampV1, TransactionResultCodeV1, TransactionResultV1, WireObject, app_hash, ca_state_hash,
    control_event_id, hash_with_domain, head_id, history_record_digest, manifest_hash,
    state_config_hash, state_transaction_id, transaction_result_digest, verify_control_event,
};

use crate::{
    Error, PublicationAuthorizationInput, PublicationAuthorizer, Result,
    storage::{
        IdempotencyEntry, PersistentState, Preauthorization, STATE_CONFIG_KEY, archive_key,
        ca_state_key, ca_version_key, control_archive_key, encode_idempotency,
        encode_preauthorization, head_key, idempotency_key, manifest_key, preauth_key,
        read_ca_state, read_config, read_idempotency, read_persistent, read_preauthorization,
        record_key,
    },
};

const RECORD_FLAG_PUBLICATION_AUTHORIZED: u16 = 0x0001;
const RECORD_FLAG_CONTROL_AUTHORIZED: u16 = 0x0002;

/// Deterministic application-state executor over one consistent M1 read view.
pub struct StateMachine<'a, S: ReadStore + ?Sized, A: PublicationAuthorizer + ?Sized> {
    store: &'a S,
    authorizer: &'a A,
    config: StateConfigV1,
    config_hash: Hash32,
}

impl<'a, S: ReadStore + ?Sized, A: PublicationAuthorizer + ?Sized> StateMachine<'a, S, A> {
    /// Binds the state machine to a read view and immutable configuration.
    ///
    /// # Errors
    ///
    /// Rejects an invalid configuration or a hash/encoding failure.
    pub fn new(store: &'a S, authorizer: &'a A, config: StateConfigV1) -> Result<Self> {
        config.validate()?;
        let config_hash = state_config_hash(&config)?;
        Ok(Self {
            store,
            authorizer,
            config,
            config_hash,
        })
    }

    /// Returns the consensus-critical configuration hash used by M1 identity.
    #[must_use]
    pub const fn config_hash(&self) -> Hash32 {
        self.config_hash
    }

    /// Reads and validates one committed CA state.
    ///
    /// # Errors
    ///
    /// Returns a storage, canonical-decoding, or validation error.
    pub fn ca_state(&self, ca_id: Hash32) -> Result<Option<CaStateV1>> {
        read_ca_state(self.store, ca_id)
    }

    /// Reads the last committed application commitment, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the M1/M2/M3/M4 recovery cross-check fails.
    pub fn committed_app_state(&self) -> Result<Option<AppStateCommitmentV1>> {
        self.recover()
            .map(|state| state.map(|value| value.app_state))
    }

    /// Reads one immutable compact record by its M3 leaf index.
    ///
    /// # Errors
    ///
    /// Returns a storage, canonical-decoding, or validation error.
    pub fn history_record(&self, index: u64) -> Result<Option<HistoryRecordV1>> {
        self.store
            .get(ColumnFamily::Records, &record_key(index))?
            .map(|bytes| HistoryRecordV1::from_canonical_cbor(&bytes).map_err(Error::from))
            .transpose()
    }

    /// Reads a closed head body. M4 stores no QC beside this body.
    ///
    /// # Errors
    ///
    /// Returns a storage, canonical-decoding, or validation error.
    pub fn closed_head(&self, epoch: u64) -> Result<Option<HeadBodyV1>> {
        self.store
            .get(ColumnFamily::Metadata, &head_key(epoch))?
            .map(|bytes| HeadBodyV1::from_canonical_cbor(&bytes).map_err(Error::from))
            .transpose()
    }

    /// Resolves an authenticated CA-version lookup to its M3 leaf index.
    ///
    /// # Errors
    ///
    /// Returns a storage error or rejects a corrupt fixed-width index.
    pub fn history_index_for_ca_version(&self, ca_id: Hash32, version: u64) -> Result<Option<u64>> {
        read_index(
            self.store
                .get(ColumnFamily::ProofIndex, &ca_version_key(ca_id, version))?,
        )
    }

    /// Resolves a publication manifest to its immutable M3 leaf index.
    ///
    /// # Errors
    ///
    /// Returns a storage error or rejects a corrupt fixed-width index.
    pub fn history_index_for_manifest(
        &self,
        ca_id: Hash32,
        exact_manifest_hash: Hash32,
    ) -> Result<Option<u64>> {
        read_index(self.store.get(
            ColumnFamily::ProofIndex,
            &manifest_key(ca_id, exact_manifest_hash),
        )?)
    }

    /// Reads the exact control event and authorization behind a compact
    /// control-history record digest.
    ///
    /// # Errors
    ///
    /// Returns a storage, canonical-decoding, or validation error.
    pub fn control_authorization(
        &self,
        authorization_digest: Hash32,
    ) -> Result<Option<lantern_types::ControlTransactionV1>> {
        self.store
            .get(
                ColumnFamily::Records,
                &control_archive_key(authorization_digest),
            )?
            .map(|bytes| {
                lantern_types::ControlTransactionV1::from_canonical_cbor(&bytes)
                    .map_err(Error::from)
            })
            .transpose()
    }

    /// Executes a successor block without making any write visible.
    ///
    /// Epochs that ended before `consensus_time` close against the committed
    /// pre-block roots. The returned value can only become visible through its
    /// consuming [`PreparedBlock::commit`] method.
    ///
    /// # Errors
    ///
    /// Rejects non-successor height/time, excessive non-empty catch-up,
    /// invalid authorization/transitions, corrupt recovery state, limits, or
    /// any M0–M3 preparation error.
    #[allow(clippy::too_many_lines)]
    pub fn prepare_block(
        &self,
        app_height: u64,
        consensus_time: TimestampV1,
        transactions: &[StateTransactionV1],
    ) -> Result<PreparedBlock> {
        consensus_time.validate()?;
        let prior = self.recover()?;
        let expected_height = prior
            .as_ref()
            .map_or(1, |state| state.app_state.app_height.saturating_add(1));
        if app_height != expected_height {
            return Err(Error::InvalidInput(format!(
                "application height is {app_height}, expected {expected_height}"
            )));
        }
        if consensus_time < self.config.genesis_time {
            return Err(Error::InvalidInput(
                "consensus time precedes configured genesis".into(),
            ));
        }
        if prior
            .as_ref()
            .is_some_and(|state| consensus_time < state.last_block_time)
        {
            return Err(Error::InvalidInput(
                "consensus time regressed from the committed block".into(),
            ));
        }
        let transaction_count = u32::try_from(transactions.len())
            .map_err(|_| Error::InvalidInput("block transaction count exceeds u32".into()))?;
        let current_epoch = epoch_at(&self.config, consensus_time)?;
        let mut open_epoch = prior.as_ref().map_or(0, |state| state.open_epoch);
        let due = current_epoch.saturating_sub(open_epoch);
        if due > u64::from(self.config.max_epoch_catchup) && transaction_count != 0 {
            return Err(Error::EpochBacklog {
                required: due,
                limit: self.config.max_epoch_catchup,
            });
        }
        let close_count = due.min(u64::from(self.config.max_epoch_catchup));

        let pre_latest_root = prior.as_ref().map_or_else(empty_latest_root, |state| {
            state.app_state.pending_latest_root
        });
        let pre_history_root = prior.as_ref().map_or(empty_history_root()?, |state| {
            state.app_state.pending_history_root
        });
        let pre_history_length = prior
            .as_ref()
            .map_or(0, |state| state.app_state.history_length);
        let mut latest_entry_count = prior
            .as_ref()
            .map_or(0, |state| state.app_state.latest_entry_count);
        let mut last_closed_epoch = prior
            .as_ref()
            .and_then(|state| state.app_state.last_closed_epoch);
        let mut last_closed_head_id = prior
            .as_ref()
            .and_then(|state| state.app_state.closed_head_id);
        let empty_bundle = empty_accumulator(DomainV1::EpochBundle)?;
        let mut epoch_bundle_hash = prior
            .as_ref()
            .map_or(empty_bundle, |state| state.epoch_bundle_hash);
        let mut epoch_admitted_count = prior.as_ref().map_or(0, |state| state.epoch_admitted_count);
        let mut closed_heads = Vec::with_capacity(usize::try_from(close_count).unwrap_or(0));

        for _ in 0..close_count {
            let (epoch_start, epoch_end) = epoch_bounds(&self.config, open_epoch)?;
            let head = HeadBodyV1 {
                protocol_version: PROTOCOL_VERSION_V1,
                network_id: self.config.network_id.clone(),
                epoch: open_epoch,
                epoch_start,
                epoch_end,
                issued_at: consensus_time,
                latest_root: pre_latest_root,
                history_root: pre_history_root,
                previous_head_id: last_closed_head_id,
                bundle_hash: epoch_bundle_hash,
                history_length: pre_history_length,
                latest_entry_count,
                key_epoch: self.config.key_epoch,
            };
            head.validate()?;
            let id = head_id(&head)?;
            last_closed_epoch = Some(open_epoch);
            last_closed_head_id = Some(id);
            closed_heads.push((head, id));
            open_epoch = open_epoch
                .checked_add(1)
                .ok_or_else(|| Error::InvalidInput("epoch number exhausted".into()))?;
            epoch_bundle_hash = empty_bundle;
            epoch_admitted_count = 0;
        }

        if transaction_count != 0 && open_epoch != current_epoch {
            return Err(Error::CorruptState(
                "non-empty block did not catch up to its admission epoch".into(),
            ));
        }

        let history = HistoryLog::new(self.store);
        let history_state = history.current_state()?;
        if history_state.leaf_count != pre_history_length {
            return Err(Error::CorruptState(
                "M3 leaf count changed after recovery cross-check".into(),
            ));
        }
        let mut working = WorkingState::new(self.store);
        let mut accepted = Vec::<AcceptedTransition>::new();
        let mut results = Vec::with_capacity(transactions.len());
        let mut results_hash = prior
            .as_ref()
            .map_or(empty_accumulator(DomainV1::TransactionResults)?, |state| {
                state.app_state.transaction_results_hash
            });
        let mut admin_registry_hash = prior
            .as_ref()
            .map_or(empty_accumulator(DomainV1::AdminRegistry)?, |state| {
                state.app_state.ca_admin_registry_hash
            });

        for (position, transaction) in transactions.iter().enumerate() {
            transaction.validate()?;
            let transaction_id = state_transaction_id(transaction)?;
            let transaction_index = u32::try_from(position)
                .map_err(|_| Error::InvalidInput("transaction index exceeds u32".into()))?;
            let existing = working.idempotency(transaction.ca_id(), transaction.nonce())?;
            let (result, transition) = if let Some(existing) = existing {
                if existing.transaction_id == transaction_id {
                    (existing.result, None)
                } else {
                    (
                        rejected_result(
                            transaction_id,
                            app_height,
                            transaction_index,
                            transaction.ca_id(),
                            TransactionResultCodeV1::RejectedIdempotencyConflict,
                        ),
                        None,
                    )
                }
            } else {
                let decision = self.process_transaction(
                    &mut working,
                    transaction,
                    transaction_id,
                    open_epoch,
                    consensus_time,
                )?;
                let (result, transition) = match decision {
                    Err(code) => (
                        rejected_result(
                            transaction_id,
                            app_height,
                            transaction_index,
                            transaction.ca_id(),
                            code,
                        ),
                        None,
                    ),
                    Ok(accepted_transition) => (
                        TransactionResultV1 {
                            protocol_version: PROTOCOL_VERSION_V1,
                            transaction_id,
                            app_height,
                            transaction_index,
                            code: TransactionResultCodeV1::Admitted,
                            ca_id: transaction.ca_id(),
                            history_index: Some(
                                pre_history_length
                                    + u64::try_from(accepted.len()).unwrap_or(u64::MAX),
                            ),
                            ca_version: Some(accepted_transition.record.version),
                            admission_epoch: Some(open_epoch),
                        },
                        Some(accepted_transition),
                    ),
                };
                working.put_idempotency(
                    transaction.ca_id(),
                    transaction.nonce(),
                    IdempotencyEntry {
                        transaction_id,
                        result: result.clone(),
                    },
                );
                (result, transition)
            };

            if let Some(transition) = transition {
                epoch_bundle_hash =
                    accumulate(DomainV1::EpochBundle, epoch_bundle_hash, transaction_id)?;
                epoch_admitted_count = epoch_admitted_count
                    .checked_add(1)
                    .ok_or_else(|| Error::InvalidInput("epoch admitted count overflow".into()))?;
                if transition.created_ca {
                    latest_entry_count = latest_entry_count
                        .checked_add(1)
                        .ok_or_else(|| Error::InvalidInput("latest entry count overflow".into()))?;
                }
                if transition.control_event {
                    admin_registry_hash =
                        accumulate(DomainV1::AdminRegistry, admin_registry_hash, transaction_id)?;
                }
                accepted.push(transition);
            }
            results_hash = accumulate(
                DomainV1::TransactionResults,
                results_hash,
                transaction_result_digest(&result)?,
            )?;
            results.push(result);
        }

        let latest_mutations = working
            .ca_updates
            .values()
            .map(|state| {
                state
                    .latest_value()
                    .to_canonical_cbor()
                    .map(|value| LatestMutationV1::set(state.ca_id, value))
            })
            .collect::<lantern_types::Result<Vec<_>>>()?;
        let latest =
            LatestMap::new(self.store).prepare_update(app_height - 1, &latest_mutations)?;
        let record_bytes = accepted
            .iter()
            .map(|transition| transition.record.to_canonical_cbor())
            .collect::<lantern_types::Result<Vec<_>>>()?;
        let history_append = history.prepare_append(&record_bytes)?;
        let app_state = AppStateCommitmentV1 {
            protocol_version: PROTOCOL_VERSION_V1,
            network_id: self.config.network_id.clone(),
            app_height,
            pending_latest_root: latest.root(),
            pending_history_root: history_append.root(),
            history_length: history_append.end_size(),
            latest_entry_count,
            last_closed_epoch,
            closed_head_id: last_closed_head_id,
            validator_config_hash: self.config.validator_config_hash,
            ca_admin_registry_hash: admin_registry_hash,
            governance_config_hash: self.config.governance_config_hash,
            transaction_results_hash: results_hash,
            schema_config_hash: self.config_hash,
        };
        app_state.validate()?;
        let computed_app_hash = app_hash(&app_state)?;
        let metadata = CommitMetadataV1 {
            app_height,
            app_hash: computed_app_hash,
            latest_root: latest.root(),
            history_root: history_append.root(),
            history_size: history_append.end_size(),
            last_closed_epoch,
            last_closed_head_id,
            validator_config_hash: self.config.validator_config_hash,
            config_hash: self.config_hash,
        };
        let persistent = PersistentState {
            last_block_time: consensus_time,
            open_epoch,
            epoch_bundle_hash,
            epoch_admitted_count,
            app_state: app_state.clone(),
        };
        let mut batch = StoreBatch::new();
        latest.append_to(&mut batch)?;
        history_append.append_to(&mut batch)?;
        self.append_m4_writes(
            &mut batch,
            &working,
            &M4WritePlan {
                accepted: &accepted,
                closed_heads: &closed_heads,
                history_start: pre_history_length,
                persistent: &persistent,
                initialize_config: prior.is_none(),
            },
        )?;

        Ok(PreparedBlock {
            batch,
            metadata,
            app_state,
            app_hash: computed_app_hash,
            results,
            closed_heads,
            latest_mutations: latest.stats().mutations,
            appended_records: history_append.stats().records,
        })
    }

    fn process_transaction(
        &self,
        working: &mut WorkingState<'_, S>,
        transaction: &StateTransactionV1,
        transaction_id: Hash32,
        admission_epoch: u64,
        consensus_time: TimestampV1,
    ) -> Result<TransitionDecision> {
        if transaction.network_id() != &self.config.network_id {
            return Ok(Err(TransactionResultCodeV1::RejectedNetwork));
        }
        match transaction {
            StateTransactionV1::Publication(publication) => {
                let intent_cbor = publication.intent.to_canonical_cbor()?;
                let Ok(authorization) = self.authorizer.authorize(PublicationAuthorizationInput {
                    intent: &publication.intent,
                    intent_cbor: &intent_cbor,
                    exact_manifest_der: &publication.exact_manifest_der,
                    intent_signature: &publication.intent_signature,
                    ee_certificate_chain: &publication.ee_certificate_chain,
                    consensus_time,
                }) else {
                    return Ok(Err(TransactionResultCodeV1::RejectedAuthorization));
                };
                if authorization.derived_ca_id != publication.intent.ca_id
                    || authorization.manifest_number != publication.intent.manifest_number
                    || authorization.manifest_hash != publication.intent.manifest_hash
                    || authorization.signature_algorithm != publication.intent.signature_algorithm
                    || manifest_hash(&publication.exact_manifest_der)
                        != publication.intent.manifest_hash
                {
                    return Ok(Err(TransactionResultCodeV1::RejectedAuthorization));
                }
                let Some(mut state) = working.ca_state(publication.intent.ca_id)? else {
                    return Ok(Err(TransactionResultCodeV1::RejectedState));
                };
                if state.status != CaStatusV1::Enabled
                    || publication.intent.previous_manifest_hash != state.effective_manifest_hash
                    || state
                        .expected_manifest_hash
                        .is_some_and(|expected| expected != publication.intent.manifest_hash)
                    || state
                        .effective_manifest_number
                        .is_some_and(|number| publication.intent.manifest_number <= number)
                {
                    return Ok(Err(TransactionResultCodeV1::RejectedState));
                }
                let version = state
                    .last_version
                    .checked_add(1)
                    .ok_or_else(|| Error::InvalidInput("CA version exhausted".into()))?;
                let record = HistoryRecordV1 {
                    protocol_version: PROTOCOL_VERSION_V1,
                    network_id: self.config.network_id.clone(),
                    ca_id: publication.intent.ca_id,
                    version,
                    event_type: HistoryEventTypeV1::Publish,
                    manifest_number: Some(publication.intent.manifest_number),
                    manifest_hash: Some(publication.intent.manifest_hash),
                    previous_manifest_hash: publication.intent.previous_manifest_hash,
                    admission_epoch,
                    flags: RECORD_FLAG_PUBLICATION_AUTHORIZED,
                    authorization_digest: transaction_id,
                };
                let digest = history_record_digest(&record)?;
                state.predecessor_manifest_number = state.effective_manifest_number;
                state.predecessor_manifest_hash = state.effective_manifest_hash;
                state.predecessor_intent_digest = state.effective_intent_digest;
                state.effective_manifest_number = Some(publication.intent.manifest_number);
                state.effective_manifest_hash = Some(publication.intent.manifest_hash);
                state.effective_intent_digest = Some(transaction_id);
                state.expected_manifest_hash = None;
                state.last_version = version;
                state.latest_record_digest = digest;
                state.latest_event_type = HistoryEventTypeV1::Publish;
                state.latest_admission_epoch = admission_epoch;
                state.validate()?;
                working.ca_updates.insert(state.ca_id, state);
                Ok(Ok(AcceptedTransition {
                    record,
                    authorization_archive: AuthorizationArchive::Publication(
                        transaction.to_canonical_cbor()?,
                    ),
                    created_ca: false,
                    control_event: false,
                }))
            }
            StateTransactionV1::Control(control) => {
                self.process_control(working, control, admission_epoch)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn process_control(
        &self,
        working: &mut WorkingState<'_, S>,
        control: &lantern_types::ControlTransactionV1,
        admission_epoch: u64,
    ) -> Result<TransitionDecision> {
        let existing = working.ca_state(control.event.ca_id)?;
        if existing
            .as_ref()
            .is_some_and(|state| state.status == CaStatusV1::Terminal)
        {
            return Ok(Err(TransactionResultCodeV1::RejectedState));
        }
        let (verification_key, created_ca) = match (&existing, &control.event.action) {
            (
                None,
                ControlActionV1::Enable {
                    initial_admin_key, ..
                },
            ) => {
                if control.event.admin_sequence != 1 || control.event.previous_state_hash.is_some()
                {
                    return Ok(Err(TransactionResultCodeV1::RejectedState));
                }
                if let Some(preauthorized) = working.preauthorization(control.event.ca_id)?
                    && preauthorized.admin_key != *initial_admin_key
                {
                    return Ok(Err(TransactionResultCodeV1::RejectedState));
                }
                (*initial_admin_key, true)
            }
            (
                Some(state),
                ControlActionV1::Enable {
                    initial_admin_key, ..
                },
            ) if state.status == CaStatusV1::Disabled
                && state.admin_public_key == *initial_admin_key =>
            {
                (state.admin_public_key, false)
            }
            (Some(state), ControlActionV1::Enable { .. }) => {
                let _ = state;
                return Ok(Err(TransactionResultCodeV1::RejectedState));
            }
            (Some(state), _) => (state.admin_public_key, false),
            (None, _) => return Ok(Err(TransactionResultCodeV1::RejectedState)),
        };
        if verify_control_event(&control.event, verification_key, &control.authorization).is_err() {
            return Ok(Err(TransactionResultCodeV1::RejectedAuthorization));
        }
        if let Some(state) = &existing
            && (control.event.admin_sequence != state.admin_sequence.saturating_add(1)
                || control.event.previous_state_hash != Some(ca_state_hash(state)?))
        {
            return Ok(Err(TransactionResultCodeV1::RejectedState));
        }

        let version = existing
            .as_ref()
            .map_or(1, |state| state.last_version.saturating_add(1));
        if version == 0 {
            return Err(Error::InvalidInput("CA version exhausted".into()));
        }
        let authorization_digest = control_event_id(&control.event)?;
        let mut state = existing.clone().unwrap_or_else(|| CaStateV1 {
            protocol_version: PROTOCOL_VERSION_V1,
            network_id: self.config.network_id.clone(),
            ca_id: control.event.ca_id,
            status: CaStatusV1::Enabled,
            admin_public_key: verification_key,
            admin_sequence: control.event.admin_sequence,
            last_version: version,
            latest_record_digest: Hash32::new([0; 32]),
            latest_event_type: HistoryEventTypeV1::Enable,
            latest_admission_epoch: admission_epoch,
            effective_manifest_number: None,
            effective_manifest_hash: None,
            effective_intent_digest: None,
            predecessor_manifest_number: None,
            predecessor_manifest_hash: None,
            predecessor_intent_digest: None,
            expected_manifest_hash: None,
            rollover_link: None,
        });
        state.admin_sequence = control.event.admin_sequence;
        state.last_version = version;
        state.latest_admission_epoch = admission_epoch;
        let (event_type, manifest_number, manifest_hash_value, previous_manifest_hash) =
            match &control.event.action {
                ControlActionV1::Enable {
                    initial_manifest_hash,
                    initial_admin_key,
                } => {
                    state.status = CaStatusV1::Enabled;
                    state.admin_public_key = *initial_admin_key;
                    state.expected_manifest_hash = Some(*initial_manifest_hash);
                    state.rollover_link = None;
                    working.set_preauthorization(control.event.ca_id, None)?;
                    (HistoryEventTypeV1::Enable, None, None, None)
                }
                ControlActionV1::Disable { .. } if state.status == CaStatusV1::Enabled => {
                    state.status = CaStatusV1::Disabled;
                    state.expected_manifest_hash = None;
                    (HistoryEventTypeV1::Disable, None, None, None)
                }
                ControlActionV1::Cancel {
                    target_version,
                    target_manifest_hash,
                    restore_manifest_hash,
                    ..
                } if state.status == CaStatusV1::Enabled
                    && state.latest_event_type == HistoryEventTypeV1::Publish
                    && *target_version == version - 1
                    && Some(*target_manifest_hash) == state.effective_manifest_hash
                    && Some(*restore_manifest_hash) == state.predecessor_manifest_hash =>
                {
                    let target_number = state.effective_manifest_number;
                    state.effective_manifest_number = state.predecessor_manifest_number;
                    state.effective_manifest_hash = state.predecessor_manifest_hash;
                    state.effective_intent_digest = state.predecessor_intent_digest;
                    state.predecessor_manifest_number = None;
                    state.predecessor_manifest_hash = None;
                    state.predecessor_intent_digest = None;
                    (
                        HistoryEventTypeV1::Cancel,
                        target_number,
                        Some(*target_manifest_hash),
                        Some(*restore_manifest_hash),
                    )
                }
                ControlActionV1::Rollover {
                    successor_ca_id,
                    successor_admin_key,
                } if matches!(state.status, CaStatusV1::Enabled | CaStatusV1::Disabled)
                    && working.ca_state(*successor_ca_id)?.is_none()
                    && working.preauthorization(*successor_ca_id)?.is_none() =>
                {
                    state.status = CaStatusV1::Terminal;
                    state.expected_manifest_hash = None;
                    state.rollover_link = Some(*successor_ca_id);
                    working.set_preauthorization(
                        *successor_ca_id,
                        Some(Preauthorization {
                            admin_key: *successor_admin_key,
                            predecessor_ca_id: state.ca_id,
                        }),
                    )?;
                    (HistoryEventTypeV1::Rollover, None, None, None)
                }
                ControlActionV1::Terminal { .. }
                    if matches!(state.status, CaStatusV1::Enabled | CaStatusV1::Disabled) =>
                {
                    state.status = CaStatusV1::Terminal;
                    state.expected_manifest_hash = None;
                    state.rollover_link = None;
                    (HistoryEventTypeV1::Terminal, None, None, None)
                }
                _ => return Ok(Err(TransactionResultCodeV1::RejectedState)),
            };
        let record = HistoryRecordV1 {
            protocol_version: PROTOCOL_VERSION_V1,
            network_id: self.config.network_id.clone(),
            ca_id: control.event.ca_id,
            version,
            event_type,
            manifest_number,
            manifest_hash: manifest_hash_value,
            previous_manifest_hash,
            admission_epoch,
            flags: RECORD_FLAG_CONTROL_AUTHORIZED,
            authorization_digest,
        };
        state.latest_record_digest = history_record_digest(&record)?;
        state.latest_event_type = event_type;
        state.validate()?;
        working.ca_updates.insert(state.ca_id, state);
        Ok(Ok(AcceptedTransition {
            record,
            authorization_archive: AuthorizationArchive::Control(control.to_canonical_cbor()?),
            created_ca,
            control_event: true,
        }))
    }

    fn append_m4_writes(
        &self,
        batch: &mut StoreBatch,
        working: &WorkingState<'_, S>,
        plan: &M4WritePlan<'_>,
    ) -> Result<()> {
        for (offset, transition) in plan.accepted.iter().enumerate() {
            let index = plan
                .history_start
                .checked_add(u64::try_from(offset).map_err(|_| {
                    Error::InvalidInput("accepted transition index exceeds u64".into())
                })?)
                .ok_or_else(|| Error::InvalidInput("history index overflow".into()))?;
            let record = transition.record.to_canonical_cbor()?;
            batch.put(ColumnFamily::Records, record_key(index), &record)?;
            batch.put(
                ColumnFamily::ProofIndex,
                ca_version_key(transition.record.ca_id, transition.record.version),
                index.to_be_bytes(),
            )?;
            if transition.record.event_type == HistoryEventTypeV1::Publish
                && let Some(manifest) = transition.record.manifest_hash
            {
                batch.put(
                    ColumnFamily::ProofIndex,
                    manifest_key(transition.record.ca_id, manifest),
                    index.to_be_bytes(),
                )?;
            }
            match &transition.authorization_archive {
                AuthorizationArchive::Publication(transaction_cbor) => batch.put(
                    ColumnFamily::IntentArchive,
                    archive_key(transition.record.authorization_digest),
                    transaction_cbor,
                )?,
                AuthorizationArchive::Control(transaction_cbor) => batch.put(
                    ColumnFamily::Records,
                    control_archive_key(transition.record.authorization_digest),
                    transaction_cbor,
                )?,
            }
        }
        for state in working.ca_updates.values() {
            batch.put(
                ColumnFamily::ConfigReconfiguration,
                ca_state_key(state.ca_id),
                state.to_canonical_cbor()?,
            )?;
        }
        for (ca_id, value) in &working.preauth_updates {
            match value {
                Some(value) => batch.put(
                    ColumnFamily::ConfigReconfiguration,
                    preauth_key(*ca_id),
                    encode_preauthorization(*value),
                )?,
                None if working
                    .preauth_original
                    .get(ca_id)
                    .is_some_and(Option::is_some) =>
                {
                    batch.delete(ColumnFamily::ConfigReconfiguration, preauth_key(*ca_id))?;
                }
                None => {}
            }
        }
        for ((ca_id, nonce), entry) in &working.idempotency_updates {
            batch.put(
                ColumnFamily::Idempotency,
                idempotency_key(*ca_id, *nonce),
                encode_idempotency(entry)?,
            )?;
        }
        for (head, _) in plan.closed_heads {
            batch.put(
                ColumnFamily::Metadata,
                head_key(head.epoch),
                head.to_canonical_cbor()?,
            )?;
        }
        if plan.initialize_config {
            batch.put(
                ColumnFamily::ConfigReconfiguration,
                STATE_CONFIG_KEY,
                self.config.to_canonical_cbor()?,
            )?;
        }
        batch.put(
            ColumnFamily::ConfigReconfiguration,
            crate::storage::GLOBAL_STATE_KEY,
            plan.persistent.encode()?,
        )?;
        Ok(())
    }

    fn recover(&self) -> Result<Option<PersistentState>> {
        let metadata = read_commit_metadata(self.store)?;
        let persistent = read_persistent(self.store)?;
        let latest = LatestMap::new(self.store);
        let latest_version = latest.latest_version()?;
        let history = HistoryLog::new(self.store).current_state()?;
        match (metadata, persistent) {
            (None, None) => {
                if latest_version.is_some()
                    || history.leaf_count != 0
                    || read_config(self.store)?.is_some()
                {
                    return Err(Error::CorruptState(
                        "uncommitted store contains initialized M2/M3/M4 state".into(),
                    ));
                }
                Ok(None)
            }
            (Some(metadata), Some(persistent)) => {
                let stored_config = read_config(self.store)?.ok_or_else(|| {
                    Error::CorruptState("committed M4 state has no configuration".into())
                })?;
                if stored_config != self.config.to_canonical_cbor()? {
                    return Err(Error::CorruptState(
                        "stored M4 configuration differs from requested configuration".into(),
                    ));
                }
                let app = &persistent.app_state;
                if metadata.config_hash != self.config_hash
                    || app.schema_config_hash != self.config_hash
                    || metadata.app_height != app.app_height
                    || metadata.app_hash != app_hash(app)?
                    || metadata.latest_root != app.pending_latest_root
                    || metadata.history_root != app.pending_history_root
                    || metadata.history_size != app.history_length
                    || metadata.last_closed_epoch != app.last_closed_epoch
                    || metadata.last_closed_head_id != app.closed_head_id
                    || metadata.validator_config_hash != app.validator_config_hash
                    || latest_version != Some(metadata.app_height - 1)
                    || latest.root(metadata.app_height - 1)? != metadata.latest_root
                    || history.root != metadata.history_root
                    || history.leaf_count != metadata.history_size
                {
                    return Err(Error::CorruptState(
                        "M1/M2/M3/M4 recovery cross-check failed".into(),
                    ));
                }
                Ok(Some(persistent))
            }
            _ => Err(Error::CorruptState(
                "M1 commit metadata and M4 global state presence differ".into(),
            )),
        }
    }
}

/// Fully staged block. Dropping this value has no storage effect.
pub struct PreparedBlock {
    batch: StoreBatch,
    metadata: CommitMetadataV1,
    app_state: AppStateCommitmentV1,
    app_hash: Hash32,
    results: Vec<TransactionResultV1>,
    closed_heads: Vec<(HeadBodyV1, Hash32)>,
    latest_mutations: usize,
    appended_records: usize,
}

impl PreparedBlock {
    #[must_use]
    pub const fn app_hash(&self) -> Hash32 {
        self.app_hash
    }

    #[must_use]
    pub const fn app_state(&self) -> &AppStateCommitmentV1 {
        &self.app_state
    }

    #[must_use]
    pub fn results(&self) -> &[TransactionResultV1] {
        &self.results
    }

    #[must_use]
    pub fn closed_heads(&self) -> &[(HeadBodyV1, Hash32)] {
        &self.closed_heads
    }

    #[must_use]
    pub const fn latest_mutations(&self) -> usize {
        self.latest_mutations
    }

    #[must_use]
    pub const fn appended_records(&self) -> usize {
        self.appended_records
    }

    /// Returns the exact typed metadata that will be committed with the batch.
    #[must_use]
    pub const fn metadata(&self) -> &CommitMetadataV1 {
        &self.metadata
    }

    /// Atomically persists the M2, M3, M4 and typed M1 metadata writes.
    ///
    /// # Errors
    ///
    /// Returns an M1 error if successor validation or the atomic `RocksDB` write
    /// fails. The prepared value is consumed and cannot be partially retried.
    pub fn commit<S: BlockStore>(self, store: &S, durability: Durability) -> Result<CommitReceipt> {
        Ok(store.commit_block(self.batch, &self.metadata, durability)?)
    }
}

#[derive(Debug)]
struct AcceptedTransition {
    record: HistoryRecordV1,
    authorization_archive: AuthorizationArchive,
    created_ca: bool,
    control_event: bool,
}

#[derive(Debug)]
enum AuthorizationArchive {
    Publication(Vec<u8>),
    Control(Vec<u8>),
}

struct M4WritePlan<'a> {
    accepted: &'a [AcceptedTransition],
    closed_heads: &'a [(HeadBodyV1, Hash32)],
    history_start: u64,
    persistent: &'a PersistentState,
    initialize_config: bool,
}

type TransitionDecision = std::result::Result<AcceptedTransition, TransactionResultCodeV1>;

struct WorkingState<'a, S: ReadStore + ?Sized> {
    store: &'a S,
    ca_updates: BTreeMap<Hash32, CaStateV1>,
    preauth_updates: BTreeMap<Hash32, Option<Preauthorization>>,
    preauth_original: BTreeMap<Hash32, Option<Preauthorization>>,
    idempotency_updates: BTreeMap<(Hash32, lantern_types::Nonce16), IdempotencyEntry>,
}

impl<'a, S: ReadStore + ?Sized> WorkingState<'a, S> {
    fn new(store: &'a S) -> Self {
        Self {
            store,
            ca_updates: BTreeMap::new(),
            preauth_updates: BTreeMap::new(),
            preauth_original: BTreeMap::new(),
            idempotency_updates: BTreeMap::new(),
        }
    }

    fn ca_state(&self, ca_id: Hash32) -> Result<Option<CaStateV1>> {
        self.ca_updates
            .get(&ca_id)
            .cloned()
            .map_or_else(|| read_ca_state(self.store, ca_id), |value| Ok(Some(value)))
    }

    fn preauthorization(&mut self, ca_id: Hash32) -> Result<Option<Preauthorization>> {
        if let Some(value) = self.preauth_updates.get(&ca_id) {
            return Ok(*value);
        }
        let value = read_preauthorization(self.store, ca_id)?;
        self.preauth_original.entry(ca_id).or_insert(value);
        Ok(value)
    }

    fn set_preauthorization(
        &mut self,
        ca_id: Hash32,
        value: Option<Preauthorization>,
    ) -> Result<()> {
        let _ = self.preauthorization(ca_id)?;
        self.preauth_updates.insert(ca_id, value);
        Ok(())
    }

    fn idempotency(
        &self,
        ca_id: Hash32,
        nonce: lantern_types::Nonce16,
    ) -> Result<Option<IdempotencyEntry>> {
        self.idempotency_updates
            .get(&(ca_id, nonce))
            .cloned()
            .map_or_else(
                || read_idempotency(self.store, ca_id, nonce),
                |value| Ok(Some(value)),
            )
    }

    fn put_idempotency(
        &mut self,
        ca_id: Hash32,
        nonce: lantern_types::Nonce16,
        entry: IdempotencyEntry,
    ) {
        self.idempotency_updates.insert((ca_id, nonce), entry);
    }
}

fn rejected_result(
    transaction_id: Hash32,
    app_height: u64,
    transaction_index: u32,
    ca_id: Hash32,
    code: TransactionResultCodeV1,
) -> TransactionResultV1 {
    TransactionResultV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        transaction_id,
        app_height,
        transaction_index,
        code,
        ca_id,
        history_index: None,
        ca_version: None,
        admission_epoch: None,
    }
}

fn empty_accumulator(domain: DomainV1) -> Result<Hash32> {
    Ok(hash_with_domain(domain, &[])?)
}

fn accumulate(domain: DomainV1, previous: Hash32, item: Hash32) -> Result<Hash32> {
    let mut payload = [0_u8; 64];
    payload[..32].copy_from_slice(previous.as_bytes());
    payload[32..].copy_from_slice(item.as_bytes());
    Ok(hash_with_domain(domain, &payload)?)
}

fn timestamp_nanos(timestamp: TimestampV1) -> i128 {
    i128::from(timestamp.seconds) * 1_000_000_000 + i128::from(timestamp.nanos)
}

pub(crate) fn epoch_at(config: &StateConfigV1, time: TimestampV1) -> Result<u64> {
    let elapsed = timestamp_nanos(time) - timestamp_nanos(config.genesis_time);
    if elapsed < 0 {
        return Err(Error::InvalidInput("time precedes genesis".into()));
    }
    let delta = i128::from(config.epoch_profile.delta_seconds()) * 1_000_000_000;
    u64::try_from(elapsed / delta)
        .map_err(|_| Error::InvalidInput("epoch number exceeds u64".into()))
}

fn epoch_bounds(config: &StateConfigV1, epoch: u64) -> Result<(TimestampV1, TimestampV1)> {
    let delta = config.epoch_profile.delta_seconds();
    let start_offset = epoch
        .checked_mul(delta)
        .ok_or_else(|| Error::InvalidInput("epoch start overflow".into()))?;
    let end_offset = start_offset
        .checked_add(delta)
        .ok_or_else(|| Error::InvalidInput("epoch end overflow".into()))?;
    let start_seconds = config
        .genesis_time
        .seconds
        .checked_add(
            i64::try_from(start_offset)
                .map_err(|_| Error::InvalidInput("epoch start does not fit timestamp".into()))?,
        )
        .ok_or_else(|| Error::InvalidInput("epoch start timestamp overflow".into()))?;
    let end_seconds = config
        .genesis_time
        .seconds
        .checked_add(
            i64::try_from(end_offset)
                .map_err(|_| Error::InvalidInput("epoch end does not fit timestamp".into()))?,
        )
        .ok_or_else(|| Error::InvalidInput("epoch end timestamp overflow".into()))?;
    Ok((
        TimestampV1::new(start_seconds, config.genesis_time.nanos)?,
        TimestampV1::new(end_seconds, config.genesis_time.nanos)?,
    ))
}

fn read_index(bytes: Option<Vec<u8>>) -> Result<Option<u64>> {
    bytes
        .map(|bytes| {
            let array: [u8; 8] = bytes.try_into().map_err(|bytes: Vec<u8>| {
                Error::CorruptState(format!("proof index has {} bytes, expected 8", bytes.len()))
            })?;
            Ok(u64::from_be_bytes(array))
        })
        .transpose()
}
