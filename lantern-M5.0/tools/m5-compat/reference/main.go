// Command m5-reference generates the M5.0 interoperability fixture using the
// official CometBFT Go types. It must be run from the root of the pinned
// CometBFT v0.38.23 checkout; generate-reference.sh enforces that precondition.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	"github.com/cometbft/cometbft/types"
	"github.com/cometbft/cometbft/version"
)

const (
	chainID         = "lantern-m5-compat"
	cometTag        = "v0.38.23"
	cometCommit     = "feb2aea4dc271d612129afc958cb844713ec792b"
	rustFamily      = "0.40.4"
	referenceHeight = int64(42)
	referenceRound  = int32(2)
)

type validatorVector struct {
	Index        int    `json:"index"`
	AddressHex   string `json:"address_hex"`
	PublicKeyHex string `json:"public_key_hex"`
	VotingPower  int64  `json:"voting_power"`
	SignBytesHex string `json:"sign_bytes_hex"`
	SignatureHex string `json:"signature_hex"`
}

type fixture struct {
	FormatVersion           uint64            `json:"format_version"`
	ReferenceImplementation string            `json:"reference_implementation"`
	CometBFTTag             string            `json:"cometbft_tag"`
	CometBFTCommit          string            `json:"cometbft_commit"`
	CometBFTSourceVersion   string            `json:"cometbft_source_version"`
	RustFamily              string            `json:"rust_family"`
	ChainID                 string            `json:"chain_id"`
	Height                  int64             `json:"height"`
	Round                   int32             `json:"round"`
	HeaderHashHex           string            `json:"header_hash_hex"`
	ValidatorSetHashHex     string            `json:"validator_set_hash_hex"`
	SignedHeaderProtoHex    string            `json:"signed_header_v0_38_proto_hex"`
	ValidatorSetProtoHex    string            `json:"validator_set_v0_38_proto_hex"`
	SignerBitmapHex         string            `json:"signer_bitmap_lsb0_hex"`
	Validators              []validatorVector `json:"validators"`
}

func fixedHash(label string) []byte {
	return tmhash.Sum([]byte("lantern/m5.0/" + label))
}

func validatorKey(index int) ed25519.PrivKey {
	seed := sha256.Sum256([]byte(fmt.Sprintf("lantern/m5.0/validator/%d", index)))
	return ed25519.GenPrivKeyFromSecret(seed[:])
}

func buildFixture() (*fixture, error) {
	validators := make([]*types.Validator, 0, 4)
	privateByAddress := make(map[string]ed25519.PrivKey, 4)
	for index := 0; index < 4; index++ {
		privateKey := validatorKey(index)
		publicKey := privateKey.PubKey()
		validator := types.NewValidator(publicKey, 1)
		validators = append(validators, validator)
		privateByAddress[hex.EncodeToString(validator.Address)] = privateKey
	}

	validatorSet := types.NewValidatorSet(validators)
	if err := validatorSet.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("validate validator set: %w", err)
	}
	validatorSetHash := validatorSet.Hash()
	header := &types.Header{
		Version: cmtversion.Consensus{
			Block: version.BlockProtocol,
			App:   1,
		},
		ChainID:            chainID,
		Height:             referenceHeight,
		Time:               time.Unix(1_735_689_600, 123_456_789).UTC(),
		LastBlockID:        types.BlockID{Hash: fixedHash("previous-block"), PartSetHeader: types.PartSetHeader{Total: 1, Hash: fixedHash("previous-parts")}},
		LastCommitHash:     fixedHash("last-commit"),
		DataHash:           fixedHash("data"),
		ValidatorsHash:     validatorSetHash,
		NextValidatorsHash: validatorSetHash,
		ConsensusHash:      fixedHash("consensus"),
		AppHash:            fixedHash("app-state-41"),
		LastResultsHash:    fixedHash("last-results"),
		EvidenceHash:       fixedHash("evidence"),
		ProposerAddress:    validatorSet.Proposer.Address,
	}
	if err := header.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("validate header: %w", err)
	}

	blockID := types.BlockID{
		Hash: header.Hash(),
		PartSetHeader: types.PartSetHeader{
			Total: 1,
			Hash:  fixedHash("current-parts"),
		},
	}
	commitSignatures := make([]types.CommitSig, len(validatorSet.Validators))
	vectors := make([]validatorVector, len(validatorSet.Validators))
	for index, validator := range validatorSet.Validators {
		privateKey, ok := privateByAddress[hex.EncodeToString(validator.Address)]
		if !ok {
			return nil, errors.New("validator private key lookup failed")
		}
		vote := &types.Vote{
			Type:             cmtproto.PrecommitType,
			Height:           referenceHeight,
			Round:            referenceRound,
			BlockID:          blockID,
			Timestamp:        time.Unix(1_735_689_610, int64(index)*1_000_000).UTC(),
			ValidatorAddress: validator.Address,
			ValidatorIndex:   int32(index),
		}
		voteProto := vote.ToProto()
		signBytes := types.VoteSignBytes(chainID, voteProto)
		signature, err := privateKey.Sign(signBytes)
		if err != nil {
			return nil, fmt.Errorf("sign validator %d vote: %w", index, err)
		}
		vote.Signature = signature
		commitSignatures[index] = vote.CommitSig()
		vectors[index] = validatorVector{
			Index:        index,
			AddressHex:   hex.EncodeToString(validator.Address),
			PublicKeyHex: hex.EncodeToString(validator.PubKey.Bytes()),
			VotingPower:  validator.VotingPower,
			SignBytesHex: hex.EncodeToString(signBytes),
			SignatureHex: hex.EncodeToString(signature),
		}
	}

	commit := &types.Commit{
		Height:     referenceHeight,
		Round:      referenceRound,
		BlockID:    blockID,
		Signatures: commitSignatures,
	}
	signedHeader := &types.SignedHeader{Header: header, Commit: commit}
	if err := signedHeader.ValidateBasic(chainID); err != nil {
		return nil, fmt.Errorf("validate signed header: %w", err)
	}
	if err := validatorSet.VerifyCommit(chainID, blockID, referenceHeight, commit); err != nil {
		return nil, fmt.Errorf("verify reference commit: %w", err)
	}

	signedHeaderBytes, err := signedHeader.ToProto().Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal signed header: %w", err)
	}
	validatorSetProto, err := validatorSet.ToProto()
	if err != nil {
		return nil, fmt.Errorf("convert validator set to protobuf: %w", err)
	}
	validatorSetBytes, err := validatorSetProto.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal validator set: %w", err)
	}

	return &fixture{
		FormatVersion:           1,
		ReferenceImplementation: "github.com/cometbft/cometbft Go types",
		CometBFTTag:             cometTag,
		CometBFTCommit:          cometCommit,
		CometBFTSourceVersion:   version.TMCoreSemVer,
		RustFamily:              rustFamily,
		ChainID:                 chainID,
		Height:                  referenceHeight,
		Round:                   referenceRound,
		HeaderHashHex:           hex.EncodeToString(header.Hash()),
		ValidatorSetHashHex:     hex.EncodeToString(validatorSetHash),
		SignedHeaderProtoHex:    hex.EncodeToString(signedHeaderBytes),
		ValidatorSetProtoHex:    hex.EncodeToString(validatorSetBytes),
		SignerBitmapHex:         "0f",
		Validators:              vectors,
	}, nil
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: go run reference/main.go OUTPUT.json")
	}
	vector, err := buildFixture()
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fixture JSON: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(os.Args[1], encoded, 0o644); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
