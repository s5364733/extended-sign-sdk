package extend_golang_sdk

import (
	"fmt"
	"math/big"
	"strconv"
	"sync"

	"github.com/NethermindEth/juno/core/crypto"
	"github.com/NethermindEth/juno/core/felt"
	"github.com/dontpanicdao/caigo"
	caigo_types "github.com/dontpanicdao/caigo/types"
)

// Optimistic issue:https://github.com/levyalpha-research/go-framework/issues/68
//
// Cached constants (computed once at package init for performance)
var (
	// Starknet field modulus (CAIRO_PRIME)
	// p = 2^251 + 17 * 2^192 + 1
	starkPrime *big.Int

	// Domain selector: selector!("\"StarknetDomain\"(...)")
	domainSelector *big.Int

	// Order selector: selector!("\"Order\"(...)")
	orderSelector *big.Int

	// "StarkNet Message" as Felt (cached)
	starknetMessageFelt *big.Int
)

func init() {
	// Initialize constants once at package load (performance optimization)
	var ok bool
	starkPrime = new(big.Int)
	_, ok = starkPrime.SetString("0x800000000000011000000000000000000000000000000000000000000000001", 0)
	if !ok {
		panic("failed to initialize STARK_PRIME")
	}

	domainSelector = new(big.Int)
	_, ok = domainSelector.SetString("0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210", 0)
	if !ok {
		panic("failed to initialize domainSelector")
	}

	orderSelector = new(big.Int)
	_, ok = orderSelector.SetString("0x36da8d51815527cabfaa9c982f564c80fa7429616739306036f1f9b608dd112", 0)
	if !ok {
		panic("failed to initialize orderSelector")
	}

	starknetMessageFelt = caigo_types.UTF8StrToBig("StarkNet Message")
}

// StarknetDomain represents Starknet domain for EIP-712 style signing
type StarknetDomain struct {
	Name     string
	Version  string
	ChainID  string
	Revision string
}

// OrderHashParams represents parameters for computing order hash
type OrderHashParams struct {
	PositionID       string // Vault ID
	BaseAssetIDHex   string // Synthetic asset ID (hex)
	BaseAmount       string // Synthetic amount (as string integer)
	QuoteAssetIDHex  string // Collateral asset ID (hex)
	QuoteAmount      string // Collateral amount (as string integer)
	FeeAssetIDHex    string // Fee asset ID (hex, usually same as collateral)
	FeeAmount        string // Fee amount (as string integer)
	Expiration       string // Expiration timestamp in seconds
	Salt             string // Nonce
	UserPublicKeyHex string // User's Starknet public key
	Domain           StarknetDomain
}

// ExtendedSigner provides Starknet signing functionality for Extended exchange
type ExtendedSigner struct {
	privateKey     string    // Starknet private key (hex with 0x prefix)
	publicKey      string    // Starknet public key (hex with 0x prefix)
	privateKeyBN   *big.Int  // Cached parsed private key (lazy init, thread-safe)
	privateKeyOnce sync.Once // For thread-safe lazy initialization
}

// NewExtendedSigner creates a new Extended signer
func NewExtendedSigner(privateKeyHex, publicKeyHex string) *ExtendedSigner {
	return &ExtendedSigner{
		privateKey: privateKeyHex,
		publicKey:  publicKeyHex,
	}
}

// GetOrderHash computes the order hash using SNIP-12 (Starknet typed data signing)
// This follows Extended exchange's implementation using Poseidon hash
// Optimized: uses cached constants, direct integer parsing, and pre-allocated slices
func (signer *ExtendedSigner) GetOrderHash(params OrderHashParams) (*big.Int, error) {
	// Parse parameters directly (optimized: avoid intermediate big.Int allocations)
	positionID := parseUint32ToBigInt(params.PositionID)
	baseAssetID := hexToBigInt(params.BaseAssetIDHex)
	baseAmount := parseInt64ToBigInt(params.BaseAmount)
	quoteAssetID := hexToBigInt(params.QuoteAssetIDHex)
	quoteAmount := parseInt64ToBigInt(params.QuoteAmount)
	feeAssetID := hexToBigInt(params.FeeAssetIDHex)
	feeAmount := stringToBigInt(params.FeeAmount)
	expiration := stringToBigInt(params.Expiration)
	salt := stringToBigInt(params.Salt)
	userPublicKey := hexToBigInt(params.UserPublicKeyHex)

	// Step 1: Compute domain hash using Poseidon
	// Use cached domainSelector (optimization: avoid repeated hex parsing)
	domainName := shortStringToBigInt(params.Domain.Name)
	domainVersion := shortStringToBigInt(params.Domain.Version)
	domainChainID := shortStringToBigInt(params.Domain.ChainID)
	domainRevision := stringToBigInt(params.Domain.Revision)

	// Pre-allocate slice for domain hash (5 elements: selector + 4 domain fields)
	domainElems := make([]*big.Int, 5)
	domainElems[0] = domainSelector // Cached constant
	domainElems[1] = domainName
	domainElems[2] = domainVersion
	domainElems[3] = domainChainID
	domainElems[4] = domainRevision
	domainHash := poseidonHash(domainElems)

	// Step 2: Compute order struct hash using Poseidon
	// Use cached orderSelector (optimization: avoid repeated hex parsing)
	// Pre-allocate slice for order hash (10 elements: selector + 9 order fields)
	orderElems := make([]*big.Int, 10)
	orderElems[0] = orderSelector // Cached constant
	orderElems[1] = positionID
	orderElems[2] = baseAssetID
	orderElems[3] = baseAmount
	orderElems[4] = quoteAssetID
	orderElems[5] = quoteAmount
	orderElems[6] = feeAssetID
	orderElems[7] = feeAmount
	orderElems[8] = expiration
	orderElems[9] = salt
	orderHash := poseidonHash(orderElems)

	// Step 3: Compute final message hash
	// Use cached starknetMessageFelt (optimization: avoid repeated string conversion)
	// Pre-allocate slice for message hash (4 elements)
	messageElems := make([]*big.Int, 4)
	messageElems[0] = starknetMessageFelt // Cached constant
	messageElems[1] = domainHash
	messageElems[2] = userPublicKey
	messageElems[3] = orderHash
	messageHash := poseidonHash(messageElems)

	return messageHash, nil
}

// getPrivateKeyBN returns the parsed private key (lazy initialization, thread-safe)
// This avoids repeated parsing of the private key on each signature operation
func (signer *ExtendedSigner) getPrivateKeyBN() *big.Int {
	signer.privateKeyOnce.Do(func() {
		signer.privateKeyBN = caigo_types.HexToBN(signer.privateKey)
	})
	return signer.privateKeyBN
}

// SignOrderHash signs the order hash with the private key
// Optimized: uses cached private key to avoid repeated parsing
func (signer *ExtendedSigner) SignOrderHash(orderHash *big.Int) (r, s *big.Int, err error) {
	privateKeyBN := signer.getPrivateKeyBN()
	return caigo.Curve.Sign(orderHash, privateKeyBN)
}

// SignOrder computes order hash and signs it in one step
func (signer *ExtendedSigner) SignOrder(params OrderHashParams) (r, s *big.Int, orderHash *big.Int, err error) {
	orderHash, err = signer.GetOrderHash(params)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute order hash: %w", err)
	}

	r, s, err = signer.SignOrderHash(orderHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sign order hash: %w", err)
	}

	return r, s, orderHash, nil
}

// GetPublicKey returns the public key
func (signer *ExtendedSigner) GetPublicKey() string {
	return signer.publicKey
}

// Helper functions

// poseidonHash computes Poseidon hash of elements (using juno/crypto)
// Optimized: uses cached STARK_PRIME, pre-allocated slice with exact length
func poseidonHash(elems []*big.Int) *big.Int {
	// Pre-allocate slice with exact length (optimization: avoid append reallocation)
	felts := make([]*felt.Felt, len(elems))

	for i, elem := range elems {
		// For negative numbers, convert to field element: p + n
		var fieldElem *big.Int
		if elem.Sign() < 0 {
			// Create new big.Int for each negative number to ensure correctness
			// Use cached STARK_PRIME (optimization: avoid repeated parsing)
			fieldElem = new(big.Int).Add(starkPrime, elem) // p + (-|n|) = p - |n|
		} else {
			fieldElem = elem
		}

		// Convert to Felt using SetBytes
		// Optimization: directly create Felt and set bytes (one allocation instead of two)
		bytes := fieldElem.Bytes()
		felts[i] = new(felt.Felt).SetBytes(bytes)
	}
	// Use crypto.PoseidonArray from juno/core/crypto
	hash := crypto.PoseidonArray(felts...)
	// Convert back to *big.Int
	return hash.BigInt(new(big.Int))
}

// shortStringToBigInt converts a Cairo short string to big.Int (Felt)
func shortStringToBigInt(str string) *big.Int {
	// Cairo short string encoding: convert string bytes to big int
	return caigo_types.UTF8StrToBig(str)
}

// uint32ToBigInt converts uint32 to big.Int
//func uint32ToBigInt(val uint32) *big.Int {
//	return new(big.Int).SetUint64(uint64(val))
//}
//
// int64ToBigInt converts int64 to big.Int (handles negative values)
//func int64ToBigInt(val int64) *big.Int {
//	return new(big.Int).SetInt64(val)
//}

// parseUint32ToBigInt parses string to uint32 and converts to big.Int directly
// Optimized: avoids intermediate big.Int allocation by parsing directly
func parseUint32ToBigInt(str string) *big.Int {
	val, err := strconv.ParseUint(str, 10, 32)
	if err != nil {
		// Fallback to stringToBigInt if parsing fails (for very large numbers)
		return stringToBigInt(str)
	}
	return new(big.Int).SetUint64(val)
}

// parseInt64ToBigInt parses string to int64 and converts to big.Int directly
// Optimized: avoids intermediate big.Int allocation by parsing directly
func parseInt64ToBigInt(str string) *big.Int {
	val, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		// Fallback to stringToBigInt if parsing fails (for very large numbers)
		return stringToBigInt(str)
	}
	return new(big.Int).SetInt64(val)
}

//
//func parseUint32(str string) uint32 {
//	bn := stringToBigInt(str)
//	return uint32(bn.Uint64())
//}
//
//func parseInt64(str string) int64 {
//	bn := stringToBigInt(str)
//	return bn.Int64()
//}

func hexToBigInt(hexStr string) *big.Int {
	return caigo_types.HexToBN(hexStr)
}

func stringToBigInt(str string) *big.Int {
	bn := new(big.Int)
	bn.SetString(str, 10)
	return bn
}

// FormatSignature formats r and s into hex string format for API
func FormatSignature(r, s *big.Int) (rHex, sHex string) {
	// Simple string concat is often faster than using functions.
	return "0x" + r.Text(16), "0x" + s.Text(16)
}
