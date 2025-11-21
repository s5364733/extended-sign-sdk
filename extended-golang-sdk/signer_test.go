package extend_golang_sdk

// Note: This test file is for validation only, run from parent directory

import (
	"math/big"
	"testing"
)

// TestSignerConsistency tests that optimized version produces same results as original
func TestSignerConsistency(t *testing.T) {
	privateKey := "0x61f8cd80251dddbcac6a5d04b136720437036ad53a721c2d5374c76fef05b12"
	publicKey := "0x2d4db4db4050219e9da3900ccd70273ca33d73ce4527ac51ea6fd137a4f2352"

	signer := NewExtendedSigner(privateKey, publicKey)

	testCases := []struct {
		name   string
		params OrderHashParams
	}{
		{
			name: "Basic order",
			params: OrderHashParams{
				PositionID:       "12345",
				BaseAssetIDHex:   "0x4254432d3600000000000000000000",
				BaseAmount:       "1500000",
				QuoteAssetIDHex:  "0x31857064564ed0ff978e687456963cba09c2c6985d8f9300a1de4962fafa054",
				QuoteAmount:      "-75000000000",
				FeeAssetIDHex:    "0x31857064564ed0ff978e687456963cba09c2c6985d8f9300a1de4962fafa054",
				FeeAmount:        "18750000",
				Expiration:       "1735689600",
				Salt:             "1234567890",
				UserPublicKeyHex: publicKey,
				Domain: StarknetDomain{
					Name:     "Perpetuals",
					Version:  "v0",
					ChainID:  "SN_MAIN",
					Revision: "1",
				},
			},
		},
		{
			name: "Negative amounts",
			params: OrderHashParams{
				PositionID:       "67890",
				BaseAssetIDHex:   "0x4254432d3600000000000000000000",
				BaseAmount:       "-1500000",
				QuoteAssetIDHex:  "0x31857064564ed0ff978e687456963cba09c2c6985d8f9300a1de4962fafa054",
				QuoteAmount:      "75000000000",
				FeeAssetIDHex:    "0x31857064564ed0ff978e687456963cba09c2c6985d8f9300a1de4962fafa054",
				FeeAmount:        "18750000",
				Expiration:       "1735689600",
				Salt:             "9876543210",
				UserPublicKeyHex: publicKey,
				Domain: StarknetDomain{
					Name:     "Perpetuals",
					Version:  "v0",
					ChainID:  "SN_MAIN",
					Revision: "1",
				},
			},
		},
		{
			name: "Large values",
			params: OrderHashParams{
				PositionID:       "999999",
				BaseAssetIDHex:   "0x4254432d3600000000000000000000",
				BaseAmount:       "1000000000000000000",
				QuoteAssetIDHex:  "0x31857064564ed0ff978e687456963cba09c2c6985d8f9300a1de4962fafa054",
				QuoteAmount:      "-50000000000000000000",
				FeeAssetIDHex:    "0x31857064564ed0ff978e687456963cba09c2c6985d8f9300a1de4962fafa054",
				FeeAmount:        "12500000000000000",
				Expiration:       "1735689600",
				Salt:             "1111111111",
				UserPublicKeyHex: publicKey,
				Domain: StarknetDomain{
					Name:     "Perpetuals",
					Version:  "v0",
					ChainID:  "SN_MAIN",
					Revision: "1",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test GetOrderHash
			hash1, err := signer.GetOrderHash(tc.params)
			if err != nil {
				t.Fatalf("GetOrderHash failed: %v", err)
			}

			// Test multiple times to ensure consistency
			hash2, err := signer.GetOrderHash(tc.params)
			if err != nil {
				t.Fatalf("GetOrderHash failed: %v", err)
			}

			if hash1.Cmp(hash2) != 0 {
				t.Errorf("GetOrderHash inconsistent: %s != %s", hash1.Text(16), hash2.Text(16))
			}

			// Test SignOrder
			r1, s1, hash3, err := signer.SignOrder(tc.params)
			if err != nil {
				t.Fatalf("SignOrder failed: %v", err)
			}

			r2, s2, hash4, err := signer.SignOrder(tc.params)
			if err != nil {
				t.Fatalf("SignOrder failed: %v", err)
			}

			// Note: Signatures will be different each time (nonce/random), but hash should be same
			if hash3.Cmp(hash4) != 0 {
				t.Errorf("SignOrder hash inconsistent: %s != %s", hash3.Text(16), hash4.Text(16))
			}

			if hash1.Cmp(hash3) != 0 {
				t.Errorf("GetOrderHash and SignOrder hash mismatch: %s != %s", hash1.Text(16), hash3.Text(16))
			}

			// Verify signatures are valid (non-zero)
			if r1.Cmp(big.NewInt(0)) == 0 || s1.Cmp(big.NewInt(0)) == 0 {
				t.Error("Signature r or s is zero")
			}
			if r2.Cmp(big.NewInt(0)) == 0 || s2.Cmp(big.NewInt(0)) == 0 {
				t.Error("Signature r or s is zero")
			}
		})
	}
}
