// Copyright 2016 Factom Foundation
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package bip44

import (
	"github.com/karen-ghazaryan/bip32"
	"github.com/karen-ghazaryan/bip39"
)

const (
	// Purpose is a constant set to 44' (or 0x8000002C) following the BIP43 recommendation.
	// It indicates that the subtree of this node is used according to this specification.
	Purpose = 0x8000002C
	// HardenedKeyStart is the index at which a hardened key starts.  Each
	// extended key has 2^31 normal child keys and 2^31 hardened child keys.
	// Thus the range for normal child keys is [0, 2^31 - 1] and the range
	// for hardened child keys is [2^31, 2^32 - 1].
	HardenedKeyStart = 0x80000000 // 2^31
	// MaxAccountNum is the maximum allowed account number.  This value was
	// chosen because accounts are hardened children and therefore must not
	// exceed the hardened child range of extended keys and it provides a
	// reserved account at the top of the range for supporting imported
	// addresses.
	MaxAccountNum = HardenedKeyStart - 2 // 2^31 - 2
	// MaxAddressesPerAccount is the maximum allowed number of addresses
	// per account number.  This value is based on the limitation of the
	// underlying hierarchical deterministic key derivation.
	MaxAddressesPerAccount = HardenedKeyStart - 1

	// DefaultAccountIndex is the number of the default account.
	DefaultAccountIndex = HardenedKeyStart

	// maxCoinType is the maximum allowed coin type used when structuring
	// the BIP0044 multi-account hierarchy.  This value is based on the
	// limitation of the underlying hierarchical deterministic key
	// derivation.
	maxCoinType = HardenedKeyStart - 1

	// ExternalBranch is the child number to use when performing BIP0044
	// style hierarchical deterministic key derivation for the external
	// branch.
	ExternalBranch uint32 = 0

	// InternalBranch is the child number to use when performing BIP0044
	// style hierarchical deterministic key derivation for the internal
	// branch.
	InternalBranch uint32 = 1
)

//https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
//https://github.com/satoshilabs/slips/blob/master/slip-0044.md
//https://github.com/FactomProject/FactomDocs/blob/master/wallet_info/wallet_test_vectors.md

type CoinType uint32
const (
	TypeBitcoin               CoinType = 0x80000000
	TypeTestnet               CoinType = 0x80000001
	TypeLitecoin              CoinType = 0x80000002
	TypeDogecoin              CoinType = 0x80000003
	TypeReddcoin              CoinType = 0x80000004
	TypeDash                  CoinType = 0x80000005
	TypePeercoin              CoinType = 0x80000006
	TypeNamecoin              CoinType = 0x80000007
	TypeFeathercoin           CoinType = 0x80000008
	TypeCounterparty          CoinType = 0x80000009
	TypeBlackcoin             CoinType = 0x8000000a
	TypeNuShares              CoinType = 0x8000000b
	TypeNuBits                CoinType = 0x8000000c
	TypeMazacoin              CoinType = 0x8000000d
	TypeViacoin               CoinType = 0x8000000e
	TypeClearingHouse         CoinType = 0x8000000f
	TypeRubycoin              CoinType = 0x80000010
	TypeGroestlcoin           CoinType = 0x80000011
	TypeDigitalcoin           CoinType = 0x80000012
	TypeCannacoin             CoinType = 0x80000013
	TypeDigiByte              CoinType = 0x80000014
	TypeOpenAssets            CoinType = 0x80000015
	TypeMonacoin              CoinType = 0x80000016
	TypeClams                 CoinType = 0x80000017
	TypePrimecoin             CoinType = 0x80000018
	TypeNeoscoin              CoinType = 0x80000019
	TypeJumbucks              CoinType = 0x8000001a
	TypeziftrCOIN             CoinType = 0x8000001b
	TypeVertcoin              CoinType = 0x8000001c
	TypeNXT                   CoinType = 0x8000001d
	TypeBurst                 CoinType = 0x8000001e
	TypeMonetaryUnit          CoinType = 0x8000001f
	TypeZoom                  CoinType = 0x80000020
	TypeVpncoin               CoinType = 0x80000021
	TypeCanadaeCoin           CoinType = 0x80000022
	TypeShadowCash            CoinType = 0x80000023
	TypeParkByte              CoinType = 0x80000024
	TypePandacoin             CoinType = 0x80000025
	TypeStartCOIN             CoinType = 0x80000026
	TypeMOIN                  CoinType = 0x80000027
	TypeArgentum              CoinType = 0x8000002D
	TypeGlobalCurrencyReserve CoinType = 0x80000031
	TypeNovacoin              CoinType = 0x80000032
	TypeAsiacoin              CoinType = 0x80000033
	TypeBitcoindark           CoinType = 0x80000034
	TypeDopecoin              CoinType = 0x80000035
	TypeTemplecoin            CoinType = 0x80000036
	TypeAIB                   CoinType = 0x80000037
	TypeEDRCoin               CoinType = 0x80000038
	TypeSyscoin               CoinType = 0x80000039
	TypeSolarcoin             CoinType = 0x8000003a
	TypeSmileycoin            CoinType = 0x8000003b
	TypeEther                 CoinType = 0x8000003c
	TypeEtherClassic          CoinType = 0x8000003d
	TypeOpenChain             CoinType = 0x80000040
	TypeOKCash                CoinType = 0x80000045
	TypeDogecoinDark          CoinType = 0x8000004d
	TypeElectronicGulden      CoinType = 0x8000004e
	TypeClubCoin              CoinType = 0x8000004f
	TypeRichCoin              CoinType = 0x80000050
	TypePotcoin               CoinType = 0x80000051
	TypeQuarkcoin             CoinType = 0x80000052
	TypeTerracoin             CoinType = 0x80000053
	TypeGridcoin              CoinType = 0x80000054
	TypeAuroracoin            CoinType = 0x80000055
	TypeIXCoin                CoinType = 0x80000056
	TypeGulden                CoinType = 0x80000057
	TypeBitBean               CoinType = 0x80000058
	TypeBata                  CoinType = 0x80000059
	TypeMyriadcoin            CoinType = 0x8000005a
	TypeBitSend               CoinType = 0x8000005b
	TypeUnobtanium            CoinType = 0x8000005c
	TypeMasterTrader          CoinType = 0x8000005d
	TypeGoldBlocks            CoinType = 0x8000005e
	TypeSaham                 CoinType = 0x8000005f
	TypeChronos               CoinType = 0x80000060
	TypeUbiquoin              CoinType = 0x80000061
	TypeEvotion               CoinType = 0x80000062
	TypeSaveTheOcean          CoinType = 0x80000063
	TypeBigUp                 CoinType = 0x80000064
	TypeGameCredits           CoinType = 0x80000065
	TypeDollarcoins           CoinType = 0x80000066
	TypeZayedcoin             CoinType = 0x80000067
	TypeDubaicoin             CoinType = 0x80000068
	TypeStratis               CoinType = 0x80000069
	TypeShilling              CoinType = 0x8000006a
	TypePiggyCoin             CoinType = 0x80000076
	TypeMonero                CoinType = 0x80000080
	TypeNavCoin               CoinType = 0x80000082
	TypeFactomFactoids        CoinType = 0x80000083
	TypeFactomEntryCredits    CoinType = 0x80000084
	TypeZcash                 CoinType = 0x80000085
	TypeLisk                  CoinType = 0x80000086
	TypeFactomIdentity        CoinType = 0x80000119
)

// NewKeyFromMnemonic constructs and returns private key
// m / purpose' / coin_type' / account' / chain / address_index
func NewKeyFromMnemonic(mnemonic string, coin, account, chain, address uint32, password string) (*bip32.Key, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, password)
	if err != nil {
		return nil, err
	}

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	return NewKeyFromMasterKey(masterKey, coin, account, chain, address)
}

func NewKeyFromMasterKey(masterKey *bip32.Key, coin, account, chain, address uint32) (*bip32.Key, error) {
	child, err := masterKey.NewChildKey(Purpose)
	if err != nil {
		return nil, err
	}

	child, err = child.NewChildKey(coin)
	if err != nil {
		return nil, err
	}

	child, err = child.NewChildKey(account)
	if err != nil {
		return nil, err
	}

	child, err = child.NewChildKey(chain)
	if err != nil {
		return nil, err
	}

	child, err = child.NewChildKey(address)
	if err != nil {
		return nil, err
	}

	return child, nil
}
