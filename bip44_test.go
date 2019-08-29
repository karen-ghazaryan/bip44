package bip44

import (
	"encoding/hex"
	"github.com/karen-ghazaryan/bip32"
	"testing"
)

func TestNewKeyFromMnemonic(t *testing.T) {
	// excluding this test because NewKeyFromMasterKey
	// is being used in NewKeyFromMnemonic
}

func TestNewKeyFromMasterKey(t *testing.T) {
	seed, _ := hex.DecodeString("a672b4fb616c21b756729a30f014a86884b7ff9a5331f4082641d0d996a351956b5fa107aed15af12ffeba71ce00964cc889e5b3caead16cd991cff51f5bb52a")
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Case: generated addresses satisfying expected", func(t *testing.T) {
		// m / purpose' / coin_type' / account' / change / address_index
		key, err := NewKeyFromMasterKey(masterKey, uint32(TypeBitcoin), HardenedKeyStart, ExternalBranch, 0)

		if err != nil {
			t.Fatal(err)
		}

		expectedPrivate := "xprvA42zRf7QytGacrzkvDJkqtZKiy4bZuDLXmwFaCaFTCtd5Y71eqgcSq5uszqUSdGj5vDFuRxGVoAqaQVZevxNiLjCsrzWdUYqSa4MfpjAAeU"
		if key.String() != expectedPrivate {
			t.Errorf("expecting %s got  %s", expectedPrivate, key.String())
		}
		t.Log(key)
	})
}
