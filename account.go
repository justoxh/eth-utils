package eth_utils

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type Account struct {
	PrivateKey  *ecdsa.PrivateKey `json:"-"`
	Keystr      string            `json:"privatekey"`
	FromAddress common.Address    `json:"-"`
	AddrStr     string            `json:"address"`

	Fn func(_s types.Signer, _addr common.Address, _tx *types.Transaction) (*types.Transaction, error) `json:"-"`
}

func (a *Account) InitAccount() {
	privateKey, err := crypto.HexToECDSA(a.Keystr)
	if err != nil {
		fmt.Println("initaccount failed", err, a.Keystr)
		return
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("initaccount failed", err)
		return
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	a.PrivateKey = privateKey
	a.FromAddress = fromAddress
	a.Fn = func(_s types.Signer, _addr common.Address, _tx *types.Transaction) (*types.Transaction, error) {
		return types.SignTx(_tx, _s, privateKey)
	}
}
