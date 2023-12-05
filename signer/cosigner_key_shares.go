package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	cryptoEth "github.com/ethereum/go-ethereum/crypto"
	"github.com/fxamacker/cbor/v2"
	vault "github.com/hashicorp/vault/api"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	cryptoTend "github.com/tendermint/tendermint/crypto"
	secp256k1Tend "github.com/tendermint/tendermint/crypto/secp256k1"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/privval"
	tsed25519 "gitlab.com/unit410/threshold-ed25519/pkg"
)

// CreateCosignerSharesFromFile creates cosigner key objects from a priv_validator_key.json file
func CreateCosignerSharesFromFile(priv string, threshold, shares int64) ([]CosignerKey, error) {
	pv, err := ReadPrivValidatorFile(priv)
	if err != nil {
		return nil, err
	}
	return CreateCosignerShares(pv, threshold, shares)
}

// CreateCosignerShares creates cosigner key objects from a privval.FilePVKey
func CreateCosignerShares(pv privval.FilePVKey, threshold, shares int64) (out []CosignerKey, err error) {
	privshares := tsed25519.DealShares(tsed25519.ExpandSecret(pv.PrivKey.Bytes()[:32]), uint8(threshold), uint8(shares))
	rsaKeys, pubKeys, err := makeRSAKeys(len(privshares))
	if err != nil {
		return nil, err
	}
	for idx, share := range privshares {
		out = append(out, CosignerKey{
			PubKey:       pv.PubKey,
			ShareKey:     share,
			ID:           idx + 1,
			RSAKey:       *rsaKeys[idx],
			CosignerKeys: pubKeys,
		})
	}
	return
}

// CreateCosignerShares creates cosigner key objects from a privval.FilePVKey
func CreateCosignerSharesECDSA(configs []*cmp.Config, threshold, shares int64) (out []CosignerKey, err error) {
	rsaKeys, pubKeys, err := makeRSAKeys(int(shares))
	if err != nil {
		return nil, err
	}

	for idx, c := range configs {
		pubkey, err := GetPubKey(c)
		if err != nil {
			return nil, err
		}

		out = append(out, CosignerKey{
			PubKey:       pubkey,
			ShareKey:     nil,
			ID:           idx + 1,
			RSAKey:       *rsaKeys[idx],
			CosignerKeys: pubKeys,
		})
	}
	return
}

func GetPubKey(c *cmp.Config) (cryptoTend.PubKey, error) {
	publicKey, err := c.PublicPoint().MarshalBinary()
	if err != nil {
		return nil, err
	}
	pubkeyECDSA, err := cryptoEth.DecompressPubkey(publicKey)
	if err != nil {
		return nil, err
	}
	var pub secp256k1Tend.PubKey = cryptoEth.CompressPubkey(pubkeyECDSA)
	return pub, nil
}

// ReadPrivValidatorFile reads in a privval.FilePVKey from a given file
func ReadPrivValidatorFile(priv string) (out privval.FilePVKey, err error) {
	var bz []byte
	if bz, err = os.ReadFile(priv); err != nil {
		return
	}
	if err = tmjson.Unmarshal(bz, &out); err != nil {
		return
	}
	return
}

// WriteCosignerShareFile writes a cosigner key to a given file name
func WriteCosignerShareFile(cosigner CosignerKey, file string) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0644) //nolint
}

func WriteConfigShareFile(c *cmp.Config, file string) error {
	data, err := c.MarshalBinary()
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0644)
}

func WritePresignatureFile(presign *ecdsa.PreSignature, file string) error {
	data, err := cbor.Marshal(presign)
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0644)
}

func makeRSAKeys(num int) (rsaKeys []*rsa.PrivateKey, pubKeys []*rsa.PublicKey, err error) {
	rsaKeys = make([]*rsa.PrivateKey, num)
	pubKeys = make([]*rsa.PublicKey, num)
	for i := 0; i < num; i++ {
		bitSize := 4096
		rsaKey, err := rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			return rsaKeys, pubKeys, err
		}
		rsaKeys[i] = rsaKey
		pubKeys[i] = &rsaKey.PublicKey
	}
	return
}

func CreateCMPConfig(threshold, shares int64) ([]*cmp.Config, error) {
	configs := make([]*cmp.Config, 0, shares)
	ids := party.IDSlice{}
	mu := &sync.Mutex{}
	errs := make(chan error)

	for i := 0; i < int(shares); i++ {
		ids = append(ids, party.ID(fmt.Sprint(i+1)))
	}

	net := NewNetwork(ids)

	wg := &sync.WaitGroup{}
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			defer wg.Done()

			pl := pool.NewPool(0)
			defer pl.TearDown()

			// CMP KEYGEN
			keygenConfig, err := CMPKeygen(id, ids, int(threshold), net, pl)

			mu.Lock()
			if err != nil {
				errs <- err
				return
			}
			fmt.Printf("create config id:%s\n", id)
			configs = append(configs, keygenConfig)
			if len(configs) == int(shares) {
				close(errs)
			}
			mu.Unlock()

		}(id)
	}
	for err := range errs {
		if err != nil {
			return nil, err
		}
	}
	wg.Wait()

	return configs, nil
}

func CreateCMPpresign(configs []*cmp.Config, threshold, shares int64) ([]*ecdsa.PreSignature, error) {
	presigns := make([]*ecdsa.PreSignature, 0, shares)
	ids := party.IDSlice{}
	mu := &sync.Mutex{}
	errs := make(chan error)

	for i := 0; i < int(shares); i++ {
		ids = append(ids, party.ID(fmt.Sprint(i+1)))
	}

	net := NewNetwork(ids)

	wg := &sync.WaitGroup{}
	for i, id := range ids {
		wg.Add(1)
		go func(id party.ID, i int) {
			defer wg.Done()

			pl := pool.NewPool(0)
			defer pl.TearDown()

			// CMP PRESIGN
			preSignature, err := CMPPreSign(configs[i], ids, net, pl)

			mu.Lock()
			if err != nil {
				errs <- err
				return
			}
			fmt.Printf("create presign id:%s\n", id)
			presigns = append(presigns, preSignature)
			if len(presigns) == int(shares) {
				close(errs)
			}
			mu.Unlock()

		}(id, i)
	}
	for err := range errs {
		if err != nil {
			return nil, err
		}
	}
	wg.Wait()

	return presigns, nil
}

func CMPPreSign(c *cmp.Config, signers party.IDSlice, n *Network, pl *pool.Pool) (*ecdsa.PreSignature, error) {
	h, err := protocol.NewMultiHandler(cmp.Presign(c, signers, pl), nil)
	if err != nil {
		return nil, err
	}

	handlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}

	preSignature := signResult.(*ecdsa.PreSignature)
	if err = preSignature.Validate(); err != nil {
		return nil, errors.New("failed to verify cmp presignature")
	}
	return preSignature, nil
}

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n *Network, pl *pool.Pool) (*cmp.Config, error) {
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}
	handlerLoop(id, h, n)

	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

// handlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func handlerLoop(id party.ID, h protocol.Handler, network *Network) {
	for {
		select {
		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			h.Accept(msg)
		}
	}
}

func correctPath(dir string) string {
	return strings.Trim(dir, "/") + "/"
}

func WriteCosignerShareVault(client *vault.Client, path string, cosigner CosignerKey) error {
	jsonBytes, err := json.Marshal(&cosigner)
	if err != nil {
		return err
	}

	_, err = client.Logical().WriteBytes(path, jsonBytes)
	if err != nil {
		return err
	}

	return nil
}

func WriteConfigCMP(client *vault.Client, path string, c *cmp.Config) error {
	data, err := c.MarshalBinary()
	if err != nil {
		return err
	}

	dataBase64 := base64.StdEncoding.EncodeToString(data)

	_, err = client.Logical().Write(path, map[string]interface{}{"key": dataBase64})
	if err != nil {
		return err
	}

	return nil
}

func WritePresig(client *vault.Client, path string, presign *ecdsa.PreSignature) error {
	data, err := cbor.Marshal(presign)
	if err != nil {
		return err
	}

	dataBase64 := base64.StdEncoding.EncodeToString(data)

	_, err = client.Logical().Write(path, map[string]interface{}{"key": dataBase64})
	if err != nil {
		return err
	}
	return nil
}

func ReadConfigCMP(client *vault.Client, dir string) (*cmp.Config, error) {
	secret, err := client.Logical().Read(correctPath(dir) + "cmp_config")
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("cmp config not found")
	}

	config := cmp.EmptyConfig(curve.Secp256k1{})

	// if err := config.UnmarshalBinary(secret.Data); err != nil { // TODO
	// 	return nil, err
	// }

	return config, nil
}

func ReadPresig(client *vault.Client, dir string) (*ecdsa.PreSignature, error) {
	secret, err := client.Logical().Read(correctPath(dir) + "cmp_presig")
	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("presignature not found")
	}

	presign := ecdsa.EmptyPreSignature(curve.Secp256k1{})

	// if err := cbor.Unmarshal(secret.Data, presign); err != nil { // TODO
	// 	return nil, err
	// }

	return presign, nil
}

func VaultClient() (*vault.Client, error) {
	config := vault.DefaultConfig()

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %v", err)
	}

	return client, nil
}
