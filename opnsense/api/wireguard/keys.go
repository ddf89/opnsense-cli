package wireguard

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// KeyPair is a WireGuard key pair, base64 encoded like wg genkey / wg pubkey print them
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// ValidateKey checks a WireGuard key (private, public or pre-shared): the base64 encoding of 32 bytes
func ValidateKey(key string) error {
	var raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil || len(raw) != 32 {
		return errors.New("must be a WireGuard key: 32 bytes base64 encoded (44 characters ending with =)")
	}
	return nil
}

// PublicKeyOf derives the public key of a WireGuard private key (X25519, like wg pubkey)
func PublicKeyOf(privateKey string) (string, error) {
	var raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid private key: must be 32 bytes base64 encoded")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// KeyPair lets OPNsense generate a new key pair (server/key_pair, configd "wireguard gen_keypair"). Nothing is
// stored on the firewall
func (opn *WireguardApi) KeyPair() (KeyPair, error) {
	var answer struct {
		Status  string `json:"status"`
		Pubkey  string `json:"pubkey"`
		Privkey string `json:"privkey"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("server", "key_pair"), nil, &answer); err != nil {
		return KeyPair{}, err
	}
	if answer.Status != "ok" || ValidateKey(answer.Privkey) != nil || ValidateKey(answer.Pubkey) != nil {
		return KeyPair{}, fmt.Errorf("OPNsense could not generate a key pair (status %q)", answer.Status)
	}
	return KeyPair{PublicKey: answer.Pubkey, PrivateKey: answer.Privkey}, nil
}

// PresharedKey lets OPNsense generate a new pre-shared key (client/psk, configd "wireguard gen_psk")
func (opn *WireguardApi) PresharedKey() (string, error) {
	var answer struct {
		Status string `json:"status"`
		Psk    string `json:"psk"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("client", "psk"), nil, &answer); err != nil {
		return "", err
	}
	if answer.Status != "ok" || ValidateKey(answer.Psk) != nil {
		return "", fmt.Errorf("OPNsense could not generate a pre-shared key (status %q)", answer.Status)
	}
	return answer.Psk, nil
}
