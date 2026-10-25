package ipsec

import (
	"fmt"
	"slices"
	"strings"
)

// The other configuration lists of VPN > IPsec: address pools (api/ipsec/pools), virtual tunnel interfaces
// (api/ipsec/vti), manual SPD entries (api/ipsec/manual_spd), pre-shared keys (api/ipsec/pre_shared_keys) and key
// pairs (api/ipsec/key_pairs)

var (
	// PoolFieldNames are the writable fields of an address pool: name (unique, letters, digits and , _ - :),
	// addrs (one CIDR subnet) and dns (comma separated addresses)
	PoolFieldNames = []string{"enabled", "name", "addrs", "dns"}
	// VtiFieldNames are the writable fields of a virtual tunnel interface (device ipsec<reqid>); reqid is unique,
	// local / remote are the outer addresses (both or none), tunnel_* the inner addresses of one family each
	VtiFieldNames = []string{"enabled", "reqid", "local", "remote", "tunnel_local", "tunnel_remote", "tunnel_local2",
		"tunnel_remote2", "skip_fw", "description"}
	// ManualSpdFieldNames are the writable fields of a manual SPD entry: either reqid or connection_child (a child
	// uuid) must be set, protocol is esp or ah
	ManualSpdFieldNames = []string{"enabled", "protocol", "reqid", "connection_child", "source", "destination", "description"}
	// PreSharedKeyFieldNames are the writable fields of a pre-shared key: ident and remote_ident (unique as a pair),
	// keyType PSK or EAP, Key the secret
	PreSharedKeyFieldNames = []string{"ident", "remote_ident", "keyType", "Key", "description"}
	// KeyPairFieldNames are the writable fields of a key pair: keyType rsa or ecdsa, publicKey and the optional
	// privateKey in PEM; keySize and keyFingerprint are computed by OPNsense
	KeyPairFieldNames = []string{"name", "keyType", "publicKey", "privateKey"}

	// SecretFields are the fields of search rows holding secrets, by resource ("pre-shared-key", "key-pair")
	SecretFields = map[string][]string{"pre-shared-key": {"Key"}, "key-pair": {"privateKey"}}

	// KeyPairSizes are the key sizes key_pairs/gen_key_pair accepts per type, the first is the default
	KeyPairSizes = map[string][]string{"rsa": {"2048", "1024", "3072", "4096", "8192"}, "ecdsa": {"384", "256", "521"}}
)

var (
	poolResource = resource{controller: "pools", search: "search", get: "get", add: "add", set: "set", del: "del",
		toggle: "toggle", container: "pool", noun: "ipsec pool", fields: PoolFieldNames}
	vtiResource = resource{controller: "vti", search: "search", get: "get", add: "add", set: "set", del: "del",
		toggle: "toggle", container: "vti", noun: "ipsec vti", fields: VtiFieldNames}
	manualSpdResource = resource{controller: "manual_spd", search: "search", get: "get", add: "add", set: "set",
		del: "del", toggle: "toggle", container: "spd", noun: "ipsec manual spd entry", fields: ManualSpdFieldNames}
	preSharedKeyResource = resource{controller: "pre_shared_keys", search: "search_item", get: "get_item",
		add: "add_item", set: "set_item", del: "del_item", container: "preSharedKey", noun: "ipsec pre-shared key",
		fields: PreSharedKeyFieldNames}
	keyPairResource = resource{controller: "key_pairs", search: "search_item", get: "get_item", add: "add_item",
		set: "set_item", del: "del_item", container: "keyPair", noun: "ipsec key pair", fields: KeyPairFieldNames}
)

// --- pools

// PoolList returns the address pools, searchPhrase is a substring match over all columns ("" for all)
func (opn *IPsecApi) PoolList(searchPhrase string) ([]Record, error) {
	return opn.list(poolResource, searchPhrase, nil)
}

// PoolGet returns the pool with this uuid or a *NotFoundError
func (opn *IPsecApi) PoolGet(uuid string) (Record, error) {
	return opn.getRecord(poolResource, uuid)
}

// PoolGetByName returns the pool with this name (case-insensitive) or a *NotFoundError
func (opn *IPsecApi) PoolGetByName(name string) (Record, error) {
	return opn.oneByName(poolResource, "name", "name", name)
}

// PoolCreate adds a pool and returns its uuid. OPNsense refuses duplicate names
func (opn *IPsecApi) PoolCreate(fields Fields) (string, error) {
	return opn.create(poolResource, fields)
}

// PoolUpdate sends only the given fields to the pool with this uuid (*NotFoundError when it does not exist)
func (opn *IPsecApi) PoolUpdate(uuid string, fields Fields) error {
	return opn.update(poolResource, uuid, fields)
}

// PoolRemove deletes the pool with this uuid. OPNsense does not check whether a connection uses it
func (opn *IPsecApi) PoolRemove(uuid string) error {
	return opn.remove(poolResource, uuid)
}

// PoolSetEnabled enables or disables a pool and returns whether its state changed
func (opn *IPsecApi) PoolSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.setEnabled(poolResource, uuid, enabled)
}

// --- virtual tunnel interfaces

// VtiList returns the virtual tunnel interfaces. Rows with origin "legacy" are generated from legacy tunnels and
// read-only
func (opn *IPsecApi) VtiList(searchPhrase string) ([]Record, error) {
	return opn.list(vtiResource, searchPhrase, nil)
}

// VtiGet returns the virtual tunnel interface with this uuid or a *NotFoundError
func (opn *IPsecApi) VtiGet(uuid string) (Record, error) {
	return opn.getRecord(vtiResource, uuid)
}

// VtiCreate adds a virtual tunnel interface and returns its uuid. OPNsense refuses duplicate reqids
func (opn *IPsecApi) VtiCreate(fields Fields) (string, error) {
	return opn.create(vtiResource, fields)
}

// VtiUpdate sends only the given fields to the virtual tunnel interface with this uuid
func (opn *IPsecApi) VtiUpdate(uuid string, fields Fields) error {
	return opn.update(vtiResource, uuid, fields)
}

// VtiRemove deletes the virtual tunnel interface with this uuid, the device is removed by the next reconfigure
func (opn *IPsecApi) VtiRemove(uuid string) error {
	return opn.remove(vtiResource, uuid)
}

// VtiSetEnabled enables or disables a virtual tunnel interface and returns whether its state changed
func (opn *IPsecApi) VtiSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.setEnabled(vtiResource, uuid, enabled)
}

// --- manual SPD entries

// ManualSpdList returns the manual SPD entries
func (opn *IPsecApi) ManualSpdList(searchPhrase string) ([]Record, error) {
	return opn.list(manualSpdResource, searchPhrase, nil)
}

// ManualSpdGet returns the manual SPD entry with this uuid or a *NotFoundError
func (opn *IPsecApi) ManualSpdGet(uuid string) (Record, error) {
	return opn.getRecord(manualSpdResource, uuid)
}

// ManualSpdForm returns the get answer with the defaults of a new entry, connection_child lists the children
// ("<connection> - <child>")
func (opn *IPsecApi) ManualSpdForm() (Form, error) {
	return opn.form(manualSpdResource, "", nil)
}

// ManualSpdCreate adds a manual SPD entry and returns its uuid
func (opn *IPsecApi) ManualSpdCreate(fields Fields) (string, error) {
	return opn.create(manualSpdResource, fields)
}

// ManualSpdUpdate sends only the given fields to the manual SPD entry with this uuid
func (opn *IPsecApi) ManualSpdUpdate(uuid string, fields Fields) error {
	return opn.update(manualSpdResource, uuid, fields)
}

// ManualSpdRemove deletes the manual SPD entry with this uuid
func (opn *IPsecApi) ManualSpdRemove(uuid string) error {
	return opn.remove(manualSpdResource, uuid)
}

// ManualSpdSetEnabled enables or disables a manual SPD entry and returns whether its state changed
func (opn *IPsecApi) ManualSpdSetEnabled(uuid string, enabled bool) (bool, error) {
	return opn.setEnabled(manualSpdResource, uuid, enabled)
}

// --- pre-shared keys

// PreSharedKeyList returns the pre-shared keys. The rows contain the keys (field Key) in clear text
func (opn *IPsecApi) PreSharedKeyList(searchPhrase string) ([]Record, error) {
	return opn.list(preSharedKeyResource, searchPhrase, nil)
}

// PreSharedKeyGet returns the pre-shared key with this uuid or a *NotFoundError
func (opn *IPsecApi) PreSharedKeyGet(uuid string) (Record, error) {
	return opn.getRecord(preSharedKeyResource, uuid)
}

// PreSharedKeyCreate adds a pre-shared key and returns its uuid. OPNsense refuses a second key for the same
// ident / remote_ident pair
func (opn *IPsecApi) PreSharedKeyCreate(fields Fields) (string, error) {
	return opn.create(preSharedKeyResource, fields)
}

// PreSharedKeyUpdate sends only the given fields to the pre-shared key with this uuid
func (opn *IPsecApi) PreSharedKeyUpdate(uuid string, fields Fields) error {
	return opn.update(preSharedKeyResource, uuid, fields)
}

// PreSharedKeyRemove deletes the pre-shared key with this uuid
func (opn *IPsecApi) PreSharedKeyRemove(uuid string) error {
	return opn.remove(preSharedKeyResource, uuid)
}

// --- key pairs

// KeyPairList returns the key pairs. The rows contain the private keys (field privateKey) in clear text
func (opn *IPsecApi) KeyPairList(searchPhrase string) ([]Record, error) {
	return opn.list(keyPairResource, searchPhrase, nil)
}

// KeyPairGet returns the key pair with this uuid or a *NotFoundError
func (opn *IPsecApi) KeyPairGet(uuid string) (Record, error) {
	return opn.getRecord(keyPairResource, uuid)
}

// KeyPairGetByName returns the only key pair with this name (case-insensitive), a *NotFoundError or a
// *TooManyFoundError (names are not unique in OPNsense)
func (opn *IPsecApi) KeyPairGetByName(name string) (Record, error) {
	return opn.oneByName(keyPairResource, "name", "name", name)
}

// KeyPairCreate adds a key pair and returns its uuid. OPNsense checks that the keys parse and belong together
// and computes keySize and keyFingerprint. Like the GUI, the change marks the IPsec configuration as pending
// (LegacyStatus), ApplyLegacy or a reconfigure writes the keys
func (opn *IPsecApi) KeyPairCreate(fields Fields) (string, error) {
	return opn.create(keyPairResource, fields)
}

// KeyPairUpdate sends only the given fields to the key pair with this uuid
func (opn *IPsecApi) KeyPairUpdate(uuid string, fields Fields) error {
	return opn.update(keyPairResource, uuid, fields)
}

// KeyPairRemove deletes the key pair with this uuid. OPNsense does not check whether an authentication round
// uses it
func (opn *IPsecApi) KeyPairRemove(uuid string) error {
	return opn.remove(keyPairResource, uuid)
}

// KeyPair is a key pair generated by KeyPairGenerate, both keys in PEM
type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

// KeyPairGenerate lets OPNsense generate a key pair (key_pairs/gen_key_pair/<type>/<size>) without storing it.
// keyType is rsa or ecdsa, size one of KeyPairSizes ("" for the default: rsa 2048, ecdsa 384)
func (opn *IPsecApi) KeyPairGenerate(keyType string, size string) (KeyPair, error) {
	var sizes, known = KeyPairSizes[keyType]
	if !known {
		return KeyPair{}, fmt.Errorf("unknown key type %q, valid are rsa and ecdsa", keyType)
	}
	var endpoint = opn.endpoint("key_pairs", "gen_key_pair") + "/" + keyType
	if size != "" {
		if !slices.Contains(sizes, size) {
			return KeyPair{}, fmt.Errorf("invalid %s key size %q, valid are %s", keyType, size, strings.Join(sizes, ", "))
		}
		endpoint += "/" + size
	}
	var answer struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Pubkey  string `json:"pubkey"`
		Privkey string `json:"privkey"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return KeyPair{}, err
	}
	if answer.Status != "ok" || answer.Pubkey == "" || answer.Privkey == "" {
		return KeyPair{}, fmt.Errorf("generating the key pair failed: %s", coreapiMessage(answer.Message, answer.Status))
	}
	return KeyPair{PublicKey: answer.Pubkey, PrivateKey: answer.Privkey}, nil
}

// PoolForm returns the get answer with the defaults of a new pool
func (opn *IPsecApi) PoolForm() (Form, error) {
	return opn.form(poolResource, "", nil)
}

// VtiForm returns the get answer with the defaults of a new virtual tunnel interface
func (opn *IPsecApi) VtiForm() (Form, error) {
	return opn.form(vtiResource, "", nil)
}

// PreSharedKeyForm returns the get answer with the defaults of a new pre-shared key
func (opn *IPsecApi) PreSharedKeyForm() (Form, error) {
	return opn.form(preSharedKeyResource, "", nil)
}

// KeyPairForm returns the get answer with the defaults of a new key pair
func (opn *IPsecApi) KeyPairForm() (Form, error) {
	return opn.form(keyPairResource, "", nil)
}

func coreapiMessage(message string, status string) string {
	if message != "" {
		return message
	}
	return fmt.Sprintf("status %q", status)
}
