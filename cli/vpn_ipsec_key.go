package cli

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/ipsec"
)

// /vpn/ipsec/pre-shared-key and /vpn/ipsec/key-pair: the pre-shared keys (and EAP secrets) of VPN > IPsec >
// Pre-Shared Keys, named by their local and remote identity, and the raw public keys of VPN > IPsec > Key Pairs
// for auth=pubkey, named by their name. Neither the pre-shared keys nor the private keys are ever shown; key-pair
// export writes the public key

func vpnIpsecValidateIdentity(value string) error {
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			return fmt.Errorf("must be an address, FQDN or email without spaces, got %q", value)
		}
	}
	return nil
}

func vpnIpsecPreSharedKeyFields(add bool) []vpnIpsecField {
	return []vpnIpsecField{
		{Arg: vpnIpsecRequired(add, Arg{Name: "local-id", Help: "local identity: an address, FQDN or email",
			Validate: func(value string) error {
				if value == "" {
					return errors.New("must not be empty")
				}
				return vpnIpsecValidateIdentity(value)
			}}), field: "ident"},
		{Arg: Arg{Name: "remote-id", Help: "remote identity, empty for any peer", Validate: vpnIpsecValidateIdentity}, field: "remote_ident"},
		{Arg: Arg{Name: "type", Values: []string{"PSK", "EAP"}, Validate: vpnIpsecNotEmpty, Help: "PSK (default) or EAP (an EAP secret of the local identity)"}, field: "keyType"},
		{Arg: vpnIpsecRequired(add, Arg{Name: "key", Help: "the secret (never shown)", Validate: vpnIpsecNotEmpty}), field: "Key", kind: vpnIpsecSecret},
		{Arg: Arg{Name: "description", Help: "description", Validate: vpnIpsecValidateText}, field: "description"},
	}
}

func vpnIpsecKeyPairFields(add bool) []vpnIpsecField {
	return []vpnIpsecField{
		{Arg: vpnIpsecRequired(add, Arg{Name: "name", Help: "name, connections refer to it with pubkeys=", Validate: vpnIpsecNotEmpty}), field: "name"},
		{Arg: Arg{Name: "type", Values: []string{"rsa", "ecdsa"}, Validate: vpnIpsecNotEmpty, Help: "rsa (default) or ecdsa, the type of the keys"}, field: "keyType"},
		{Arg: vpnIpsecRequired(add, Arg{Name: "public-key-file", Help: "read the public key (PEM) from this local file", Validate: vpnIpsecNotEmpty}),
			field: "publicKey", kind: vpnIpsecFile},
		{Arg: Arg{Name: "private-key-file", Help: "read the private key (PEM) from this local file, only for own keys; empty removes it"},
			field: "privateKey", kind: vpnIpsecFile},
	}
}

func vpnIpsecKeyPairShown() []vpnIpsecField {
	return []vpnIpsecField{
		{Arg: Arg{Name: "name"}, field: "name"},
		{Arg: Arg{Name: "type"}, field: "keyType"},
		{Arg: Arg{Name: "key-size"}, field: "keySize"},
		{Arg: Arg{Name: "fingerprint"}, field: "keyFingerprint"},
		{Arg: Arg{Name: "private-key"}, field: "privateKey", kind: vpnIpsecPresent},
	}
}

// vpnIpsecPreSharedKeyNames: local-id/remote-id and the local identity alone
func vpnIpsecPreSharedKeyNames(r ipsec.Record) []string {
	return []string{r.Value("ident") + "/" + r.Value("remote_ident"), r.Value("ident")}
}

func vpnIpsecPreSharedKeyLabel(r ipsec.Record) string {
	if r.Value("remote_ident") == "" {
		return fmt.Sprintf("%q", r.Value("ident"))
	}
	return fmt.Sprintf("%q/%q", r.Value("ident"), r.Value("remote_ident"))
}

// vpnIpsecKeyPairInUse refuses to remove a key pair authentication rounds use (OPNsense would keep the uuid)
func vpnIpsecKeyPairInUse(api *ipsec.IPsecApi, keyPair ipsec.Record) error {
	var users []string
	for _, list := range []func(connection string) ([]ipsec.Record, error){api.LocalList, api.RemoteList} {
		var rounds, err = list("")
		if err != nil {
			return err
		}
		users = append(users, vpnIpsecUsers(rounds, "pubkeys", keyPair.Uuid(), vpnIpsecRoundLabel)...)
	}
	if len(users) > 0 {
		return fmt.Errorf("the key pair %q is used by the authentication rounds %s, change their pubkeys= first",
			keyPair.Value("name"), strings.Join(users, ", "))
	}
	return nil
}

var vpnIpsecKeyPairItems = &vpnIpsecItems{
	menu: "vpn/ipsec/key-pair", help: "raw public keys for auth=pubkey (VPN > IPsec > Key Pairs)",
	noun: "key pair", itemHelp: "the #, uuid or name of the key pair", prefix: "keyPair.",
	addLong: `Adds the keys of public-key-file= (and private-key-file= for an own key) in PEM, OPNsense checks that
they belong together; "generate" lets OPNsense create a new key pair. The name names the key pair: if it exists
already, add fails unless replace is given, then that key pair is replaced completely.`,
	fields:     vpnIpsecKeyPairFields,
	shown:      vpnIpsecKeyPairShown,
	fieldNames: ipsec.KeyPairFieldNames,
	list:       func(api *ipsec.IPsecApi) ([]ipsec.Record, error) { return api.KeyPairList("") },
	form:       (*ipsec.IPsecApi).KeyPairForm,
	create:     (*ipsec.IPsecApi).KeyPairCreate,
	update:     (*ipsec.IPsecApi).KeyPairUpdate,
	remove:     (*ipsec.IPsecApi).KeyPairRemove,
	names:      func(r ipsec.Record) []string { return []string{r.Value("name")} },
	label:      vpnIpsecQuoted("name"),
	key: func(r ipsec.Record, values map[string]string) bool {
		return strings.EqualFold(r.Value("name"), values["name"])
	},
	keyText: "name",
	columns: []vpnIpsecColumn{
		{"NAME", func(r ipsec.Record) string { return r.Value("name") }},
		{"TYPE", func(r ipsec.Record) string { return r.Value("keyType") }},
		{"SIZE", func(r ipsec.Record) string { return r.Value("keySize") }},
		{"PRIVATE", func(r ipsec.Record) string { return YesNo(Flag(r.Value("privateKey") != "")) }},
		{"FINGERPRINT", func(r ipsec.Record) string { return r.Value("keyFingerprint") }},
	},
	secrets:      ipsec.SecretFields["key-pair"],
	removeLong:   "A key pair used by authentication rounds can not be removed.",
	beforeRemove: vpnIpsecKeyPairInUse,
}

func init() {
	vpnIpsecRegister(&vpnIpsecItems{
		menu: "vpn/ipsec/pre-shared-key", help: "pre-shared keys and EAP secrets of the identities (VPN > IPsec > Pre-Shared Keys)",
		noun: "pre-shared key", itemHelp: "the #, uuid, local-id or local-id/remote-id of the key", prefix: "preSharedKey.",
		addLong: `Rounds with auth=psk use the key of their identities (local id= and remote id=). The local and remote
identity name the key: if a key for them exists already, add fails unless replace is given, then that key is
replaced completely.`,
		fields:     vpnIpsecPreSharedKeyFields,
		fieldNames: ipsec.PreSharedKeyFieldNames,
		list:       func(api *ipsec.IPsecApi) ([]ipsec.Record, error) { return api.PreSharedKeyList("") },
		form:       (*ipsec.IPsecApi).PreSharedKeyForm,
		create:     (*ipsec.IPsecApi).PreSharedKeyCreate,
		update:     (*ipsec.IPsecApi).PreSharedKeyUpdate,
		remove:     (*ipsec.IPsecApi).PreSharedKeyRemove,
		names:      vpnIpsecPreSharedKeyNames,
		label:      vpnIpsecPreSharedKeyLabel,
		key: func(r ipsec.Record, values map[string]string) bool {
			return strings.EqualFold(r.Value("ident"), values["ident"]) && strings.EqualFold(r.Value("remote_ident"), values["remote_ident"])
		},
		keyText: "local-id and remote-id",
		columns: []vpnIpsecColumn{
			{"TYPE", func(r ipsec.Record) string { return r.Value("keyType") }},
			{"LOCAL-ID", func(r ipsec.Record) string { return r.Value("ident") }},
			{"REMOTE-ID", func(r ipsec.Record) string { return r.Value("remote_ident") }},
			{"DESCRIPTION", func(r ipsec.Record) string { return r.Value("description") }},
		},
		secrets: ipsec.SecretFields["pre-shared-key"],
	})

	var item = vpnIpsecKeyPairItems.itemArg()
	vpnIpsecKeyPairItems.extra = []*Command{
		{Name: "generate", Help: "let OPNsense generate a new key pair and add it, prints its uuid",
			Long: `Generates a key pair on the firewall and stores it under name= (the private key never leaves the firewall
and is not shown). Sizes: rsa 1024, 2048 (default), 3072, 4096, 8192; ecdsa 256, 384 (default), 521. Like add it
fails for an existing name unless replace is given. Give the public key to the peer with "export".
` + vpnIpsecApplyHint,
			Args: []Arg{
				{Name: "name", Required: true, Help: "name of the new key pair", Validate: vpnIpsecNotEmpty},
				{Name: "type", Values: []string{"rsa", "ecdsa"}, Default: "rsa", Help: "rsa (default) or ecdsa"},
				{Name: "size", Type: Int, Help: "key size in bits (rsa) or curve size (ecdsa)"},
				{Name: "replace", Type: Bool, Help: "replace the keys of the key pair with the same name"},
			},
			Check: func(args *Args) error {
				if args.Has("size") && args.String("size") != "" {
					var keyType = strings.ToLower(args.String("type"))
					var sizes = ipsec.KeyPairSizes[keyType]
					if !containsFold(sizes, args.String("size")) {
						return fmt.Errorf("size of an %s key must be one of %s", keyType, strings.Join(sizes, ", "))
					}
				}
				return nil
			},
			Run: vpnIpsecKeyPairGenerate},
		{Name: "export", Help: "write the public key (PEM) of a key pair, e.g. for the peer",
			Args: []Arg{item,
				{Name: "file", Default: "-", Help: "file to write, - for stdout"},
				{Name: "overwrite", Type: Bool, Help: "replace an existing file"},
			},
			Run: vpnIpsecKeyPairExport},
	}
	vpnIpsecRegister(vpnIpsecKeyPairItems)
}

func vpnIpsecKeyPairGenerate(c *Context, args *Args) error {
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var name = strings.TrimSpace(args.String("name"))
	var keyType = strings.ToLower(args.String("type"))
	var records, listErr = api.KeyPairList("")
	if listErr != nil {
		return listErr
	}
	var existing = coreapi.Filter(records, func(r ipsec.Record) bool { return strings.EqualFold(r.Value("name"), name) })
	switch {
	case len(existing) > 1:
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d key pairs named %q (%s), remove or rename them first",
			len(existing), name, strings.Join(vpnIpsecUuids(existing), ", "))}
	case len(existing) == 1 && !args.Bool("replace"):
		return fmt.Errorf("a key pair named %q exists already (%s), give replace to generate new keys for it", name, existing[0].Uuid())
	}

	var keys, generateErr = api.KeyPairGenerate(keyType, args.String("size"))
	if generateErr != nil {
		return generateErr
	}
	var fields = ipsec.Fields{"name": name, "keyType": keyType, "publicKey": keys.PublicKey, "privateKey": keys.PrivateKey}
	if len(existing) == 1 {
		if err := api.KeyPairUpdate(existing[0].Uuid(), fields); err != nil {
			return vpnIpsecKeyPairItems.error(err)
		}
		c.Infof("replaced the keys of the key pair %q", existing[0].Value("name"))
		c.Println(existing[0].Uuid())
		return nil
	}
	var uuid, createErr = api.KeyPairCreate(fields)
	if createErr != nil {
		return vpnIpsecKeyPairItems.error(createErr)
	}
	c.Println(uuid)
	return nil
}

func vpnIpsecKeyPairExport(c *Context, args *Args) error {
	if args.Bool("overwrite") && args.String("file") == "-" {
		return errors.New("overwrite has no effect with file=- (stdout)")
	}
	var api, err = vpnIpsecApi(c)
	if err != nil {
		return err
	}
	var keyPair, _, selectErr = vpnIpsecKeyPairItems.selectItem(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var content = keyPair.Value("publicKey")
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("the key pair %q has no public key", keyPair.Value("name"))
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := vpnIpsecWriteFile(c, args.String("file"), []byte(content), args.Bool("overwrite")); err != nil {
		return err
	}
	if args.String("file") != "-" {
		c.Infof("saved the public key of %q to %s", keyPair.Value("name"), args.String("file"))
	}
	return nil
}
