package cli

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/trust"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// /system/trust/authority: the certificate authorities of System > Trust > Authorities. Items are selected by the
// # of print, the uuid, the description or the refid. Private keys are never printed, only exported on request

const systemTrustAuthorityItemHelp = "the #, uuid, description or refid of the certificate authority"

// systemTrustAuthority methods of add
const (
	systemTrustAuthorityInternal     = "internal"
	systemTrustAuthorityIntermediate = "intermediate"
	systemTrustAuthorityImport       = "import"
)

// systemTrustAuthoritySubjectArgs are the distinguished name arguments of add
var systemTrustAuthoritySubjectArgs = []string{"common-name", "country", "state", "city", "organization", "organizational-unit", "email"}

// systemTrustAuthorityGenerateArgs are only valid for generated (internal / intermediate) CAs
var systemTrustAuthorityGenerateArgs = append([]string{"key-type", "digest", "lifetime", "ocsp-uri"}, systemTrustAuthoritySubjectArgs...)

// systemTrustAuthorityMaxFile limits the PEM files read for certificate-file= and key-file=
const systemTrustAuthorityMaxFile = 1 << 20

func init() {
	var menu = Root.Menu("system/trust/authority")
	menu.Help = "certificate authorities (System > Trust > Authorities)"

	var item = Arg{Name: "item", Positional: true, Required: true, Help: systemTrustAuthorityItemHelp,
		Complete: systemTrustAuthorityNames}
	var dnText = func(name string, help string) Arg {
		return Arg{Name: name, Help: help, Validate: systemTrustAuthorityValidateText}
	}

	menu.Add(
		&Command{Name: "print", Help: "list the certificate authorities",
			Args: []Arg{
				{Name: "detail", Type: Bool, Help: "show all fields of every certificate authority"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (without the private key)"},
				{Name: "search", Help: "only certificate authorities where any field contains this text"},
			}, Run: systemTrustAuthorityPrint},
		&Command{Name: "show", Help: "show all fields of one certificate authority (never the private key)",
			Args: []Arg{item}, Run: systemTrustAuthorityShow},
		&Command{Name: "add", Help: "create or import a certificate authority, prints its uuid",
			Long: `method=internal generates a self-signed root CA on the firewall, method=intermediate a CA signed by
issuer= (which needs its private key), method=import imports certificate-file=<PEM file> with an
optional key-file=<PEM file> (unencrypted; without it the CA can not sign). The subject fields of an intermediate CA
default to the issuer's. Examples:
  add description="Lab root" common-name="Lab Root CA" key-type=rsa-4096 lifetime=3650
  add method=intermediate issuer="Lab root" description="Lab VPN" common-name="Lab VPN CA"
  add method=import description="Corp root" certificate-file=corp-root.pem
The description names the CA: if one with this description exists already, add fails unless replace is
given, which regenerates (or re-imports) that CA in place, keeping its uuid and refid. A CA in use is
never replaced.`,
			Args: []Arg{
				{Name: "method", Values: []string{systemTrustAuthorityInternal, systemTrustAuthorityIntermediate, systemTrustAuthorityImport},
					Default: systemTrustAuthorityInternal, Help: "internal (self-signed root), intermediate (signed by issuer=) or import"},
				{Name: "description", Required: true, Help: "the name of the certificate authority", Validate: systemTrustAuthorityValidateDescription},
				dnText("common-name", "the common name (CN), required for internal and intermediate"),
				{Name: "country", Help: "two letter country code (C)", Default: trust.CaDefaultCountry,
					Validate: systemTrustAuthorityValidateCountry, Complete: systemTrustAuthorityCountries},
				dnText("state", "state or province (ST)"),
				dnText("city", "city (L)"),
				dnText("organization", "organization (O)"),
				dnText("organizational-unit", "organizational unit (OU)"),
				dnText("email", "email address"),
				{Name: "key-type", Default: systemTrustAuthorityKeyArg(trust.CaDefaultKeyType), Complete: systemTrustAuthorityKeyTypes,
					Help: "RSA key size (rsa-2048, rsa-4096, …) or elliptic curve (prime256v1, secp384r1, secp521r1)"},
				{Name: "digest", Default: trust.CaDefaultDigest, Complete: systemTrustAuthorityDigests, Help: "digest algorithm, e.g. sha256"},
				{Name: "lifetime", Type: Int, Default: strconv.Itoa(trust.CaDefaultLifetime), Validate: ValidateRange(1, 36500),
					Help: "validity in days"},
				{Name: "ocsp-uri", Help: "OCSP responder URI added to the certificate", Validate: systemTrustAuthorityValidateUri},
				{Name: "issuer", Complete: systemTrustAuthorityNames,
					Help: "the signing CA of an intermediate CA: " + systemTrustAuthorityItemHelp},
				{Name: "certificate-file", Help: "PEM file with the certificate to import"},
				{Name: "key-file", Help: "PEM file with the private key to import (optional)"},
				{Name: "replace", Type: Bool, Help: "replace the certificate authority with the same description"},
			},
			Check: systemTrustAuthorityCheckAdd,
			Run:   systemTrustAuthorityAdd},
		&Command{Name: "set", Help: "change a certificate authority, the other fields are kept",
			Long: `The subject, key type and lifetime are part of the certificate and can not be changed: replace the
certificate with certificate-file=<PEM file> (it must belong to the stored private key, e.g. a renewal)
or regenerate the CA with add ... replace. key-file=<PEM file> adds the private key of an imported CA.`,
			Args: []Arg{
				item,
				{Name: "description", Help: "the new name", Validate: systemTrustAuthorityValidateDescription},
				{Name: "serial", Type: Int, Validate: ValidateRange(0, 1<<31-1), Help: "serial number of the next certificate this CA signs"},
				{Name: "certificate-file", Help: "PEM file with the new certificate"},
				{Name: "key-file", Help: "PEM file with the private key (unencrypted), it can not be removed"},
			}, Run: systemTrustAuthoritySet},
		&Command{Name: "remove", Help: "remove a certificate authority",
			Long: `A certificate authority still referenced by certificates, intermediate CAs, revocation lists or
services is not removed (OPNsense itself would remove it and leave those dangling).`,
			Args: []Arg{item}, Run: systemTrustAuthorityRemove},
		&Command{Name: "dump", Help: "show the certificate as text (openssl x509 -text)", Args: []Arg{item}, Run: systemTrustAuthorityDump},
		&Command{Name: "export", Help: "save the certificate or the private key as PEM file",
			Long: `Writes <description>_crt.pem or <description>_prv.pem (private keys with mode 0600) unless file= is
given, file=- writes to stdout. An existing file is only overwritten with overwrite.`,
			Args: []Arg{
				item,
				{Name: "type", Values: []string{"cert", "key"}, Default: "cert", Help: "cert for the certificate, key for the private key"},
				{Name: "file", Help: "file to write, - for stdout (default: <description>_crt.pem / _prv.pem)"},
				{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
			},
			Check: func(args *Args) error {
				if args.Bool("overwrite") && args.String("file") == "-" {
					return errors.New("overwrite has no effect with file=- (stdout)")
				}
				return nil
			},
			Run: systemTrustAuthorityExport},
	)
}

// --- validation

func systemTrustAuthorityValidateText(value string) error {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("must not contain control characters like newlines, got %q", value)
		}
	}
	return nil
}

func systemTrustAuthorityValidateDescription(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("must not be empty")
	}
	return systemTrustAuthorityValidateText(value)
}

var systemTrustAuthorityCountryPattern = regexp.MustCompile(`^[A-Za-z]{2}$`)

func systemTrustAuthorityValidateCountry(value string) error {
	if !systemTrustAuthorityCountryPattern.MatchString(value) {
		return fmt.Errorf("must be a two letter country code like NL or DE, got %q", value)
	}
	return nil
}

func systemTrustAuthorityValidateUri(value string) error {
	if value == "" {
		return nil
	}
	var parsed, err = url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("must be a URL like http://ocsp.example.com, got %q", value)
	}
	return nil
}

// systemTrustAuthorityCheckAdd allows only the arguments of the chosen method
func systemTrustAuthorityCheckAdd(args *Args) error {
	var method = strings.ToLower(args.String("method"))
	var forbid = func(names ...string) error {
		for _, name := range names {
			if args.Has(name) {
				return fmt.Errorf("%s can not be used with method=%s", name, method)
			}
		}
		return nil
	}
	switch method {
	case systemTrustAuthorityImport:
		if !args.Has("certificate-file") || args.String("certificate-file") == "" {
			return errors.New("method=import needs certificate-file=<PEM file>")
		}
		if err := forbid(append([]string{"issuer"}, systemTrustAuthorityGenerateArgs...)...); err != nil {
			return fmt.Errorf("%w, an imported CA takes them from its certificate", err)
		}
		return nil
	case systemTrustAuthorityIntermediate:
		if args.String("issuer") == "" {
			return errors.New("method=intermediate needs issuer= (the signing certificate authority)")
		}
	default:
		if err := forbid("issuer"); err != nil {
			return fmt.Errorf("%w, use method=intermediate", err)
		}
	}
	if err := forbid("certificate-file", "key-file"); err != nil {
		return fmt.Errorf("%w, use method=import", err)
	}
	if strings.TrimSpace(args.String("common-name")) == "" {
		return fmt.Errorf("method=%s needs common-name=", method)
	}
	return nil
}

// --- lookups

func systemTrustAuthorityUuid(ca trust.Authority) string {
	return ca.Uuid
}

func systemTrustAuthorityNamesOf(ca trust.Authority) []string {
	return []string{ca.Description, ca.Refid}
}

// systemTrustAuthoritySelect loads all CAs and finds the one selector refers to
func systemTrustAuthoritySelect(c *Context, api *trust.TrustApi, selector string) (trust.Authority, []trust.Authority, error) {
	var authorities, err = api.CaList()
	if err != nil {
		return trust.Authority{}, nil, err
	}
	var ca, selectErr = Select(c, selector, authorities, systemTrustAuthorityUuid, systemTrustAuthorityNamesOf)
	return ca, authorities, selectErr
}

// systemTrustAuthorityNames completes items with the descriptions
func systemTrustAuthorityNames(c *Context) []string {
	var api, err = trustApi(c)
	if err != nil {
		return nil
	}
	var authorities, listErr = api.CaList()
	if listErr != nil {
		return nil
	}
	var names []string
	for _, ca := range authorities {
		if ca.Description != "" {
			names = append(names, ca.Description)
		}
	}
	return names
}

func systemTrustAuthorityOptionKeys(c *Context, pick func(trust.AuthorityOptions) []trust.AuthorityOption) []string {
	var api, err = trustApi(c)
	if err != nil {
		return nil
	}
	var options, optionsErr = api.CaOptions()
	if optionsErr != nil {
		return nil
	}
	var keys []string
	for _, option := range pick(options) {
		keys = append(keys, option.Key)
	}
	return keys
}

func systemTrustAuthorityKeyTypes(c *Context) []string {
	var keys = systemTrustAuthorityOptionKeys(c, func(o trust.AuthorityOptions) []trust.AuthorityOption { return o.KeyTypes })
	for i, key := range keys {
		keys[i] = systemTrustAuthorityKeyArg(key)
	}
	return keys
}

func systemTrustAuthorityDigests(c *Context) []string {
	return systemTrustAuthorityOptionKeys(c, func(o trust.AuthorityOptions) []trust.AuthorityOption { return o.Digests })
}

func systemTrustAuthorityCountries(c *Context) []string {
	return systemTrustAuthorityOptionKeys(c, func(o trust.AuthorityOptions) []trust.AuthorityOption { return o.Countries })
}

// systemTrustAuthorityOption returns the option key matching value, case-insensitive, by key, by description
// (RSA-4096 is 4096) or by its argument form render(key) (rsa-4096); render nil leaves keys as they are
func systemTrustAuthorityOption(what string, options []trust.AuthorityOption, value string, render func(string) string) (string, error) {
	if render == nil {
		render = func(key string) string { return key }
	}
	var keys = make([]string, 0, len(options))
	for _, option := range options {
		if strings.EqualFold(option.Key, value) || strings.EqualFold(option.Description, value) || strings.EqualFold(render(option.Key), value) {
			return option.Key, nil
		}
		keys = append(keys, render(option.Key))
	}
	return "", fmt.Errorf("unknown %s %q, valid are: %s", what, value, strings.Join(keys, ", "))
}

// systemTrustAuthorityReadPem reads the PEM file of argument name
func systemTrustAuthorityReadPem(args *Args, name string) (string, error) {
	var path = args.String(name)
	if path == "" {
		return "", fmt.Errorf("%s: a file name is required", name)
	}
	var file, err = os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = file.Close() }()
	var content, readErr = io.ReadAll(io.LimitReader(file, systemTrustAuthorityMaxFile+1))
	if readErr != nil {
		return "", fmt.Errorf("%s: %w", name, readErr)
	}
	if len(content) > systemTrustAuthorityMaxFile {
		return "", fmt.Errorf("%s: %s is larger than 1 MiB, that is no PEM file", name, path)
	}
	if !bytes.Contains(content, []byte("-----BEGIN ")) {
		return "", fmt.Errorf("%s: %s is not a PEM file (no -----BEGIN line)", name, path)
	}
	return string(content), nil
}

// --- output

// systemTrustAuthorityKey renders key_type like the key-type argument
func systemTrustAuthorityKey(ca trust.Authority) string {
	return systemTrustAuthorityKeyArg(ca.KeyType)
}

// systemTrustAuthorityKeyArg renders an API key type like the key-type argument (and /system/trust/certificate):
// RSA sizes as rsa-2048, curves as they are
func systemTrustAuthorityKeyArg(keyType string) string {
	if _, err := strconv.Atoi(keyType); err == nil {
		return "rsa-" + keyType
	}
	return keyType
}

// systemTrustAuthorityIssuer describes the issuer: the description of a CA in the store, self-signed, or the
// issuer of the certificate when it is not in the store
func systemTrustAuthorityIssuer(ca trust.Authority, cert *x509.Certificate) string {
	switch {
	case ca.Caref != "" && ca.CarefDescription != "":
		return ca.CarefDescription
	case ca.Caref != "":
		return fmt.Sprintf("unknown (refid %s)", ca.Caref)
	case cert == nil:
		return ""
	case bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil:
		return "self-signed"
	default:
		return "external: " + cert.Issuer.String()
	}
}

func systemTrustAuthorityTime(value time.Time, ok bool, layout string) string {
	if !ok {
		return ""
	}
	var text = value.Local().Format(layout)
	if layout == time.DateOnly && value.Before(time.Now()) {
		text += " (expired)"
	}
	return text
}

func systemTrustAuthorityValidUntil(ca trust.Authority) string {
	var until, ok = ca.NotAfter()
	return systemTrustAuthorityTime(until, ok, time.DateOnly)
}

// systemTrustAuthorityFields are the fields of show and print detail, the private key only as yes/no
func systemTrustAuthorityFields(ca trust.Authority) [][2]string {
	var cert, _ = ca.X509()
	var fingerprint string
	var expired = "no"
	if cert != nil {
		fingerprint = trust.CaFingerprint(cert)
	}
	var from, fromOk = ca.NotBefore()
	var until, untilOk = ca.NotAfter()
	if untilOk && until.Before(time.Now()) {
		expired = "yes"
	}
	return [][2]string{
		{"uuid", ca.Uuid},
		{"refid", ca.Refid},
		{"description", ca.Description},
		{"common-name", ca.CommonName},
		{"subject", ca.Name},
		{"issuer", systemTrustAuthorityIssuer(ca, cert)},
		{"issuer-refid", ca.Caref},
		{"valid-from", systemTrustAuthorityTime(from, fromOk, time.DateTime)},
		{"valid-until", systemTrustAuthorityTime(until, untilOk, time.DateTime)},
		{"expired", expired},
		{"key-type", systemTrustAuthorityKey(ca)},
		{"digest", ca.Digest},
		{"private-key", map[bool]string{true: "yes", false: "no"}[ca.HasPrivateKey]},
		{"next-serial", ca.Serial},
		{"in-use", strconv.Itoa(ca.InUse())},
		{"ocsp-uri", ca.OcspUri},
		{"fingerprint", fingerprint},
	}
}

func systemTrustAuthorityPrint(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var authorities, raw, searchErr = api.CaSearchRaw(args.String("search"))
	if searchErr != nil {
		return searchErr
	}

	var uuids = make([]string, len(authorities))
	for i, ca := range authorities {
		uuids[i] = ca.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(authorities))
		for i, ca := range authorities {
			items[i] = systemTrustAuthorityFields(ca)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(authorities))
		for i, ca := range authorities {
			var cert, _ = ca.X509()
			rows[i] = []string{ca.Description, ca.CommonName, systemTrustAuthorityIssuer(ca, cert), systemTrustAuthorityValidUntil(ca),
				systemTrustAuthorityKey(ca), map[bool]string{true: "yes", false: "no"}[ca.HasPrivateKey], strconv.Itoa(ca.InUse())}
		}
		c.Items([]string{"DESCRIPTION", "COMMON-NAME", "ISSUER", "VALID-UNTIL", "KEY", "PRIVATE-KEY", "IN-USE"}, rows, uuids)
	}
	return nil
}

func systemTrustAuthorityShow(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var ca, _, selectErr = systemTrustAuthoritySelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemTrustAuthorityFields(ca))
	return nil
}

// --- changes

// systemTrustAuthorityInternalSpec builds the generate spec from the arguments, checking key type and digest
// against the options of OPNsense
func systemTrustAuthorityInternalSpec(api *trust.TrustApi, args *Args) (trust.AuthorityInternal, error) {
	var options, err = api.CaOptions()
	if err != nil {
		return trust.AuthorityInternal{}, err
	}
	keyType, err := systemTrustAuthorityOption("key-type", options.KeyTypes, args.String("key-type"), systemTrustAuthorityKeyArg)
	if err != nil {
		return trust.AuthorityInternal{}, err
	}
	digest, err := systemTrustAuthorityOption("digest", options.Digests, args.String("digest"), nil)
	if err != nil {
		return trust.AuthorityInternal{}, err
	}
	var subject = trust.AuthoritySubject{
		CommonName:         args.String("common-name"),
		State:              args.String("state"),
		City:               args.String("city"),
		Organization:       args.String("organization"),
		OrganizationalUnit: args.String("organizational-unit"),
		Email:              args.String("email"),
	}
	// an intermediate CA inherits the country of its issuer unless given
	if args.Has("country") || !strings.EqualFold(args.String("method"), systemTrustAuthorityIntermediate) {
		subject.Country, err = systemTrustAuthorityOption("country", options.Countries, strings.ToUpper(args.String("country")), nil)
		if err != nil {
			return trust.AuthorityInternal{}, err
		}
	}
	return trust.AuthorityInternal{
		Description:  args.String("description"),
		Subject:      subject,
		KeyType:      keyType,
		Digest:       digest,
		LifetimeDays: args.Int("lifetime"),
		OcspUri:      args.String("ocsp-uri"),
	}, nil
}

func systemTrustAuthorityImportSpec(args *Args) (trust.AuthorityImport, error) {
	var certificate, err = systemTrustAuthorityReadPem(args, "certificate-file")
	if err != nil {
		return trust.AuthorityImport{}, err
	}
	var spec = trust.AuthorityImport{Description: args.String("description"), Certificate: certificate}
	if args.Has("key-file") {
		if spec.PrivateKey, err = systemTrustAuthorityReadPem(args, "key-file"); err != nil {
			return trust.AuthorityImport{}, err
		}
	}
	return spec, trust.CaCheckPair(spec.Certificate, spec.PrivateKey)
}

func systemTrustAuthorityAdd(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var method = strings.ToLower(args.String("method"))
	var description = args.String("description")

	var authorities, listErr = api.CaList()
	if listErr != nil {
		return listErr
	}
	var existing []trust.Authority
	for _, ca := range authorities {
		if strings.EqualFold(ca.Description, description) {
			existing = append(existing, ca)
		}
	}
	switch {
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, ca := range existing {
			uuids[i] = ca.Uuid
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d certificate authorities with description %q (%s), change or remove them with set or remove",
			len(existing), description, strings.Join(uuids, ", "))}
	case len(existing) == 1 && !args.Bool("replace"):
		return fmt.Errorf("a certificate authority with description %q exists already (%s), change it with set or replace it with add ... replace",
			existing[0].Description, existing[0].Uuid)
	case len(existing) == 1 && existing[0].InUse() > 0:
		return fmt.Errorf("the certificate authority %q is in use (%d reference(s)), it can not be replaced; use set or a new description",
			existing[0].Description, existing[0].InUse())
	}

	if method == systemTrustAuthorityImport {
		var spec, specErr = systemTrustAuthorityImportSpec(args)
		if specErr != nil {
			return specErr
		}
		if len(existing) == 1 {
			if err := api.CaReplaceImport(existing[0].Uuid, spec); err != nil {
				return err
			}
			c.Infof("replaced the existing certificate authority %q", existing[0].Description)
			c.Println(existing[0].Uuid)
			return nil
		}
		var uuid, importErr = api.CaImport(spec)
		if importErr != nil {
			return importErr
		}
		c.Println(uuid)
		return nil
	}

	var spec, specErr = systemTrustAuthorityInternalSpec(api, args)
	if specErr != nil {
		return specErr
	}
	if method == systemTrustAuthorityIntermediate {
		var issuer, selectErr = Select(c, args.String("issuer"), authorities, systemTrustAuthorityUuid, systemTrustAuthorityNamesOf)
		if selectErr != nil {
			return fmt.Errorf("issuer: %w", selectErr)
		}
		if len(existing) == 1 && issuer.Uuid == existing[0].Uuid {
			return errors.New("a certificate authority can not be its own issuer")
		}
		if !issuer.HasPrivateKey {
			return fmt.Errorf("the issuer %q has no private key, it can not sign", issuer.Description)
		}
		spec.Issuer = issuer.Refid
		if spec.Subject, err = api.CaInheritSubject(issuer.Refid, spec.Subject); err != nil {
			return err
		}
	}

	if len(existing) == 1 {
		if err := api.CaReplaceInternal(existing[0].Uuid, spec); err != nil {
			return err
		}
		c.Infof("regenerated the existing certificate authority %q (new key and certificate)", existing[0].Description)
		c.Println(existing[0].Uuid)
		return nil
	}
	var uuid, createErr = api.CaCreateInternal(spec)
	if createErr != nil {
		return createErr
	}
	c.Println(uuid)
	return nil
}

func systemTrustAuthoritySet(c *Context, args *Args) error {
	var patch trust.AuthorityPatch
	if args.Has("description") {
		var description = args.String("description")
		patch.Description = &description
	}
	if args.Has("serial") {
		var serial = args.Int("serial")
		patch.Serial = &serial
	}
	for _, file := range []struct {
		arg    string
		target **string
	}{{"certificate-file", &patch.Certificate}, {"key-file", &patch.PrivateKey}} {
		if args.Has(file.arg) {
			var content, err = systemTrustAuthorityReadPem(args, file.arg)
			if err != nil {
				return err
			}
			*file.target = &content
		}
	}
	if patch == (trust.AuthorityPatch{}) {
		return errors.New("set: nothing to change, give at least one of description=, serial=, certificate-file= or key-file= (type \"set ?\" for help)")
	}

	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var ca, _, selectErr = systemTrustAuthoritySelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.CaUpdate(ca.Uuid, patch)
}

func systemTrustAuthorityRemove(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var ca, _, selectErr = systemTrustAuthoritySelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.CaRemove(ca.Uuid)
}

func systemTrustAuthorityDump(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var ca, _, selectErr = systemTrustAuthoritySelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var dump, dumpErr = api.CaDump(ca.Uuid)
	if dumpErr != nil {
		return dumpErr
	}
	c.Printf("%s", dump)
	if dump != "" && !strings.HasSuffix(dump, "\n") {
		c.Println()
	}
	return nil
}

var systemTrustAuthorityUnsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// systemTrustAuthorityFileName is the GUI's download name <description>_<crt|prv>.pem, made safe for a path
func systemTrustAuthorityFileName(description string, exportType string) string {
	var base = strings.Trim(systemTrustAuthorityUnsafeFileChars.ReplaceAllString(description, "_"), "._")
	if base == "" {
		base = "ca"
	}
	return fmt.Sprintf("%s_%s.pem", base, exportType)
}

func systemTrustAuthorityExport(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var ca, _, selectErr = systemTrustAuthoritySelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var exportType, mode = trust.CaExportCertificate, os.FileMode(0o644)
	if strings.EqualFold(args.String("type"), "key") {
		if !ca.HasPrivateKey {
			return fmt.Errorf("the certificate authority %q has no private key", ca.Description)
		}
		exportType, mode = trust.CaExportPrivateKey, 0o600
	}
	var payload, _, exportErr = api.CaExport(ca.Uuid, exportType)
	if exportErr != nil {
		return exportErr
	}

	var output = args.String("file")
	if output == "-" {
		_, err = c.Out.Write([]byte(payload))
		return err
	}
	if output == "" {
		output = systemTrustAuthorityFileName(ca.Description, exportType)
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if args.Bool("overwrite") {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(output, flags, mode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", output)
		}
		return err
	}
	// an overwritten file keeps its mode, a private key must not stay readable for others
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write([]byte(payload)); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	c.Infof("saved %s (%d bytes)", output, len(payload))
	return nil
}
