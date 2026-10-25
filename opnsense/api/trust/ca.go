package trust

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strconv"
	"strings"
	"time"
)

// System > Trust > Authorities (api/trust/ca). Verified against OPNsense 26.7:
//   - search and get return the private key (prv base64, prv_payload PEM) of every CA. Authority never keeps it,
//     only whether there is one; CaExport is the only way to read a key
//   - the action of a stored CA always reads "existing" and lifetime the default 825, the DN fields, key_type and
//     digest are parsed from the certificate on load (country falls back to the default NL when the certificate
//     has none), so they can not be changed by set
//   - an intermediate CA is action "internal" with caref = the refid of the issuer, the issuer's serial is increased
//   - del deletes a CA even when certificates, CRLs or other CAs refer to it (no safe delete), CaRemove checks refcount
//   - set on an unknown, well-formed uuid creates a new CA (upsert), CaUpdate checks existence first
//   - certificate errors (invalid PEM, wrong key, issuer without key) are HTTP 500 {"errorMessage":"…"}
//   - set with action "internal" regenerates key and certificate in place (same uuid and refid), set with action
//     "existing" and crt_payload replaces the certificate; an empty prv_payload keeps the stored key, prv "" clears it

// Authority key types (option keys of key_type) and digests OPNsense offers, see CaOptions for the live lists
const (
	CaDefaultKeyType  = "2048"
	CaDefaultDigest   = "sha256"
	CaDefaultLifetime = 825
	// CaDefaultCountry is used by OPNsense when no country is given (the field is required)
	CaDefaultCountry = "NL"
)

// Export types of CaExport (the type of generate_file)
const (
	CaExportCertificate = "crt"
	CaExportPrivateKey  = "prv"
)

// Authority is a certificate authority as returned by trust/ca/search, without its private key
type Authority struct {
	Uuid string `json:"uuid"`
	// Refid is the 13 hex digit reference other records (certificates, CRLs, CAs, OpenVPN, …) use
	Refid       string `json:"refid"`
	Description string `json:"descr"`
	// Caref is the refid of the issuing CA, "" for self-signed or imported CAs whose issuer is not in the store
	Caref string `json:"caref"`
	// CarefDescription is the description of the issuer when it is in the store
	CarefDescription string `json:"%caref"`
	// Serial is the serial of the next certificate signed by this CA ("" before the first one)
	Serial string `json:"serial"`
	// KeyType is "512" … "8192" (RSA bits) or the curve name like prime256v1, parsed from the certificate
	KeyType            string `json:"key_type"`
	Digest             string `json:"digest"`
	CommonName         string `json:"commonname"`
	Country            string `json:"country"`
	State              string `json:"state"`
	City               string `json:"city"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalunit"`
	Email              string `json:"email"`
	OcspUri            string `json:"ocsp_uri"`
	// Name is the subject like /C=NL/CN=My CA
	Name string `json:"name"`
	// Certificate is the PEM certificate
	Certificate string `json:"crt_payload"`
	// Refcount is the number of other config entries referring to the refid (certificates, CRLs, CAs, services)
	Refcount string `json:"refcount"`
	// ValidFrom and ValidTo are unix epochs
	ValidFrom string `json:"valid_from"`
	ValidTo   string `json:"valid_to"`
	// HasPrivateKey tells whether OPNsense holds the private key (needed to sign certificates)
	HasPrivateKey bool `json:"-"`
}

// UnmarshalJSON decodes a search/get row, the private key is only checked for presence
func (ca *Authority) UnmarshalJSON(data []byte) error {
	type plain Authority
	var row struct {
		plain
		Prv        string `json:"prv"`
		PrvPayload string `json:"prv_payload"`
	}
	if err := json.Unmarshal(data, &row); err != nil {
		return err
	}
	*ca = Authority(row.plain)
	ca.HasPrivateKey = strings.TrimSpace(row.Prv) != "" || strings.TrimSpace(row.PrvPayload) != ""
	return nil
}

// InUse returns the number of references to this CA
func (ca Authority) InUse() int {
	var count, _ = strconv.Atoi(ca.Refcount)
	return count
}

// NotAfter returns ValidTo as time, ok is false when it is not set
func (ca Authority) NotAfter() (time.Time, bool) {
	return caEpoch(ca.ValidTo)
}

// NotBefore returns ValidFrom as time, ok is false when it is not set
func (ca Authority) NotBefore() (time.Time, bool) {
	return caEpoch(ca.ValidFrom)
}

func caEpoch(value string) (time.Time, bool) {
	var epoch, err = strconv.ParseInt(value, 10, 64)
	if err != nil || epoch <= 0 {
		return time.Time{}, false
	}
	return time.Unix(epoch, 0), true
}

// X509 parses Certificate
func (ca Authority) X509() (*x509.Certificate, error) {
	return CaParseCertificate(ca.Certificate)
}

// CaFingerprint returns the SHA-256 fingerprint of a certificate as colon separated upper case hex, like openssl
func CaFingerprint(cert *x509.Certificate) string {
	var sum = sha256.Sum256(cert.Raw)
	var hexDigits = strings.ToUpper(hex.EncodeToString(sum[:]))
	var pairs = make([]string, 0, len(sum))
	for i := 0; i < len(hexDigits); i += 2 {
		pairs = append(pairs, hexDigits[i:i+2])
	}
	return strings.Join(pairs, ":")
}

// AuthoritySubject is the distinguished name of a new CA, empty fields are left out (Country "" uses
// CaDefaultCountry, OPNsense requires one)
type AuthoritySubject struct {
	CommonName         string
	Country            string
	State              string
	City               string
	Organization       string
	OrganizationalUnit string
	Email              string
}

// AuthorityInternal describes a CA OPNsense generates (key pair and certificate)
type AuthorityInternal struct {
	Description string
	// Issuer is the refid of the signing CA for an intermediate CA, "" for a self-signed root CA
	Issuer  string
	Subject AuthoritySubject
	// KeyType is an option key like "2048", "4096" or "prime256v1", "" for CaDefaultKeyType
	KeyType string
	// Digest like sha256, "" for CaDefaultDigest
	Digest string
	// LifetimeDays 0 uses CaDefaultLifetime
	LifetimeDays int
	// OcspUri is added as authorityInfoAccess OCSP URI when not empty
	OcspUri string
}

// AuthorityImport describes an existing CA to import
type AuthorityImport struct {
	Description string
	// Certificate is the PEM certificate
	Certificate string
	// PrivateKey is the optional PEM private key (unencrypted), without it the CA can not sign
	PrivateKey string
}

// AuthorityPatch holds the changeable fields of a CA, nil fields are kept
type AuthorityPatch struct {
	Description *string
	// Serial is the serial of the next certificate signed by the CA
	Serial *int
	// Certificate replaces the certificate (e.g. renewed with the same key), it must match the stored key
	Certificate *string
	// PrivateKey adds or replaces the private key, it must match the certificate. It can not be removed
	PrivateKey *string
}

// AuthorityOption is a value of an option list of the CA form
type AuthorityOption struct {
	Key         string
	Description string
}

// AuthorityOptions are the option lists of the CA form (key types, digests, countries), sorted by key
type AuthorityOptions struct {
	KeyTypes  []AuthorityOption
	Digests   []AuthorityOption
	Countries []AuthorityOption
}

// AuthorityInfo is the parsed certificate of a CA as returned by ca_info/<refid>
type AuthorityInfo struct {
	Name               string            `json:"name"`
	SerialNumber       string            `json:"serialNumber"`
	CommonName         string            `json:"commonname"`
	Country            string            `json:"country"`
	State              string            `json:"state"`
	City               string            `json:"city"`
	Organization       string            `json:"organization"`
	OrganizationalUnit string            `json:"organizationalunit"`
	Email              string            `json:"email"`
	OcspUri            string            `json:"ocsp_uri"`
	Issuer             map[string]string `json:"issuer"`
	KeyType            caFlexString      `json:"key_type"`
	Digest             string            `json:"digest"`
	ValidFrom          caFlexString      `json:"valid_from"`
	ValidTo            caFlexString      `json:"valid_to"`
}

// caFlexString accepts a JSON string or number (ca_info sends RSA key sizes and epochs as numbers)
type caFlexString string

func (s *caFlexString) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*s = ""
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*s = caFlexString(text)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return err
	}
	*s = caFlexString(number.String())
	return nil
}

// AuthorityInUseError is returned by CaRemove for a CA other records refer to
type AuthorityInUseError struct {
	Authority Authority
	// Authorities and Certificates are the descriptions of the CAs and certificates it issued
	Authorities  []string
	Certificates []string
}

func (e *AuthorityInUseError) Error() string {
	var users []string
	if len(e.Authorities) > 0 {
		users = append(users, fmt.Sprintf("authorities %s", caQuoteList(e.Authorities)))
	}
	if len(e.Certificates) > 0 {
		users = append(users, fmt.Sprintf("certificates %s", caQuoteList(e.Certificates)))
	}
	var count = e.Authority.InUse()
	var others = count - len(e.Authorities) - len(e.Certificates)
	if others > 0 {
		users = append(users, fmt.Sprintf("%d other reference(s) like revocation lists or services", others))
	}
	return fmt.Sprintf("the certificate authority %q is in use (%d reference(s): %s), remove or change those first",
		e.Authority.Description, count, strings.Join(users, ", "))
}

func caQuoteList(values []string) string {
	var quoted = make([]string, len(values))
	for i, value := range values {
		quoted[i] = strconv.Quote(value)
	}
	return strings.Join(quoted, ", ")
}

// --- endpoints

func (opn *TrustApi) caEndpoint(method string, args ...string) string {
	var endpoint = opn.endpoint("ca", method)
	for _, arg := range args {
		endpoint += "/" + arg
	}
	return endpoint
}

// caPrivateFields are left out of CaSearchRaw: the key (twice) and the base64 copy of the certificate
var caPrivateFields = []string{"prv", "prv_payload", "crt"}

// CaSearch returns the CAs where any column contains searchPhrase ("" for all) in API order
func (opn *TrustApi) CaSearch(searchPhrase string) ([]Authority, error) {
	var authorities, _, err = opn.CaSearchRaw(searchPhrase)
	return authorities, err
}

// CaSearchRaw is CaSearch which also returns the API objects for JSON output, without the private key and the
// base64 certificate (crt_payload holds the PEM)
func (opn *TrustApi) CaSearchRaw(searchPhrase string) ([]Authority, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.caEndpoint("search"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var authorities = make([]Authority, len(rows))
	var redacted = make([]json.RawMessage, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &authorities[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected certificate authority from OPNsense: %w", err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(row, &object); err != nil {
			return nil, nil, fmt.Errorf("unexpected certificate authority from OPNsense: %w", err)
		}
		for _, field := range caPrivateFields {
			delete(object, field)
		}
		if redacted[i], err = json.Marshal(object); err != nil {
			return nil, nil, err
		}
	}
	return authorities, redacted, nil
}

// CaList returns all CAs in API order
func (opn *TrustApi) CaList() ([]Authority, error) {
	return opn.CaSearch("")
}

// CaGet returns the CA with the given uuid
func (opn *TrustApi) CaGet(uuid string) (Authority, error) {
	// get/<uuid> answers option lists for key_type, digest, … so the search result is filtered instead
	return opn.caFind(fmt.Sprintf("certificate authority %s", uuid), func(ca Authority) bool { return ca.Uuid == uuid })
}

// CaGetByRefid returns the CA with the given refid (the reference certificates and CRLs use)
func (opn *TrustApi) CaGetByRefid(refid string) (Authority, error) {
	if refid == "" {
		return Authority{}, errors.New("cannot look up a certificate authority by an empty refid")
	}
	return opn.caFind(fmt.Sprintf("certificate authority with refid %s", refid), func(ca Authority) bool { return ca.Refid == refid })
}

// CaGetByDescription returns the only CA with exactly this description. Returns *coreapi.NotFoundError if there
// is none and *coreapi.TooManyFoundError if there is more than one
func (opn *TrustApi) CaGetByDescription(description string) (Authority, error) {
	if description == "" {
		return Authority{}, errors.New("cannot look up a certificate authority by an empty description")
	}
	return opn.caFind(fmt.Sprintf("certificate authority with description %q", description),
		func(ca Authority) bool { return ca.Description == description })
}

func (opn *TrustApi) caFind(name string, match func(Authority) bool) (Authority, error) {
	var authorities, err = opn.CaList()
	if err != nil {
		return Authority{}, err
	}
	var matching = coreapi.Filter(authorities, match)
	switch len(matching) {
	case 0:
		return Authority{}, &coreapi.NotFoundError{Name: name}
	case 1:
		return matching[0], nil
	default:
		var uuids = make([]string, len(matching))
		for i, ca := range matching {
			uuids[i] = ca.Uuid
		}
		return Authority{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s matches %s", name, strings.Join(uuids, ", "))}
	}
}

// CaOptions returns the key types, digests and countries the CA form offers
func (opn *TrustApi) CaOptions() (AuthorityOptions, error) {
	type options map[string]struct {
		Value string `json:"value"`
	}
	var container struct {
		Ca struct {
			KeyType options `json:"key_type"`
			Digest  options `json:"digest"`
			Country options `json:"country"`
		} `json:"ca"`
	}
	if err := opn.DoJSON("GET", opn.caEndpoint("get"), nil, &container); err != nil {
		return AuthorityOptions{}, err
	}
	var convert = func(values options) []AuthorityOption {
		var result = make([]AuthorityOption, 0, len(values))
		for key, value := range values {
			if key != "" {
				result = append(result, AuthorityOption{Key: key, Description: value.Value})
			}
		}
		sort.Slice(result, func(i, j int) bool { return caOptionLess(result[i].Key, result[j].Key) })
		return result
	}
	return AuthorityOptions{
		KeyTypes:  convert(container.Ca.KeyType),
		Digests:   convert(container.Ca.Digest),
		Countries: convert(container.Ca.Country),
	}, nil
}

// caOptionLess sorts numbers (RSA key sizes) numerically before names
func caOptionLess(a string, b string) bool {
	var numberA, errA = strconv.Atoi(a)
	var numberB, errB = strconv.Atoi(b)
	switch {
	case errA == nil && errB == nil:
		return numberA < numberB
	case errA == nil:
		return true
	case errB == nil:
		return false
	default:
		return a < b
	}
}

// CaInfo returns the parsed certificate of the CA with the given refid
func (opn *TrustApi) CaInfo(refid string) (AuthorityInfo, error) {
	if refid == "" {
		return AuthorityInfo{}, errors.New("cannot get the info of a certificate authority without refid")
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.caEndpoint("ca_info", refid), nil, &raw); err != nil {
		return AuthorityInfo{}, err
	}
	// unknown refids are answered with []
	if caEmptyAnswer(raw) {
		return AuthorityInfo{}, &coreapi.NotFoundError{Name: fmt.Sprintf("certificate authority with refid %s", refid)}
	}
	var info AuthorityInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return AuthorityInfo{}, fmt.Errorf("unexpected certificate authority info from OPNsense: %w", err)
	}
	return info, nil
}

// CaDump returns the certificate of the CA with the given uuid as text (openssl x509 -fingerprint -sha256 -text)
func (opn *TrustApi) CaDump(uuid string) (string, error) {
	if uuid == "" {
		return "", errors.New("cannot dump a certificate authority without uuid")
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.caEndpoint("raw_dump", uuid), nil, &raw); err != nil {
		return "", err
	}
	if caEmptyAnswer(raw) {
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("certificate authority %s", uuid)}
	}
	var dump struct {
		ExitStatus int    `json:"exit_status"`
		Stdout     string `json:"stdout"`
		Stderr     string `json:"stderr"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return "", fmt.Errorf("unexpected certificate dump from OPNsense: %w", err)
	}
	if dump.ExitStatus != 0 {
		return "", fmt.Errorf("openssl failed on the certificate (exit status %d): %s", dump.ExitStatus, strings.TrimSpace(dump.Stderr))
	}
	return dump.Stdout, nil
}

// caEmptyAnswer tells whether OPNsense answered [] or {} (its "nothing found")
func caEmptyAnswer(raw json.RawMessage) bool {
	var trimmed = string(bytes.TrimSpace(raw))
	return trimmed == "[]" || trimmed == "{}" || trimmed == "null"
}

// CaExport returns the PEM certificate (CaExportCertificate) or private key (CaExportPrivateKey) of the CA with
// the given uuid and the CA's description
func (opn *TrustApi) CaExport(uuid string, exportType string) (payload string, description string, err error) {
	if uuid == "" {
		return "", "", errors.New("cannot export a certificate authority without uuid")
	}
	if exportType != CaExportCertificate && exportType != CaExportPrivateKey {
		return "", "", fmt.Errorf("unknown export type %q, use %s or %s", exportType, CaExportCertificate, CaExportPrivateKey)
	}
	var result struct {
		Status  string `json:"status"`
		Descr   string `json:"descr"`
		Payload string `json:"payload"`
		Error   string `json:"error"`
	}
	// generate_file must be POSTed (GET answers {"status":"failed"})
	if err := opn.DoJSON("POST", opn.caEndpoint("generate_file", uuid, exportType), nil, &result); err != nil {
		return "", "", err
	}
	if result.Status != "ok" {
		if result.Error != "" { // "Missing certificate": unknown uuid
			return "", "", &coreapi.NotFoundError{Name: fmt.Sprintf("certificate authority %s (%s)", uuid, result.Error)}
		}
		return "", "", fmt.Errorf("exporting %s of certificate authority %s failed", exportType, uuid)
	}
	if result.Payload == "" && exportType == CaExportPrivateKey {
		return "", result.Descr, fmt.Errorf("the certificate authority %q has no private key", result.Descr)
	}
	return result.Payload, result.Descr, nil
}

// --- changes

// caNode is the body of add and set; strings are sent as given, nil pointers are left out
type caNode struct {
	Action             string  `json:"action,omitempty"`
	Descr              *string `json:"descr,omitempty"`
	Caref              *string `json:"caref,omitempty"`
	KeyType            string  `json:"key_type,omitempty"`
	Digest             string  `json:"digest,omitempty"`
	Lifetime           string  `json:"lifetime,omitempty"`
	CommonName         *string `json:"commonname,omitempty"`
	Country            *string `json:"country,omitempty"`
	State              *string `json:"state,omitempty"`
	City               *string `json:"city,omitempty"`
	Organization       *string `json:"organization,omitempty"`
	OrganizationalUnit *string `json:"organizationalunit,omitempty"`
	Email              *string `json:"email,omitempty"`
	OcspUri            *string `json:"ocsp_uri,omitempty"`
	Serial             *string `json:"serial,omitempty"`
	CrtPayload         *string `json:"crt_payload,omitempty"`
	PrvPayload         *string `json:"prv_payload,omitempty"`
	Prv                *string `json:"prv,omitempty"`
}

type caContainer struct {
	Ca caNode `json:"ca"`
}

func caString(value string) *string {
	return &value
}

// node builds the complete body of an internal CA, every field is sent so a replace resets them
func (spec AuthorityInternal) node() (caNode, error) {
	if strings.TrimSpace(spec.Description) == "" {
		return caNode{}, errors.New("a certificate authority needs a description")
	}
	if spec.LifetimeDays < 0 {
		return caNode{}, fmt.Errorf("invalid lifetime %d days", spec.LifetimeDays)
	}
	var orDefault = func(value string, fallback string) string {
		if value == "" {
			return fallback
		}
		return value
	}
	var lifetime = spec.LifetimeDays
	if lifetime == 0 {
		lifetime = CaDefaultLifetime
	}
	var subject = spec.Subject
	return caNode{
		Action:             "internal",
		Descr:              caString(spec.Description),
		Caref:              caString(spec.Issuer),
		KeyType:            orDefault(spec.KeyType, CaDefaultKeyType),
		Digest:             orDefault(spec.Digest, CaDefaultDigest),
		Lifetime:           strconv.Itoa(lifetime),
		CommonName:         caString(subject.CommonName),
		Country:            caString(orDefault(subject.Country, CaDefaultCountry)),
		State:              caString(subject.State),
		City:               caString(subject.City),
		Organization:       caString(subject.Organization),
		OrganizationalUnit: caString(subject.OrganizationalUnit),
		Email:              caString(subject.Email),
		OcspUri:            caString(spec.OcspUri),
	}, nil
}

// node builds the body of an import, prv is cleared when no key is given so a replace drops the old key
func (spec AuthorityImport) node() (caNode, error) {
	if strings.TrimSpace(spec.Description) == "" {
		return caNode{}, errors.New("a certificate authority needs a description")
	}
	if err := CaCheckPair(spec.Certificate, spec.PrivateKey); err != nil {
		return caNode{}, err
	}
	var node = caNode{
		Action:     "existing",
		Descr:      caString(spec.Description),
		Caref:      caString(""),
		CrtPayload: caString(spec.Certificate),
		PrvPayload: caString(spec.PrivateKey),
	}
	if strings.TrimSpace(spec.PrivateKey) == "" {
		node.Prv = caString("")
	}
	return node, nil
}

// caCheckIssuer checks that the issuing CA exists and holds its private key
func (opn *TrustApi) caCheckIssuer(refid string) (Authority, error) {
	var issuer, err = opn.CaGetByRefid(refid)
	if err != nil {
		return Authority{}, err
	}
	if !issuer.HasPrivateKey {
		return Authority{}, fmt.Errorf("the issuer %q has no private key, it can not sign", issuer.Description)
	}
	return issuer, nil
}

// caMutate wraps the HTTP 500 certificate errors of OPNsense
func (opn *TrustApi) caMutate(endpoint string, node caNode) (string, error) {
	var uuid, err = opn.Mutate(endpoint, caContainer{Ca: node})
	if err != nil {
		var httpErr *coreapi.HttpError
		if errors.As(err, &httpErr) && httpErr.StatusCode == 500 {
			return "", fmt.Errorf("OPNsense refused the certificate authority: %s", httpErr.Message)
		}
		return "", err
	}
	return uuid, nil
}

// CaCreateInternal generates a CA on OPNsense (key pair and certificate) and returns its uuid: self-signed when
// spec.Issuer is "", else an intermediate CA signed by the CA with that refid (see CaCreateIntermediate)
func (opn *TrustApi) CaCreateInternal(spec AuthorityInternal) (string, error) {
	var node, err = spec.node()
	if err != nil {
		return "", err
	}
	if spec.Issuer != "" {
		if _, err := opn.caCheckIssuer(spec.Issuer); err != nil {
			return "", err
		}
	}
	return opn.caMutate(opn.caEndpoint("add"), node)
}

// CaCreateIntermediate generates a CA signed by the CA with refid issuer and returns its uuid. Like the GUI,
// empty subject fields other than the common name are taken from the issuer
func (opn *TrustApi) CaCreateIntermediate(issuer string, spec AuthorityInternal) (string, error) {
	if issuer == "" {
		return "", errors.New("an intermediate certificate authority needs an issuer")
	}
	spec.Issuer = issuer
	var inherited, err = opn.CaInheritSubject(issuer, spec.Subject)
	if err != nil {
		return "", err
	}
	spec.Subject = inherited
	return opn.CaCreateInternal(spec)
}

// CaInheritSubject fills the empty fields of subject except the common name from the CA with refid issuer
func (opn *TrustApi) CaInheritSubject(issuer string, subject AuthoritySubject) (AuthoritySubject, error) {
	var info, err = opn.CaInfo(issuer)
	if err != nil {
		return subject, err
	}
	for _, field := range []struct {
		target *string
		value  string
	}{
		{&subject.Country, info.Country},
		{&subject.State, info.State},
		{&subject.City, info.City},
		{&subject.Organization, info.Organization},
		{&subject.OrganizationalUnit, info.OrganizationalUnit},
		{&subject.Email, info.Email},
	} {
		if *field.target == "" {
			*field.target = field.value
		}
	}
	return subject, nil
}

// CaImport imports an existing CA (PEM certificate and optional private key) and returns its uuid.
// OPNsense links it to its issuer when that is in the store
func (opn *TrustApi) CaImport(spec AuthorityImport) (string, error) {
	var node, err = spec.node()
	if err != nil {
		return "", err
	}
	return opn.caMutate(opn.caEndpoint("add"), node)
}

// CaReplaceInternal regenerates the CA with the given uuid in place (same uuid and refid, new key and
// certificate). Certificates it signed before no longer verify against it
func (opn *TrustApi) CaReplaceInternal(uuid string, spec AuthorityInternal) error {
	var node, err = spec.node()
	if err != nil {
		return err
	}
	if _, err := opn.CaGet(uuid); err != nil {
		return err
	}
	if spec.Issuer != "" {
		if _, err := opn.caCheckIssuer(spec.Issuer); err != nil {
			return err
		}
	}
	_, err = opn.caMutate(opn.caEndpoint("set", uuid), node)
	return err
}

// CaReplaceImport replaces the certificate and key of the CA with the given uuid by an imported one (same uuid
// and refid); without spec.PrivateKey the stored key is removed
func (opn *TrustApi) CaReplaceImport(uuid string, spec AuthorityImport) error {
	var node, err = spec.node()
	if err != nil {
		return err
	}
	if _, err := opn.CaGet(uuid); err != nil {
		return err
	}
	_, err = opn.caMutate(opn.caEndpoint("set", uuid), node)
	return err
}

// CaUpdate changes the non nil fields of patch on the CA with the given uuid. A new certificate or key must
// match the other one
func (opn *TrustApi) CaUpdate(uuid string, patch AuthorityPatch) error {
	if uuid == "" {
		return errors.New("cannot update a certificate authority without uuid")
	}
	if patch == (AuthorityPatch{}) {
		return errors.New("nothing to change")
	}
	if patch.Description != nil && strings.TrimSpace(*patch.Description) == "" {
		return errors.New("the description of a certificate authority can not be empty")
	}
	if patch.Serial != nil && *patch.Serial < 0 {
		return fmt.Errorf("invalid serial %d", *patch.Serial)
	}
	// set on an unknown uuid would create a new CA
	var current, err = opn.CaGet(uuid)
	if err != nil {
		return err
	}

	var node = caNode{Descr: patch.Description, CrtPayload: patch.Certificate, PrvPayload: patch.PrivateKey}
	if patch.Serial != nil {
		node.Serial = caString(strconv.Itoa(*patch.Serial))
	}
	if patch.Certificate != nil || patch.PrivateKey != nil {
		var certificate = current.Certificate
		if patch.Certificate != nil {
			certificate = *patch.Certificate
		}
		if patch.PrivateKey != nil {
			if strings.TrimSpace(*patch.PrivateKey) == "" {
				return errors.New("the private key of a certificate authority can not be removed, only replaced")
			}
			if err := CaCheckPair(certificate, *patch.PrivateKey); err != nil {
				return err
			}
		} else if err := CaCheckPair(certificate, ""); err != nil {
			return err
		} else if current.HasPrivateKey {
			// the new certificate must belong to the stored key
			var key, _, exportErr = opn.CaExport(uuid, CaExportPrivateKey)
			if exportErr != nil {
				return exportErr
			}
			if err := CaCheckPair(certificate, key); err != nil {
				return fmt.Errorf("the new certificate does not belong to the stored private key: %w", err)
			}
		}
		// the stored CA reads action "existing", which takes crt_payload
		node.Action = "existing"
	}
	_, err = opn.caMutate(opn.caEndpoint("set", uuid), node)
	return err
}

// CaRemove deletes the CA with the given uuid. A CA in use (refcount > 0: issued certificates, intermediate CAs,
// CRLs, services) is not deleted, an *AuthorityInUseError tells by whom; OPNsense itself would delete it
func (opn *TrustApi) CaRemove(uuid string) error {
	if uuid == "" {
		return errors.New("cannot remove a certificate authority without uuid")
	}
	var authorities, err = opn.CaList()
	if err != nil {
		return err
	}
	var matching = coreapi.Filter(authorities, func(ca Authority) bool { return ca.Uuid == uuid })
	if len(matching) == 0 {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("certificate authority %s", uuid)}
	}
	var ca = matching[0]
	if ca.InUse() > 0 {
		var inUse = &AuthorityInUseError{Authority: ca}
		for _, other := range authorities {
			if other.Caref == ca.Refid && other.Uuid != ca.Uuid {
				inUse.Authorities = append(inUse.Authorities, other.Description)
			}
		}
		inUse.Certificates, _ = opn.caIssuedCertificates(ca.Refid)
		return inUse
	}

	if _, err := opn.Mutate(opn.caEndpoint("del", uuid), nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("certificate authority %s", uuid), Err: err}
		}
		return err
	}
	return nil
}

// caIssuedCertificates returns the descriptions of the certificates signed by the CA with refid
func (opn *TrustApi) caIssuedCertificates(refid string) ([]string, error) {
	var rows, err = coreapi.Search[struct {
		Descr string `json:"descr"`
		Caref string `json:"caref"`
	}](opn.OPNsense, opn.endpoint("cert", "search"), refid)
	if err != nil {
		return nil, err
	}
	var descriptions []string
	for _, row := range rows {
		if row.Caref == refid {
			descriptions = append(descriptions, row.Descr)
		}
	}
	return descriptions, nil
}

// --- PEM checks, done locally so nothing invalid is sent

// CaParseCertificate parses the first certificate of a PEM text
func CaParseCertificate(certificate string) (*x509.Certificate, error) {
	var rest = []byte(certificate)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no PEM certificate (-----BEGIN CERTIFICATE-----) found")
		}
		if block.Type == "CERTIFICATE" {
			var cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid certificate: %w", err)
			}
			return cert, nil
		}
	}
}

// caParsePrivateKey parses the first private key of a PEM text (PKCS#8, PKCS#1 or SEC 1)
func caParsePrivateKey(privateKey string) (crypto.Signer, error) {
	var rest = []byte(privateKey)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no PEM private key (-----BEGIN PRIVATE KEY-----) found")
		}
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			continue
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" {
			return nil, errors.New("the private key is encrypted, OPNsense needs it unencrypted")
		}
		var parsed any
		var err error
		switch block.Type {
		case "RSA PRIVATE KEY":
			parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			parsed, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		var signer, ok = parsed.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type %T", parsed)
		}
		return signer, nil
	}
}

// CaCheckPair checks a PEM CA certificate and, when not empty, that the PEM private key belongs to it
func CaCheckPair(certificate string, privateKey string) error {
	var cert, err = CaParseCertificate(certificate)
	if err != nil {
		return err
	}
	if cert.BasicConstraintsValid && !cert.IsCA {
		return fmt.Errorf("the certificate %q is not a certificate authority (basicConstraints CA:FALSE)", cert.Subject.String())
	}
	if strings.TrimSpace(privateKey) == "" {
		return nil
	}
	var key, keyErr = caParsePrivateKey(privateKey)
	if keyErr != nil {
		return keyErr
	}
	type comparable interface{ Equal(crypto.PublicKey) bool }
	var public, ok = key.Public().(comparable)
	if !ok || !public.Equal(cert.PublicKey) {
		return errors.New("the private key does not belong to the certificate")
	}
	return nil
}
