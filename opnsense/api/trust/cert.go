package trust

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	coreapi "opnsense-cli/opnsense/api"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Certificates of System > Trust > Certificates (api/trust/cert).
//
// OPNsense 26.7 behaviour this file relies on (verified on the dev box):
//   - add and set run the "action" of the record: internal (create a key and sign it with the CA caref, self-signed
//     without caref), external (key + signing request), import (certificate, optionally its key), sign_csr (sign
//     an uploaded request with the CA caref), import_csr (store the CA signed certificate of a request created
//     with external), reissue (sign a new certificate for the stored key) and manual (store crt_payload as is).
//   - Loading a record computes its action from what it holds (crt+prv: reissue, crt: manual, csr: sign_csr,
//     csr+prv: import_csr), so a set without action REISSUES certificates with a key (new crt, lifetime reset to
//     397 days). Every update therefore sends action manual, which keeps the stored payloads.
//   - The subject, alt names, key type, digest and cert_type of a row are parsed from the certificate (or request),
//     lifetime is not: rows always show the default 397, the validity is valid_from / valid_to (unix epoch).
//   - Rows (search and get) contain the private key twice (prv base64, prv_payload PEM).
//   - Failures of the action (invalid PEM, key mismatch, unverifiable certificate) and deleting a certificate in
//     use are answered with HTTP 500 {"errorMessage": …, "errorTitle": …}.
//   - set on an unknown version 4 uuid CREATES a record (other unknown uuids answer {"result":"failed"} without
//     validations), so every update looks the certificate up first. get and raw_dump answer [] for unknown uuids.
//   - del/<uuids> takes a comma separated list.
//   - generate_file/<uuid>/<type> must be POSTed and answers {"status":"ok","payload":""} when the requested part
//     does not exist (no key, no request, a request without certificate).

// Values of Cert.CertType and CertRequest.Type
const (
	CertTypeClient   = "usr_cert"
	CertTypeServer   = "server_cert"
	CertTypeCombined = "combined_server_client"
	CertTypeCA       = "v3_ca"
)

// OPNsense defaults for new certificates
const (
	CertDefaultKeyType  = "2048"
	CertDefaultDigest   = "sha256"
	CertDefaultLifetime = 397 // days
	CertDefaultType     = CertTypeClient
	CertDefaultCountry  = "NL"
)

// CertKeyTypes are the key types OPNsense offers: RSA bits or an elliptic curve
var CertKeyTypes = []string{"1024", "2048", "3072", "4096", "8192", "prime256v1", "secp384r1", "secp521r1"}

// CertDigests are the signature digests OPNsense offers
var CertDigests = []string{"sha1", "sha224", "sha256", "sha384", "sha512"}

// CertMethod is how CertCreate obtains the certificate
type CertMethod string

const (
	// CertMethodInternal creates a key and a certificate signed by the CA CertRequest.IssuerRef
	CertMethodInternal CertMethod = "internal"
	// CertMethodSelfSigned creates a key and a self-signed certificate
	CertMethodSelfSigned CertMethod = "self-signed"
	// CertMethodSigningRequest creates a key and a certificate signing request (CSR) to be signed elsewhere, the
	// signed certificate is added with CertImportSigned
	CertMethodSigningRequest CertMethod = "csr"
	// CertMethodImport stores CertRequest.CertificatePEM and the optional CertRequest.PrivateKeyPEM
	CertMethodImport CertMethod = "import"
	// CertMethodSignRequest signs CertRequest.SigningRequestPEM with the CA CertRequest.IssuerRef, there is no key
	CertMethodSignRequest CertMethod = "sign-csr"
)

// CertMethods are all CertMethod values
var CertMethods = []CertMethod{CertMethodInternal, CertMethodSelfSigned, CertMethodSigningRequest, CertMethodImport, CertMethodSignRequest}

// Export formats of CertExport (the API's names)
const (
	CertExportCertificate    = "crt"
	CertExportPrivateKey     = "prv"
	CertExportSigningRequest = "csr"
	CertExportPKCS12         = "pkcs12"
)

// Cert is a certificate (or a pending signing request) as returned by trust/cert/search. The private key is never
// kept: HasPrivateKey tells whether the firewall stores one, CertExport fetches it
type Cert struct {
	Uuid  string `json:"uuid"`
	Refid string `json:"refid"` // the stable 13 hex digit id other config sections refer to
	Descr string `json:"descr"`
	// Caref is the refid of the CA in the trust store which issued the certificate (linked by issuer name),
	// "" for self-signed and foreign certificates
	Caref     string `json:"caref"`
	CarefName string `json:"%caref"` // description of the CA Caref
	// Action is what a set would do with the record, see the package notes: reissue, manual, sign_csr, import_csr
	Action string `json:"action"`
	// CertType is parsed from the certificate's key usage: CertTypeClient, CertTypeServer, CertTypeCombined or ""
	CertType           string `json:"cert_type"`
	KeyType            string `json:"key_type"` // RSA bits like "2048" or the curve like "prime256v1"
	Digest             string `json:"digest"`
	CommonName         string `json:"commonname"`
	Country            string `json:"country"`
	State              string `json:"state"`
	City               string `json:"city"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalunit"`
	Email              string `json:"email"`
	OcspUri            string `json:"ocsp_uri"`
	// AltNames* are newline separated
	AltNamesDNS   string `json:"altnames_dns"`
	AltNamesIP    string `json:"altnames_ip"`
	AltNamesEmail string `json:"altnames_email"`
	AltNamesURI   string `json:"altnames_uri"`
	// CertificatePEM is "" for a pending signing request
	CertificatePEM    string `json:"crt_payload"`
	SigningRequestPEM string `json:"csr_payload"`
	// Purpose is the RFC 3280 extended key usage, e.g. id-kp-serverAuth
	Purpose string `json:"rfc3280_purpose"`
	// InUse is "1" when another part of the configuration refers to the certificate (users excluded)
	InUse string `json:"in_use"`
	// IsUser is "1" when the common name is a user name (a user certificate)
	IsUser string `json:"is_user"`
	// Name is the subject, e.g. /C=NL/CN=host.example
	Name      string `json:"name"`
	ValidFrom string `json:"valid_from"` // unix epoch, "" for a pending request
	ValidTo   string `json:"valid_to"`

	HasPrivateKey bool `json:"-"`
}

// UnmarshalJSON decodes a row and drops the private key, only remembering whether there is one
func (cert *Cert) UnmarshalJSON(data []byte) error {
	type plain Cert
	var row struct {
		plain
		Prv        string `json:"prv"`
		PrvPayload string `json:"prv_payload"`
	}
	if err := json.Unmarshal(data, &row); err != nil {
		return err
	}
	*cert = Cert(row.plain)
	cert.HasPrivateKey = row.Prv != "" || row.PrvPayload != ""
	return nil
}

// IsPending tells whether the record is a signing request without certificate yet
func (cert Cert) IsPending() bool {
	return cert.CertificatePEM == "" && cert.SigningRequestPEM != ""
}

// IsExternal tells whether the certificate is managed outside the trust store (e.g. by a plugin): OPNsense lists
// them with an id that is not a uuid, they can not be changed or removed
func (cert Cert) IsExternal() bool {
	return !strings.Contains(cert.Uuid, "-")
}

// InUseFlag tells whether another part of the configuration refers to the certificate
func (cert Cert) InUseFlag() bool {
	return cert.InUse == "1"
}

// NotAfter returns the end of the validity, ok is false for pending requests
func (cert Cert) NotAfter() (time.Time, bool) {
	return certEpoch(cert.ValidTo)
}

// NotBefore returns the start of the validity, ok is false for pending requests
func (cert Cert) NotBefore() (time.Time, bool) {
	return certEpoch(cert.ValidFrom)
}

func certEpoch(value string) (time.Time, bool) {
	var seconds, err = strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}

// X509 parses the certificate, it fails for pending requests
func (cert Cert) X509() (*x509.Certificate, error) {
	if cert.CertificatePEM == "" {
		return nil, fmt.Errorf("certificate %q has no certificate (pending signing request)", cert.Descr)
	}
	return CertParsePEM(cert.CertificatePEM)
}

// IsSelfSigned tells whether the certificate is signed by its own key
func (cert Cert) IsSelfSigned() bool {
	var parsed, err = cert.X509()
	if err != nil || !bytes.Equal(parsed.RawIssuer, parsed.RawSubject) {
		return false
	}
	// not CheckSignatureFrom: it refuses parents that are not a CA, self-signed leaf certificates are no CA
	return parsed.CheckSignature(parsed.SignatureAlgorithm, parsed.RawTBSCertificate, parsed.Signature) == nil
}

// CertSplitLines splits a newline separated API list (alt names) into its non empty elements
func CertSplitLines(value string) []string {
	var result []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

// CertParsePEM parses the first CERTIFICATE block of text
func CertParsePEM(text string) (*x509.Certificate, error) {
	var block = certPEMBlock(text, "CERTIFICATE")
	if block == nil {
		return nil, errors.New("no PEM encoded certificate (-----BEGIN CERTIFICATE-----) found")
	}
	var parsed, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}
	return parsed, nil
}

// CertParseRequestPEM parses the first CERTIFICATE REQUEST block of text
func CertParseRequestPEM(text string) (*x509.CertificateRequest, error) {
	var block = certPEMBlock(text, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
	if block == nil {
		return nil, errors.New("no PEM encoded signing request (-----BEGIN CERTIFICATE REQUEST-----) found")
	}
	var parsed, err = x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid signing request: %w", err)
	}
	if err := parsed.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid signing request: %w", err)
	}
	return parsed, nil
}

func certPEMBlock(text string, types ...string) *pem.Block {
	var rest = []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		for _, wanted := range types {
			if block.Type == wanted {
				return block
			}
		}
	}
}

// CertFingerprint returns the SHA-256 fingerprint like openssl, e.g. FA:2B:…
func CertFingerprint(parsed *x509.Certificate) string {
	var sum = sha256.Sum256(parsed.Raw)
	var parts = make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// CertIssuer is a certificate authority of the trust store which can sign certificates (trust/cert/ca_list)
type CertIssuer struct {
	Refid string `json:"caref"`
	Descr string `json:"descr"`
}

// CertInUseError is returned when removing a certificate other parts of the configuration refer to
type CertInUseError struct {
	Descr string
	Uuid  string
	// Usages are the referring items as OPNsense reports them, e.g. "cron - nightly {cron.jobs.job.<uuid>}", empty
	// when the in_use flag refused the removal before asking OPNsense
	Usages []string
}

func (e *CertInUseError) Error() string {
	var message = fmt.Sprintf("certificate %q (%s) is in use", e.Descr, e.Uuid)
	if len(e.Usages) > 0 {
		message += " by " + strings.Join(e.Usages, ", ")
	}
	return message + ", remove the references first"
}

func (opn *TrustApi) certEndpoint(method string, args ...string) string {
	var endpoint = opn.endpoint("cert", method)
	for _, arg := range args {
		endpoint += "/" + url.PathEscape(arg)
	}
	return endpoint
}

var certUuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// certCheckUuid refuses anything but one uuid: del takes comma separated lists, the path must not be extended
func certCheckUuid(uuid string, what string) error {
	if !certUuidPattern.MatchString(uuid) {
		return fmt.Errorf("cannot %s certificate %q: not a uuid", what, uuid)
	}
	return nil
}

// certPrivateFields are removed from the raw rows: the private key (base64 and PEM)
var certPrivateFields = map[string]bool{"prv": true, "prv_payload": true}

// CertSearch returns the certificates where any column (including the base64 and PEM payloads) contains
// searchPhrase, "" for all, in API order
func (opn *TrustApi) CertSearch(searchPhrase string) ([]Cert, error) {
	var certs, _, err = opn.CertSearchRaw(searchPhrase)
	return certs, err
}

// CertSearchRaw is CertSearch which also returns the raw API rows, without the private key fields (prv,
// prv_payload) and otherwise unchanged (same key order)
func (opn *TrustApi) CertSearchRaw(searchPhrase string) ([]Cert, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.certEndpoint("search"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var certs = make([]Cert, len(rows))
	var redacted = make([]json.RawMessage, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &certs[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected certificate from OPNsense: %w", err)
		}
		if redacted[i], err = certRedact(row); err != nil {
			return nil, nil, fmt.Errorf("unexpected certificate from OPNsense: %w", err)
		}
	}
	return certs, redacted, nil
}

// certRedact removes certPrivateFields from a JSON object, keeping the order of the other keys
func certRedact(row json.RawMessage) (json.RawMessage, error) {
	var decoder = json.NewDecoder(bytes.NewReader(row))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("not a JSON object: %s", row)
	}
	var out bytes.Buffer
	out.WriteByte('{')
	var first = true
	for decoder.More() {
		var keyToken, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		var key, _ = keyToken.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if certPrivateFields[key] {
			continue
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		var encodedKey, _ = json.Marshal(key)
		out.Write(encodedKey)
		out.WriteByte(':')
		var compact bytes.Buffer
		if err := json.Compact(&compact, value); err != nil {
			return nil, err
		}
		out.Write(compact.Bytes())
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// CertList returns all certificates in API order
func (opn *TrustApi) CertList() ([]Cert, error) {
	return opn.CertSearch("")
}

// CertGet returns the certificate with the given uuid (the get endpoint answers option lists, so the list is
// filtered instead)
func (opn *TrustApi) CertGet(uuid string) (Cert, error) {
	if uuid == "" {
		return Cert{}, errors.New("cannot look up a certificate without uuid")
	}
	return opn.certFind(fmt.Sprintf("certificate %s", uuid), func(cert Cert) bool { return strings.EqualFold(cert.Uuid, uuid) })
}

// CertGetByRefid returns the certificate with the given refid
func (opn *TrustApi) CertGetByRefid(refid string) (Cert, error) {
	if refid == "" {
		return Cert{}, errors.New("cannot look up a certificate by an empty refid")
	}
	return opn.certFind(fmt.Sprintf("certificate with refid %s", refid), func(cert Cert) bool { return cert.Refid == refid })
}

// CertGetByDescription returns the only certificate with exactly this description: *coreapi.NotFoundError when
// there is none, *coreapi.TooManyFoundError when there are several
func (opn *TrustApi) CertGetByDescription(description string) (Cert, error) {
	if description == "" {
		return Cert{}, errors.New("cannot look up a certificate by an empty description")
	}
	return opn.certFind(fmt.Sprintf("certificate with description %q", description),
		func(cert Cert) bool { return cert.Descr == description })
}

func (opn *TrustApi) certFind(name string, match func(Cert) bool) (Cert, error) {
	var certs, err = opn.CertList()
	if err != nil {
		return Cert{}, err
	}
	var matching = coreapi.Filter(certs, match)
	switch len(matching) {
	case 0:
		return Cert{}, &coreapi.NotFoundError{Name: name}
	case 1:
		return matching[0], nil
	default:
		var uuids = make([]string, len(matching))
		for i, cert := range matching {
			uuids[i] = cert.Uuid
		}
		return Cert{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%s matches %s", name, strings.Join(uuids, ", "))}
	}
}

// CertIssuers returns the certificate authorities that can be used as CertRequest.IssuerRef, in config order
func (opn *TrustApi) CertIssuers() ([]CertIssuer, error) {
	var container struct {
		Rows []CertIssuer `json:"rows"`
	}
	if err := opn.DoJSON("GET", opn.certEndpoint("ca_list"), nil, &container); err != nil {
		return nil, err
	}
	return container.Rows, nil
}

// CertIssuerByName finds a CA of CertIssuers by refid or description (exact, then case-insensitive) and returns
// its refid
func (opn *TrustApi) CertIssuerByName(name string) (CertIssuer, error) {
	if name == "" {
		return CertIssuer{}, errors.New("no certificate authority given")
	}
	var issuers, err = opn.CertIssuers()
	if err != nil {
		return CertIssuer{}, err
	}
	for _, issuer := range issuers {
		if issuer.Refid == name {
			return issuer, nil
		}
	}
	for _, exact := range []bool{true, false} {
		var matching []CertIssuer
		for _, issuer := range issuers {
			if exact && issuer.Descr == name || !exact && strings.EqualFold(issuer.Descr, name) {
				matching = append(matching, issuer)
			}
		}
		if len(matching) == 1 {
			return matching[0], nil
		}
		if len(matching) > 1 {
			var refids = make([]string, len(matching))
			for i, issuer := range matching {
				refids[i] = issuer.Refid
			}
			return CertIssuer{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("certificate authority %q matches %s, use the refid",
				name, strings.Join(refids, ", "))}
		}
	}
	return CertIssuer{}, &coreapi.NotFoundError{Name: fmt.Sprintf("certificate authority %q", name)}
}

// CertRequest describes a new certificate for CertCreate / CertReplace. Which fields are used depends on Method:
//
//	internal, self-signed: subject, alt names, Type, KeyType, Digest, Lifetime (IssuerRef only for internal)
//	csr:                   subject, alt names, KeyType, Digest
//	import:                CertificatePEM, PrivateKeyPEM (optional)
//	sign-csr:              SigningRequestPEM, IssuerRef, Type, Digest, Lifetime, alt names (the subject comes from
//	                       the request, its extensions are not copied)
//
// Empty values use the OPNsense defaults (CertDefault*)
type CertRequest struct {
	Method      CertMethod
	Description string
	IssuerRef   string // refid of the signing CA, see CertIssuers
	Type        string // CertTypeClient, CertTypeServer, CertTypeCombined, CertTypeCA
	KeyType     string // one of CertKeyTypes
	Digest      string // one of CertDigests
	Lifetime    int    // days

	CommonName         string
	Country            string // two letter code
	State              string
	City               string
	Organization       string
	OrganizationalUnit string
	Email              string

	AltNamesDNS   []string
	AltNamesIP    []string
	AltNamesEmail []string
	AltNamesURI   []string

	CertificatePEM    string
	PrivateKeyPEM     string
	SigningRequestPEM string
}

// certNodeFields are all writable fields, CertReplace sends each of them so nothing of the old record is kept
var certNodeFields = []string{
	"action", "descr", "caref", "cert_type", "key_type", "digest", "lifetime", "private_key_location",
	"commonname", "country", "state", "city", "organization", "organizationalunit", "email", "ocsp_uri",
	"altnames_dns", "altnames_ip", "altnames_email", "altnames_uri",
	"crt", "csr", "prv", "crt_payload", "csr_payload", "prv_payload",
}

var certCountryPattern = regexp.MustCompile(`^[A-Z]{2}$`)

// node checks the request and returns the fields to send, keyed by API name
func (request CertRequest) node() (map[string]string, error) {
	if strings.TrimSpace(request.Description) == "" {
		return nil, errors.New("a certificate needs a description")
	}
	if strings.ContainsAny(request.Description, "\n\r") {
		return nil, errors.New("the description of a certificate must be one line")
	}
	var node = map[string]string{"descr": request.Description}
	var withDefault = func(value string, fallback string) string {
		if value == "" {
			return fallback
		}
		return value
	}
	var oneOf = func(what string, value string, allowed []string) error {
		for _, candidate := range allowed {
			if value == candidate {
				return nil
			}
		}
		return fmt.Errorf("invalid %s %q, use one of %s", what, value, strings.Join(allowed, ", "))
	}

	var subject = func(required bool) error {
		if required && strings.TrimSpace(request.CommonName) == "" {
			return fmt.Errorf("method %s needs a common name", request.Method)
		}
		var country = withDefault(request.Country, CertDefaultCountry)
		if !certCountryPattern.MatchString(country) {
			return fmt.Errorf("invalid country %q, use a two letter code like NL", request.Country)
		}
		for _, field := range []struct{ name, value string }{
			{"commonname", request.CommonName}, {"state", request.State}, {"city", request.City},
			{"organization", request.Organization}, {"organizationalunit", request.OrganizationalUnit},
			{"email", request.Email},
		} {
			if strings.ContainsAny(field.value, "\n\r") {
				return fmt.Errorf("%s must be one line", field.name)
			}
			node[field.name] = field.value
		}
		node["country"] = country
		return nil
	}
	var altNames = func() error {
		for _, ip := range request.AltNamesIP {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid IP address alt name %q", ip)
			}
		}
		for _, email := range request.AltNamesEmail {
			if !strings.Contains(email, "@") {
				return fmt.Errorf("invalid email alt name %q", email)
			}
		}
		for _, uri := range request.AltNamesURI {
			if parsed, err := url.Parse(uri); err != nil || parsed.Scheme == "" {
				return fmt.Errorf("invalid URI alt name %q, use an absolute URI like https://host.example/", uri)
			}
		}
		for _, list := range []struct {
			name   string
			values []string
		}{{"altnames_dns", request.AltNamesDNS}, {"altnames_ip", request.AltNamesIP},
			{"altnames_email", request.AltNamesEmail}, {"altnames_uri", request.AltNamesURI}} {
			for _, value := range list.values {
				if value == "" || strings.ContainsAny(value, "\n\r,") {
					return fmt.Errorf("invalid alt name %q", value)
				}
			}
			node[list.name] = strings.Join(list.values, "\n")
		}
		return nil
	}
	var signing = func(withKey bool) error {
		var certType = withDefault(request.Type, CertDefaultType)
		if err := oneOf("certificate type", certType, []string{CertTypeClient, CertTypeServer, CertTypeCombined, CertTypeCA}); err != nil {
			return err
		}
		node["cert_type"] = certType
		var digest = withDefault(request.Digest, CertDefaultDigest)
		if err := oneOf("digest", digest, CertDigests); err != nil {
			return err
		}
		node["digest"] = digest
		var lifetime = request.Lifetime
		if lifetime == 0 {
			lifetime = CertDefaultLifetime
		}
		if lifetime < 1 {
			return fmt.Errorf("invalid lifetime %d, it is a number of days", lifetime)
		}
		node["lifetime"] = strconv.Itoa(lifetime)
		if withKey {
			var keyType = withDefault(request.KeyType, CertDefaultKeyType)
			if err := oneOf("key type", keyType, CertKeyTypes); err != nil {
				return err
			}
			node["key_type"] = keyType
		}
		return nil
	}
	var unused = func(fields map[string]bool) error {
		for name, given := range fields {
			if given {
				return fmt.Errorf("method %s does not use %s", request.Method, name)
			}
		}
		return nil
	}
	var hasSubject = request.CommonName != "" || request.Country != "" || request.State != "" || request.City != "" ||
		request.Organization != "" || request.OrganizationalUnit != "" || request.Email != ""
	var hasAltNames = len(request.AltNamesDNS)+len(request.AltNamesIP)+len(request.AltNamesEmail)+len(request.AltNamesURI) > 0

	switch request.Method {
	case CertMethodInternal, CertMethodSelfSigned:
		if request.Method == CertMethodInternal && request.IssuerRef == "" {
			return nil, errors.New("method internal needs the certificate authority (issuer) that signs the certificate, use self-signed without one")
		}
		if err := unused(map[string]bool{"an issuer": request.Method == CertMethodSelfSigned && request.IssuerRef != "",
			"a certificate": request.CertificatePEM != "", "a private key": request.PrivateKeyPEM != "",
			"a signing request": request.SigningRequestPEM != ""}); err != nil {
			return nil, err
		}
		node["action"], node["caref"], node["private_key_location"] = "internal", request.IssuerRef, "firewall"
		if err := subject(true); err != nil {
			return nil, err
		}
		if err := altNames(); err != nil {
			return nil, err
		}
		if err := signing(true); err != nil {
			return nil, err
		}
	case CertMethodSigningRequest:
		if err := unused(map[string]bool{"an issuer": request.IssuerRef != "", "a type": request.Type != "",
			"a lifetime": request.Lifetime != 0, "a certificate": request.CertificatePEM != "",
			"a private key": request.PrivateKeyPEM != "", "a signing request": request.SigningRequestPEM != ""}); err != nil {
			return nil, err
		}
		node["action"] = "external"
		if err := subject(true); err != nil {
			return nil, err
		}
		if err := altNames(); err != nil {
			return nil, err
		}
		if err := signing(true); err != nil {
			return nil, err
		}
		delete(node, "cert_type") // the request is created with the v3_req extensions
		delete(node, "lifetime")
	case CertMethodImport:
		if err := unused(map[string]bool{"an issuer": request.IssuerRef != "", "a type": request.Type != "",
			"a key type": request.KeyType != "", "a digest": request.Digest != "", "a lifetime": request.Lifetime != 0,
			"subject fields": hasSubject, "alt names": hasAltNames,
			"a signing request": request.SigningRequestPEM != ""}); err != nil {
			return nil, err
		}
		if _, err := CertParsePEM(request.CertificatePEM); err != nil {
			return nil, err
		}
		if request.PrivateKeyPEM != "" {
			if _, err := tls.X509KeyPair([]byte(request.CertificatePEM), []byte(request.PrivateKeyPEM)); err != nil {
				return nil, fmt.Errorf("the private key does not belong to the certificate (or is encrypted / invalid): %w", err)
			}
		}
		node["action"], node["crt_payload"], node["prv_payload"] = "import", request.CertificatePEM, request.PrivateKeyPEM
	case CertMethodSignRequest:
		if request.IssuerRef == "" {
			return nil, errors.New("method sign-csr needs the certificate authority (issuer) that signs the request")
		}
		if err := unused(map[string]bool{"a key type": request.KeyType != "", "subject fields": hasSubject,
			"a certificate": request.CertificatePEM != "", "a private key": request.PrivateKeyPEM != ""}); err != nil {
			return nil, err
		}
		if _, err := CertParseRequestPEM(request.SigningRequestPEM); err != nil {
			return nil, err
		}
		node["action"], node["caref"], node["csr_payload"] = "sign_csr", request.IssuerRef, request.SigningRequestPEM
		if err := altNames(); err != nil {
			return nil, err
		}
		if err := signing(false); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown method %q", request.Method)
	}
	return node, nil
}

type certContainer struct {
	Cert map[string]string `json:"cert"`
}

// certMutate sends add / set and turns the HTTP 500 answers of failing actions into readable errors
func (opn *TrustApi) certMutate(what string, endpoint string, node map[string]string) (string, error) {
	var uuid, err = opn.Mutate(endpoint, certContainer{Cert: node})
	if err != nil {
		var httpErr *coreapi.HttpError
		if errors.As(err, &httpErr) && httpErr.StatusCode == 500 && httpErr.Message != "" {
			return "", fmt.Errorf("%s: OPNsense refused it: %s", what, strings.TrimSpace(httpErr.Message))
		}
		return "", err
	}
	return uuid, nil
}

// CertCreate creates a certificate (or signing request) as described by request and returns its uuid
func (opn *TrustApi) CertCreate(request CertRequest) (string, error) {
	var node, err = request.node()
	if err != nil {
		return "", err
	}
	if err := opn.certCheckIssuer(request.IssuerRef); err != nil {
		return "", err
	}
	var uuid, mutateErr = opn.certMutate("creating the certificate", opn.certEndpoint("add"), node)
	if mutateErr != nil {
		return "", mutateErr
	}
	if uuid == "" {
		return "", errors.New("OPNsense saved the certificate but did not answer its uuid")
	}
	return uuid, nil
}

// CertReplace replaces the certificate uuid completely by a new one as described by request. The record keeps its
// uuid and refid, so references to it (services using the certificate) stay valid; services are not restarted
func (opn *TrustApi) CertReplace(uuid string, request CertRequest) error {
	if err := certCheckUuid(uuid, "replace"); err != nil {
		return err
	}
	var node, err = request.node()
	if err != nil {
		return err
	}
	if err := opn.certCheckIssuer(request.IssuerRef); err != nil {
		return err
	}
	var existing, getErr = opn.CertGet(uuid)
	if getErr != nil {
		return getErr
	}
	if existing.IsExternal() {
		return fmt.Errorf("certificate %q is managed outside the trust store and can not be replaced", existing.Descr)
	}
	// send every field: the old subject, alt names and payloads would be merged otherwise
	for _, field := range certNodeFields {
		if _, given := node[field]; !given {
			node[field] = ""
		}
	}
	_, err = opn.certMutate("replacing the certificate", opn.certEndpoint("set", uuid), node)
	return certSetNotFound(uuid, err)
}

// certCheckIssuer verifies that refid ("" for none) is a CA of the trust store, OPNsense would answer a validation
// error for unknown ones but only after the key was created
func (opn *TrustApi) certCheckIssuer(refid string) error {
	if refid == "" {
		return nil
	}
	var issuers, err = opn.CertIssuers()
	if err != nil {
		return err
	}
	for _, issuer := range issuers {
		if issuer.Refid == refid {
			return nil
		}
	}
	return &coreapi.NotFoundError{Name: fmt.Sprintf("certificate authority with refid %s", refid)}
}

// certSetNotFound maps the bare {"result":"failed"} of set on an unknown uuid to *NotFoundError
func certSetNotFound(uuid string, err error) error {
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: fmt.Sprintf("certificate %s", uuid), Err: err}
	}
	return err
}

// CertPatch holds the fields CertUpdate can change, nil fields are kept. Everything else is part of the
// certificate itself, use CertReplace or CertReissue
type CertPatch struct {
	Description *string
}

// CertUpdate changes the non nil fields of patch on the certificate uuid. It never touches the certificate, key or
// request (see the package notes on action). The certificate is looked up first: set on an unknown (version 4)
// uuid would create a record
func (opn *TrustApi) CertUpdate(uuid string, patch CertPatch) error {
	if err := certCheckUuid(uuid, "update"); err != nil {
		return err
	}
	var node = map[string]string{"action": "manual"}
	if patch.Description != nil {
		if strings.TrimSpace(*patch.Description) == "" {
			return errors.New("a certificate needs a description")
		}
		if strings.ContainsAny(*patch.Description, "\n\r") {
			return errors.New("the description of a certificate must be one line")
		}
		node["descr"] = *patch.Description
	}
	var cert, err = opn.CertGet(uuid)
	if err != nil {
		return err
	}
	if cert.IsExternal() {
		return fmt.Errorf("certificate %q is managed outside the trust store and can not be changed", cert.Descr)
	}
	_, err = opn.certMutate("updating the certificate", opn.certEndpoint("set", uuid), node)
	return certSetNotFound(uuid, err)
}

// CertReissue signs a new certificate for the stored key and subject of the certificate uuid, by the same CA,
// valid for lifetime days (0: 397) with digest ("" keeps the current one). Self-signed certificates can not be
// reissued (OPNsense answers "missing CA key"), neither can certificates without stored key
func (opn *TrustApi) CertReissue(uuid string, lifetime int, digest string) error {
	if err := certCheckUuid(uuid, "reissue"); err != nil {
		return err
	}
	var cert, err = opn.CertGet(uuid)
	if err != nil {
		return err
	}
	switch {
	case cert.IsExternal():
		return fmt.Errorf("certificate %q is managed outside the trust store and can not be reissued", cert.Descr)
	case cert.IsPending():
		return fmt.Errorf("certificate %q is a pending signing request, import the signed certificate instead", cert.Descr)
	case !cert.HasPrivateKey:
		return fmt.Errorf("certificate %q has no stored private key, it can not be reissued", cert.Descr)
	case cert.Caref == "":
		return fmt.Errorf("certificate %q is not issued by a certificate authority of the trust store, it can not be reissued", cert.Descr)
	}
	if lifetime == 0 {
		lifetime = CertDefaultLifetime
	}
	if lifetime < 1 {
		return fmt.Errorf("invalid lifetime %d, it is a number of days", lifetime)
	}
	var node = map[string]string{"action": "reissue", "lifetime": strconv.Itoa(lifetime)}
	if digest != "" {
		var valid = false
		for _, candidate := range CertDigests {
			valid = valid || candidate == digest
		}
		if !valid {
			return fmt.Errorf("invalid digest %q, use one of %s", digest, strings.Join(CertDigests, ", "))
		}
		node["digest"] = digest
	}
	_, err = opn.certMutate("reissuing the certificate", opn.certEndpoint("set", uuid), node)
	return certSetNotFound(uuid, err)
}

// CertImportSigned stores certificatePEM, the CA signed certificate of the pending signing request uuid (created
// with CertMethodSigningRequest). The certificate must belong to the request's key and OPNsense checks that it
// verifies against the trust store
func (opn *TrustApi) CertImportSigned(uuid string, certificatePEM string) error {
	if err := certCheckUuid(uuid, "import into"); err != nil {
		return err
	}
	var parsed, parseErr = CertParsePEM(certificatePEM)
	if parseErr != nil {
		return parseErr
	}
	var cert, err = opn.CertGet(uuid)
	if err != nil {
		return err
	}
	if cert.SigningRequestPEM == "" || !cert.HasPrivateKey {
		return fmt.Errorf("certificate %q is not a pending signing request with a key on this firewall (add method=csr)", cert.Descr)
	}
	var request, requestErr = CertParseRequestPEM(cert.SigningRequestPEM)
	if requestErr != nil {
		return fmt.Errorf("the stored signing request of %q: %w", cert.Descr, requestErr)
	}
	if !certSameKey(parsed, request) {
		return fmt.Errorf("the certificate does not belong to the signing request of %q (different public key)", cert.Descr)
	}
	var node = map[string]string{"action": "import_csr", "crt_payload": certificatePEM}
	_, err = opn.certMutate("importing the signed certificate", opn.certEndpoint("set", uuid), node)
	return certSetNotFound(uuid, err)
}

func certSameKey(cert *x509.Certificate, request *x509.CertificateRequest) bool {
	var key, ok = cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return key.Equal(request.PublicKey)
}

// CertRemove deletes the certificate uuid. Certificates in use are refused with *CertInUseError (OPNsense refuses
// them as well), unknown ones are *coreapi.NotFoundError
func (opn *TrustApi) CertRemove(uuid string) error {
	if err := certCheckUuid(uuid, "remove"); err != nil {
		return err
	}
	var cert, err = opn.CertGet(uuid)
	if err != nil {
		return err
	}
	if cert.IsExternal() {
		return fmt.Errorf("certificate %q is managed outside the trust store and can not be removed", cert.Descr)
	}
	if cert.InUseFlag() {
		return &CertInUseError{Descr: cert.Descr, Uuid: cert.Uuid}
	}

	if _, err := opn.Mutate(opn.certEndpoint("del", uuid), nil); err != nil {
		var httpErr *coreapi.HttpError
		switch {
		case coreapi.IsNotFound(err):
			return &coreapi.NotFoundError{Name: fmt.Sprintf("certificate %s", uuid), Err: err}
		case errors.As(err, &httpErr) && httpErr.StatusCode == 500 && httpErr.Message != "":
			// "Item in use by": one "<module> - <description> {<reference>}" per line
			return &CertInUseError{Descr: cert.Descr, Uuid: cert.Uuid, Usages: CertSplitLines(httpErr.Message)}
		}
		return err
	}
	return nil
}

// CertDump returns the openssl text dump (with the SHA-256 fingerprint) of the certificate uuid, or of its signing
// request when it is pending
func (opn *TrustApi) CertDump(uuid string) (string, error) {
	if err := certCheckUuid(uuid, "dump"); err != nil {
		return "", err
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", opn.certEndpoint("raw_dump", uuid), nil, &raw); err != nil {
		return "", err
	}
	if trimmed := bytes.TrimSpace(raw); bytes.Equal(trimmed, []byte("[]")) || bytes.Equal(trimmed, []byte("{}")) {
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("certificate %s", uuid)}
	}
	var dump struct {
		ExitStatus int    `json:"exit_status"`
		Stdout     string `json:"stdout"`
		Stderr     string `json:"stderr"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return "", fmt.Errorf("unexpected answer from raw_dump: %w", err)
	}
	if dump.ExitStatus != 0 {
		return "", fmt.Errorf("openssl could not dump certificate %s: %s", uuid, strings.TrimSpace(dump.Stderr))
	}
	return dump.Stdout, nil
}

// CertExport returns a part of the certificate uuid: CertExportCertificate, CertExportPrivateKey or
// CertExportSigningRequest as PEM, CertExportPKCS12 as binary PKCS #12 (certificate, key and CA chain) encrypted
// with password (only used for pkcs12, "" for none). filename is the name the GUI suggests (<descr>_crt.pem,
// <descr>_cert.p12), made safe for a file name
func (opn *TrustApi) CertExport(uuid string, format string, password string) (content []byte, filename string, err error) {
	if err := certCheckUuid(uuid, "export"); err != nil {
		return nil, "", err
	}
	switch format {
	case CertExportCertificate, CertExportPrivateKey, CertExportSigningRequest, CertExportPKCS12:
	default:
		return nil, "", fmt.Errorf("unknown export format %q, use crt, prv, csr or pkcs12", format)
	}
	if password != "" && format != CertExportPKCS12 {
		return nil, "", errors.New("a password is only used for the pkcs12 format")
	}

	var body any
	if password != "" {
		body = map[string]string{"password": password}
	}
	var answer struct {
		Status     string `json:"status"`
		Descr      string `json:"descr"`
		Error      string `json:"error"`
		Payload    string `json:"payload"`
		PayloadB64 string `json:"payload_b64"`
	}
	if err := opn.DoJSON("POST", opn.certEndpoint("generate_file", uuid, format), body, &answer); err != nil {
		return nil, "", err
	}
	if answer.Status != "ok" {
		if answer.Descr == "" && strings.Contains(answer.Error, "Missing certificate") {
			return nil, "", &coreapi.NotFoundError{Name: fmt.Sprintf("certificate %s", uuid)}
		}
		var message = strings.TrimSpace(answer.Error)
		if format == CertExportPKCS12 && strings.Contains(message, "PEM routines") {
			message = "it needs a certificate and its private key (" + message + ")"
		}
		if message == "" {
			message = fmt.Sprintf("status %q", answer.Status)
		}
		return nil, "", fmt.Errorf("exporting %s of certificate %q failed: %s", format, answer.Descr, message)
	}

	var names = map[string]string{
		CertExportCertificate: "certificate", CertExportPrivateKey: "private key", CertExportSigningRequest: "signing request",
	}
	if format == CertExportPKCS12 {
		if content, err = base64.StdEncoding.DecodeString(answer.PayloadB64); err != nil {
			return nil, "", fmt.Errorf("unexpected PKCS #12 payload: %w", err)
		}
		if len(content) == 0 {
			return nil, "", fmt.Errorf("exporting pkcs12 of certificate %q failed: empty answer", answer.Descr)
		}
		return content, CertSafeFilename(answer.Descr) + "_cert.p12", nil
	}
	if answer.Payload == "" {
		return nil, "", fmt.Errorf("certificate %q has no %s", answer.Descr, names[format])
	}
	return []byte(answer.Payload), CertSafeFilename(answer.Descr) + "_" + format + ".pem", nil
}

var certUnsafeFilename = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// CertSafeFilename turns a description into a file name without path separators, spaces or other special
// characters ("cert" when nothing is left)
func CertSafeFilename(description string) string {
	var name = strings.Trim(certUnsafeFilename.ReplaceAllString(description, "_"), "_.")
	if name == "" {
		return "cert"
	}
	return name
}
