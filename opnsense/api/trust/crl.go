package trust

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	coreapi "opnsense-cli/opnsense/api"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// System > Trust > Revocation (api/trust/crl). This is not a model controller: every certificate authority has at
// most one revocation list, addressed by the refid of the CA (caref). set/<caref> creates or replaces the list
// completely: an internal list is (re)built and signed from the revoked certificates sent as
// revoked_reason_<code>=<comma separated cert refids>, an imported list ("existing") is stored as given. set
// answers {"status":"saved"} / {"status":"failed","validations":{…}}, del {"status":"deleted"|"not found"}.

const (
	// CrlMethodInternal is a list built and signed by OPNsense from the revoked certificates (needs the CA key)
	CrlMethodInternal = "internal"
	// CrlMethodImport is an imported list, stored as given
	CrlMethodImport = "existing"
	// CrlDefaultLifetime is the lifetime in days OPNsense proposes for a new list
	CrlDefaultLifetime = "9999"
	// CrlMaxLifetime is the largest lifetime (days) accepted here, OPNsense itself does not validate it and fails
	// with an internal error for anything that is not a number
	CrlMaxLifetime = 99999
)

// CrlReason is a revocation reason (RFC 5280 CRLReason) as OPNsense supports them
type CrlReason struct {
	Code string // the API code, the <code> of revoked_reason_<code>
	Name string // the RFC 5280 name, e.g. keyCompromise
}

// CrlReasons are the reasons OPNsense offers, in code order
var CrlReasons = []CrlReason{
	{"0", "unspecified"},
	{"1", "keyCompromise"},
	{"2", "cACompromise"},
	{"3", "affiliationChanged"},
	{"4", "superseded"},
	{"5", "cessationOfOperation"},
	{"6", "certificateHold"},
}

// CrlReasonName returns the RFC 5280 name of an API reason code, the code itself when unknown
func CrlReasonName(code string) string {
	for _, reason := range CrlReasons {
		if reason.Code == code {
			return reason.Name
		}
	}
	return code
}

func crlValidReason(code string) bool {
	for _, reason := range CrlReasons {
		if reason.Code == code {
			return true
		}
	}
	return false
}

// CrlAuthority is a row of trust/crl/search: one per certificate authority, with or without a revocation list
type CrlAuthority struct {
	Refid string `json:"refid"`
	Descr string `json:"descr"` // of the CA
	// CrlDescr is the description of the revocation list, nil when the CA has none
	CrlDescr *string `json:"crl_descr"`
}

// HasCrl tells whether the CA has a revocation list
func (a CrlAuthority) HasCrl() bool {
	return a.CrlDescr != nil
}

// CrlCertificateRef is a certificate get/<caref> offers for the list: a certificate issued by the CA, or one on
// the list (also when the certificate itself was deleted since)
type CrlCertificateRef struct {
	Refid string
	Descr string
	// Reason is the code of the revocation reason, "" when the certificate is not revoked
	Reason string
}

// Crl is the revocation list of a CA as returned by get/<caref>. Without a list OPNsense answers defaults (no
// description, serial 0, lifetime 9999, method internal), see Exists
type Crl struct {
	Caref string
	Descr string
	// Serial is the CRL number of the current list, the next update increments it
	Serial string
	// Lifetime of an internal list in days
	Lifetime string
	// Method is CrlMethodInternal or CrlMethodImport
	Method string
	// Text is the list in PEM format ("" without list)
	Text string
	// Certificates are the certificates the list can revoke (sorted by description), see Revoked
	Certificates []CrlCertificateRef
}

// Exists tells whether the CA has a revocation list (OPNsense requires a description for it)
func (crl *Crl) Exists() bool {
	return crl.Descr != "" || crl.Text != ""
}

// Imported tells whether the list was imported rather than built by OPNsense
func (crl *Crl) Imported() bool {
	return crl.Method == CrlMethodImport
}

// Revoked returns the certificates OPNsense revokes on an internal list. Imported lists have none here, their
// entries are only in Text (see Parse)
func (crl *Crl) Revoked() []CrlCertificateRef {
	return coreapi.Filter(crl.Certificates, func(ref CrlCertificateRef) bool { return ref.Reason != "" })
}

// Parse decodes Text (PEM, or DER) into the X.509 revocation list: update times, CRL number and the entries with
// serial, date and reason. OPNsense rebuilds an internal list on every change, so the revocation dates of its
// entries are the time of the last change, see CrlRevocationTimes for the real ones
func (crl *Crl) Parse() (*x509.RevocationList, error) {
	return CrlParse(crl.Text)
}

// CrlParse decodes a revocation list in PEM (the first X509 CRL block) or DER format
func CrlParse(text string) (*x509.RevocationList, error) {
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("empty revocation list")
	}
	var der = []byte(text)
	if block, _ := pem.Decode([]byte(text)); block != nil {
		der = block.Bytes
	}
	var list, err = x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("invalid revocation list: %w", err)
	}
	return list, nil
}

// CrlSerialHex renders a certificate serial number like openssl does: upper case hex with an even number of
// digits, e.g. 01 or 7CA97B
func CrlSerialHex(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	var hex = strings.ToUpper(serial.Text(16))
	if len(hex)%2 == 1 {
		hex = "0" + hex
	}
	return hex
}

// CrlParseSerial parses a serial number in hex like openssl prints it, optionally with 0x prefix or colons
// (01, 0x1, 7c:a9:7b)
func CrlParseSerial(text string) (*big.Int, bool) {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(strings.TrimPrefix(text, "0x"), "0X")
	text = strings.ReplaceAll(text, ":", "")
	if text == "" {
		return nil, false
	}
	var serial, ok = new(big.Int).SetString(text, 16)
	if !ok || serial.Sign() < 0 {
		return nil, false
	}
	return serial, true
}

func (opn *TrustApi) crlEndpoint(method string, caref string) (string, error) {
	if caref == "" || strings.ContainsAny(caref, "/?#") {
		return "", fmt.Errorf("invalid certificate authority reference %q", caref)
	}
	return opn.endpoint("crl", method) + "/" + caref, nil
}

// CrlList returns one entry per certificate authority, in API order
func (opn *TrustApi) CrlList() ([]CrlAuthority, error) {
	var authorities, _, err = opn.CrlListRaw()
	return authorities, err
}

// CrlListRaw is CrlList with the rows as OPNsense sent them
func (opn *TrustApi) CrlListRaw() ([]CrlAuthority, []json.RawMessage, error) {
	var rows, err = coreapi.Search[json.RawMessage](opn.OPNsense, opn.endpoint("crl", "search"), "")
	if err != nil {
		return nil, nil, err
	}
	var authorities = make([]CrlAuthority, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &authorities[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected revocation list row from OPNsense: %w", err)
		}
	}
	return authorities, rows, nil
}

// CrlGetRaw returns the "crl" object of get/<caref> as OPNsense sends it, *NotFoundError for an unknown CA
func (opn *TrustApi) CrlGetRaw(caref string) (json.RawMessage, error) {
	var endpoint, err = opn.crlEndpoint("get", caref)
	if err != nil {
		return nil, err
	}
	var answer struct {
		Crl json.RawMessage `json:"crl"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return nil, err
	}
	// an unknown CA is answered with {"caref":"","descr":""}
	if len(answer.Crl) == 0 || string(answer.Crl) == "null" {
		return nil, &coreapi.NotFoundError{Name: "certificate authority " + caref}
	}
	return answer.Crl, nil
}

// CrlGet returns the revocation list of the CA caref (check Exists), *NotFoundError for an unknown CA
func (opn *TrustApi) CrlGet(caref string) (*Crl, error) {
	var raw, err = opn.CrlGetRaw(caref)
	if err != nil {
		return nil, err
	}
	return crlDecode(raw)
}

// crlOption is an entry of an option list of get: {"value":"description","selected":"1"}
type crlOption struct {
	Value    string          `json:"value"`
	Selected json.RawMessage `json:"selected"`
}

func (o crlOption) selected() bool {
	switch strings.Trim(string(o.Selected), `"`) {
	case "1", "true":
		return true
	}
	return false
}

// crlOptions decodes an option list, PHP sends an empty one as []
func crlOptions(raw json.RawMessage) (map[string]crlOption, error) {
	var options map[string]crlOption
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] == '[' || string(trimmed) == "null" {
		return options, nil
	}
	if err := json.Unmarshal(raw, &options); err != nil {
		return nil, err
	}
	return options, nil
}

func crlDecode(raw json.RawMessage) (*Crl, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("unexpected revocation list from OPNsense: %w", err)
	}
	var text = func(name string) string {
		var value string
		_ = json.Unmarshal(fields[name], &value)
		return value
	}
	var crl = &Crl{Caref: text("caref"), Descr: text("descr"), Serial: text("serial"), Lifetime: text("lifetime"), Text: text("text")}

	methods, err := crlOptions(fields["crlmethod"])
	if err != nil {
		return nil, fmt.Errorf("unexpected crlmethod from OPNsense: %w", err)
	}
	crl.Method = CrlMethodInternal
	for method, option := range methods {
		if option.selected() {
			crl.Method = method
		}
	}

	var refs = map[string]*CrlCertificateRef{}
	for _, reason := range CrlReasons {
		options, err := crlOptions(fields["revoked_reason_"+reason.Code])
		if err != nil {
			return nil, fmt.Errorf("unexpected revoked_reason_%s from OPNsense: %w", reason.Code, err)
		}
		for refid, option := range options {
			var ref = refs[refid]
			if ref == nil {
				ref = &CrlCertificateRef{Refid: refid, Descr: option.Value}
				refs[refid] = ref
			}
			if option.selected() {
				ref.Reason = reason.Code
			}
		}
	}
	for _, ref := range refs {
		crl.Certificates = append(crl.Certificates, *ref)
	}
	sort.Slice(crl.Certificates, func(i, j int) bool {
		var a, b = crl.Certificates[i], crl.Certificates[j]
		if a.Descr != b.Descr {
			return a.Descr < b.Descr
		}
		return a.Refid < b.Refid
	})
	return crl, nil
}

// CrlSettings is a complete revocation list for set/<caref>
type CrlSettings struct {
	Descr string
	// Lifetime in days, CrlDefaultLifetime when empty. Also stored for imported lists
	Lifetime string
	// Method is CrlMethodInternal or CrlMethodImport
	Method string
	// Text is the list to import (PEM), only for CrlMethodImport
	Text string
	// Revoked maps the refids of the revoked certificates to their reason code, only for CrlMethodInternal.
	// Certificates not in here are not (or no longer) revoked
	Revoked map[string]string
}

// CrlValidateDescription checks a list description like OPNsense: 1-255 characters, no line breaks
func CrlValidateDescription(descr string) error {
	if descr == "" {
		return errors.New("the description must not be empty")
	}
	if utf8.RuneCountInString(descr) > 255 {
		return errors.New("the description must be at most 255 characters")
	}
	if strings.ContainsAny(descr, "\r\n") {
		return errors.New("the description must not contain line breaks")
	}
	return nil
}

// CrlValidateLifetime checks a lifetime in days (OPNsense fails with an internal error for non numbers)
func CrlValidateLifetime(lifetime string) error {
	var days, err = strconv.Atoi(lifetime)
	if err != nil || days < 1 || days > CrlMaxLifetime {
		return fmt.Errorf("the lifetime must be a number of days from 1 to %d, got %q", CrlMaxLifetime, lifetime)
	}
	return nil
}

// CrlSet creates or replaces the revocation list of the CA caref. It checks first that the CA exists (OPNsense
// stores an imported list for any caref) and that the revoked certificates are offered for this CA (OPNsense
// revokes any certificate by refid, also those of other CAs)
func (opn *TrustApi) CrlSet(caref string, settings CrlSettings) error {
	var current, err = opn.CrlGet(caref)
	if err != nil {
		return err
	}
	return opn.crlSet(current, settings)
}

func (opn *TrustApi) crlSet(current *Crl, settings CrlSettings) error {
	if settings.Lifetime == "" {
		settings.Lifetime = CrlDefaultLifetime
	}
	if err := CrlValidateDescription(settings.Descr); err != nil {
		return err
	}
	if err := CrlValidateLifetime(settings.Lifetime); err != nil {
		return err
	}

	var payload = map[string]string{
		"descr":     settings.Descr,
		"lifetime":  settings.Lifetime,
		"crlmethod": settings.Method,
	}
	switch settings.Method {
	case CrlMethodImport:
		if len(settings.Revoked) > 0 {
			return errors.New("an imported revocation list can not revoke certificates")
		}
		if _, err := CrlParse(settings.Text); err != nil {
			return err
		}
		payload["text"] = settings.Text
	case CrlMethodInternal:
		if settings.Text != "" {
			return errors.New("an internal revocation list is built by OPNsense, it takes no text")
		}
		var offered = map[string]bool{}
		for _, ref := range current.Certificates {
			offered[ref.Refid] = true
		}
		var byReason = map[string][]string{}
		for refid, reason := range settings.Revoked {
			if !offered[refid] {
				return &coreapi.NotFoundError{Name: fmt.Sprintf("certificate %s of the certificate authority %s", refid, current.Caref)}
			}
			if !crlValidReason(reason) {
				return fmt.Errorf("invalid revocation reason %q for certificate %s", reason, refid)
			}
			byReason[reason] = append(byReason[reason], refid)
		}
		// every reason is sent: the certificates not listed are unrevoked
		for _, reason := range CrlReasons {
			var refids = byReason[reason.Code]
			sort.Strings(refids)
			payload["revoked_reason_"+reason.Code] = strings.Join(refids, ",")
		}
	default:
		return fmt.Errorf("invalid method %q, use %s or %s", settings.Method, CrlMethodInternal, CrlMethodImport)
	}

	endpoint, err := opn.crlEndpoint("set", current.Caref)
	if err != nil {
		return err
	}
	return opn.crlStatus(endpoint, map[string]any{"crl": payload}, "saved")
}

// crlStatus POSTs to set / del, which answer {"status":…} instead of the {"result":…} of model controllers
func (opn *TrustApi) crlStatus(endpoint string, body any, success string) error {
	var answer struct {
		Status      string                     `json:"status"`
		Validations coreapi.ValidationMessages `json:"validations"`
	}
	if err := opn.DoJSON("POST", endpoint, body, &answer); err != nil {
		return err
	}
	switch answer.Status {
	case success:
		return nil
	case "not found":
		return &coreapi.NotFoundError{Name: endpoint}
	case "failed":
		if len(answer.Validations) == 0 {
			return fmt.Errorf("OPNsense refused %s", endpoint)
		}
		return &coreapi.ValidationError{Validations: answer.Validations}
	default:
		return fmt.Errorf("unexpected status from %s: %q", endpoint, answer.Status)
	}
}

// CrlImport creates or replaces the revocation list of the CA caref with an imported one (PEM). OPNsense checks
// that it is a CRL, not that the CA issued it
func (opn *TrustApi) CrlImport(caref string, descr string, text string) error {
	return opn.CrlSet(caref, CrlSettings{Descr: descr, Method: CrlMethodImport, Text: text})
}

// crlInternal returns the existing internal list of caref, errors for missing and imported lists
func (opn *TrustApi) crlInternal(caref string) (*Crl, error) {
	var crl, err = opn.CrlGet(caref)
	if err != nil {
		return nil, err
	}
	if !crl.Exists() {
		return nil, &coreapi.NotFoundError{Name: "revocation list of the certificate authority " + caref}
	}
	if crl.Imported() {
		return nil, fmt.Errorf("the revocation list of the certificate authority %s is imported, certificates can only be revoked on an internal list", caref)
	}
	return crl, nil
}

func crlRevokedMap(crl *Crl) map[string]string {
	var revoked = map[string]string{}
	for _, ref := range crl.Revoked() {
		revoked[ref.Refid] = ref.Reason
	}
	return revoked
}

func crlUpdate(crl *Crl, revoked map[string]string) CrlSettings {
	return CrlSettings{Descr: crl.Descr, Lifetime: crl.Lifetime, Method: CrlMethodInternal, Revoked: revoked}
}

// CrlRevoke adds certificates (refids) with the reason code to the existing internal list of caref, or changes
// the reason of certificates on it. The list is rebuilt and signed
func (opn *TrustApi) CrlRevoke(caref string, reason string, refids ...string) error {
	if len(refids) == 0 {
		return errors.New("no certificate to revoke")
	}
	if !crlValidReason(reason) {
		return fmt.Errorf("invalid revocation reason %q", reason)
	}
	var crl, err = opn.crlInternal(caref)
	if err != nil {
		return err
	}
	var revoked = crlRevokedMap(crl)
	for _, refid := range refids {
		revoked[refid] = reason
	}
	return opn.crlSet(crl, crlUpdate(crl, revoked))
}

// CrlUnrevoke removes certificates (refids) from the internal list of caref, *NotFoundError when one of them
// is not on it
func (opn *TrustApi) CrlUnrevoke(caref string, refids ...string) error {
	if len(refids) == 0 {
		return errors.New("no certificate to unrevoke")
	}
	var crl, err = opn.crlInternal(caref)
	if err != nil {
		return err
	}
	var revoked = crlRevokedMap(crl)
	for _, refid := range refids {
		if _, ok := revoked[refid]; !ok {
			return &coreapi.NotFoundError{Name: fmt.Sprintf("certificate %s on the revocation list of %s", refid, caref)}
		}
		delete(revoked, refid)
	}
	return opn.crlSet(crl, crlUpdate(crl, revoked))
}

// CrlRemove deletes the revocation list of the CA caref, *NotFoundError when it has none
func (opn *TrustApi) CrlRemove(caref string) error {
	var endpoint, err = opn.crlEndpoint("del", caref)
	if err != nil {
		return err
	}
	if err := opn.crlStatus(endpoint, nil, "deleted"); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: "revocation list of the certificate authority " + caref}
		}
		return err
	}
	return nil
}

// CrlDump returns the list as text (openssl crl -fingerprint -sha256 -text on the firewall), *NotFoundError when
// the CA has no list
func (opn *TrustApi) CrlDump(caref string) (string, error) {
	var endpoint, err = opn.crlEndpoint("raw_dump", caref)
	if err != nil {
		return "", err
	}
	var raw json.RawMessage
	if err := opn.DoJSON("GET", endpoint, nil, &raw); err != nil {
		return "", err
	}
	// without list (or for an unknown CA) the answer is []
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '[' {
		return "", &coreapi.NotFoundError{Name: "revocation list of the certificate authority " + caref}
	}
	var dump struct {
		ExitStatus json.RawMessage `json:"exit_status"`
		Stdout     string          `json:"stdout"`
		Stderr     string          `json:"stderr"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return "", fmt.Errorf("unexpected answer from %s: %w", endpoint, err)
	}
	if status := strings.Trim(string(dump.ExitStatus), `"`); status != "" && status != "0" {
		return "", fmt.Errorf("openssl failed on the firewall (exit status %s): %s", status, strings.TrimSpace(dump.Stderr))
	}
	return dump.Stdout, nil
}

// CrlExport returns the list in PEM format, *NotFoundError when the CA has no list
func (opn *TrustApi) CrlExport(caref string) (string, error) {
	var crl, err = opn.CrlGet(caref)
	if err != nil {
		return "", err
	}
	if crl.Text == "" {
		return "", &coreapi.NotFoundError{Name: "revocation list of the certificate authority " + caref}
	}
	return crl.Text, nil
}

// CrlRevocationTimes returns when the certificates of the CA caref on its internal list were revoked, by serial
// (CrlSerialHex). It reads the OCSP index OPNsense offers (get_ocsp_info_data), which only lists certificates
// that still exist
func (opn *TrustApi) CrlRevocationTimes(caref string) (map[string]time.Time, error) {
	var endpoint, err = opn.crlEndpoint("get_ocsp_info_data", caref)
	if err != nil {
		return nil, err
	}
	var answer struct {
		Payload string `json:"payload"`
	}
	if err := opn.DoJSON("GET", endpoint, nil, &answer); err != nil {
		return nil, err
	}
	return crlParseOcspIndex(answer.Payload), nil
}

// crlParseOcspIndex reads an openssl CA index: status, expiry, revocation date (YYMMDDHHMMSSZ), serial (hex),
// file, name separated by tabs; only revoked (R) lines with a parseable date are returned
func crlParseOcspIndex(payload string) map[string]time.Time {
	var times = map[string]time.Time{}
	for _, line := range strings.Split(payload, "\n") {
		var columns = strings.Split(line, "\t")
		if len(columns) < 4 || columns[0] != "R" {
			continue
		}
		var date, _, _ = strings.Cut(columns[2], ",")
		var revoked, err = time.Parse("060102150405Z", date)
		if err != nil {
			continue
		}
		if serial, ok := CrlParseSerial(columns[3]); ok {
			times[CrlSerialHex(serial)] = revoked
		}
	}
	return times
}

// CrlCertificate is a certificate as trust/cert/search returns it, reduced to what revocation needs (the private
// key the search also returns is not kept)
type CrlCertificate struct {
	Uuid       string
	Refid      string
	Descr      string
	Caref      string
	CommonName string
	// Serial is parsed from the certificate, nil when it could not be parsed
	Serial *big.Int
}

// CrlCertificates returns the certificates issued by the CA caref (all certificates for ""), in API order
func (opn *TrustApi) CrlCertificates(caref string) ([]CrlCertificate, error) {
	type row struct {
		Uuid       string `json:"uuid"`
		Refid      string `json:"refid"`
		Descr      string `json:"descr"`
		Caref      string `json:"caref"`
		CommonName string `json:"commonname"`
		Crt        string `json:"crt_payload"`
	}
	var rows, err = coreapi.Search[row](opn.OPNsense, opn.endpoint("cert", "search"), "")
	if err != nil {
		return nil, err
	}
	var certificates []CrlCertificate
	for _, r := range rows {
		if caref != "" && r.Caref != caref {
			continue
		}
		var certificate = CrlCertificate{Uuid: r.Uuid, Refid: r.Refid, Descr: r.Descr, Caref: r.Caref, CommonName: r.CommonName}
		if block, _ := pem.Decode([]byte(r.Crt)); block != nil {
			if parsed, err := x509.ParseCertificate(block.Bytes); err == nil {
				certificate.Serial = parsed.SerialNumber
			}
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}
