package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/trust"
	"os"
	"strconv"
	"strings"
	"time"
)

// /system/trust/certificate: the certificates and signing requests of System > Trust > Certificates. Items are
// selected by the # of print, the uuid, the refid or the description. Private keys are never printed by print,
// show or dump, only by "export type=key"

const systemTrustCertItemHelp = "the #, uuid, description or refid of the certificate"

// systemTrustCertMethods maps the method argument to the library, the method decides which arguments are used
var systemTrustCertMethods = map[string]trust.CertMethod{
	"internal":    trust.CertMethodInternal,
	"self-signed": trust.CertMethodSelfSigned,
	"csr":         trust.CertMethodSigningRequest,
	"import":      trust.CertMethodImport,
	"sign-csr":    trust.CertMethodSignRequest,
}

// systemTrustCertTypes maps the type argument to the API's cert_type
var systemTrustCertTypes = []struct{ arg, api string }{
	{"server", trust.CertTypeServer},
	{"client", trust.CertTypeClient},
	{"combined", trust.CertTypeCombined},
	{"ca", trust.CertTypeCA},
}

// systemTrustCertKeyTypes maps the key-type argument to the API's key_type
var systemTrustCertKeyTypes = []struct{ arg, api string }{
	{"rsa-1024", "1024"}, {"rsa-2048", "2048"}, {"rsa-3072", "3072"}, {"rsa-4096", "4096"}, {"rsa-8192", "8192"},
	{"prime256v1", "prime256v1"}, {"secp384r1", "secp384r1"}, {"secp521r1", "secp521r1"},
}

// systemTrustCertExportTypes maps the export type argument to the API's generate_file type
var systemTrustCertExportTypes = map[string]string{
	"cert":   trust.CertExportCertificate,
	"key":    trust.CertExportPrivateKey,
	"csr":    trust.CertExportSigningRequest,
	"pkcs12": trust.CertExportPKCS12,
}

// systemTrustCertMethodArgs lists per method the arguments it requires and the ones it accepts besides
// description, method and replace
var systemTrustCertMethodArgs = map[string]struct{ required, optional []string }{
	"internal": {required: []string{"issuer", "common-name"}, optional: append([]string{"type", "key-type", "digest", "lifetime"},
		systemTrustCertSubjectArgs...)},
	"self-signed": {required: []string{"common-name"}, optional: append([]string{"type", "key-type", "digest", "lifetime"},
		systemTrustCertSubjectArgs...)},
	"csr":      {required: []string{"common-name"}, optional: append([]string{"key-type", "digest"}, systemTrustCertSubjectArgs...)},
	"import":   {required: []string{"certificate-file"}, optional: []string{"key-file"}},
	"sign-csr": {required: []string{"issuer", "csr-file"}, optional: []string{"type", "digest", "lifetime", "alt-dns", "alt-ip", "alt-email", "alt-uri"}},
}

// systemTrustCertSubjectArgs are the subject and alt name arguments (besides common-name)
var systemTrustCertSubjectArgs = []string{"country", "state", "city", "organization", "organizational-unit", "email",
	"alt-dns", "alt-ip", "alt-email", "alt-uri"}

// systemTrustCertMaxFile is the size limit of the PEM files read by add and import-signed
const systemTrustCertMaxFile = 1 << 20

func init() {
	var menu = Root.Menu("system/trust/certificate")
	menu.Help = "certificates and signing requests (System > Trust > Certificates)"

	var item = Arg{Name: "item", Help: systemTrustCertItemHelp, Positional: true, Required: true, Complete: systemTrustCertItemNames}
	var typeValues = make([]string, len(systemTrustCertTypes))
	for i, certType := range systemTrustCertTypes {
		typeValues[i] = certType.arg
	}
	var keyTypeValues = make([]string, len(systemTrustCertKeyTypes))
	for i, keyType := range systemTrustCertKeyTypes {
		keyTypeValues[i] = keyType.arg
	}
	var methodValues = []string{"internal", "self-signed", "csr", "import", "sign-csr"}
	var lifetimeArg = Arg{Name: "lifetime", Type: Int, Validate: ValidateRange(1, 36500),
		Help: fmt.Sprintf("validity in days (default %d)", trust.CertDefaultLifetime)}
	var digestArg = Arg{Name: "digest", Values: trust.CertDigests, Help: "signature digest (default " + trust.CertDefaultDigest + ")"}

	menu.Add(
		&Command{Name: "print", Help: "list the certificates and signing requests",
			Long: `search= matches (case-insensitive) the description, common name, alt names, issuer, refid and uuid.
expiring=30 lists the certificates that expire within 30 days, including the expired ones.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every certificate", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them (without the private key)", Type: Bool},
				{Name: "search", Help: "only certificates where the name, common name, alt names or issuer contain this text"},
				{Name: "expiring", Type: Int, Validate: ValidateRange(0, 36500),
					Help: "only certificates expiring within this many days (expired ones included)"},
			}, Run: systemTrustCertPrint},
		&Command{Name: "show", Help: "show all fields of one certificate (never the private key)", Args: []Arg{item}, Run: systemTrustCertShow},
		&Command{Name: "add", Help: "create, import or sign a certificate, prints its uuid",
			Long: `method decides how the certificate is obtained and which arguments it takes:
  internal     a new key and a certificate signed by issuer (a CA of the trust store)
               needs issuer, common-name; takes type, key-type, digest, lifetime, the subject and alt names
  self-signed  a new key and a self-signed certificate, like internal without issuer
  csr          a new key and a signing request to have signed elsewhere; complete it with import-signed
               needs common-name; takes key-type, digest, the subject and alt names
  import       an existing certificate (PEM) and optionally its private key (PEM, not encrypted)
               needs certificate-file; takes key-file
  sign-csr     signs a request (PEM) with issuer, the key stays with the requester. The subject comes from the
               request, its extensions are not copied: give the alt names again
               needs issuer, csr-file; takes type, digest, lifetime and alt names
The description names the certificate: if one with this description exists already, add fails unless replace is
given. replace creates the new certificate in place of the old one, it keeps its uuid and refid so everything
using it keeps working (services are not restarted). The country defaults to NL like in OPNsense.`,
			Args: []Arg{
				{Name: "description", Help: "what the certificate is for, also its name", Required: true, Validate: systemTrustCertValidateLine},
				{Name: "method", Values: methodValues, Default: "internal", Help: "how to obtain the certificate, see add ?"},
				{Name: "issuer", Complete: systemTrustCertIssuerNames,
					Help: "the certificate authority that signs it: description or refid of a CA (internal, sign-csr)"},
				{Name: "type", Values: typeValues, Help: "what the certificate is used for (default client)"},
				{Name: "common-name", Help: "the subject CN, e.g. host.example.com", Validate: systemTrustCertValidateLine},
				{Name: "alt-dns", Type: List, Help: "DNS subject alternative names"},
				{Name: "alt-ip", Type: List, Validate: ValidateIPList, Help: "IP address subject alternative names"},
				{Name: "alt-email", Type: List, Validate: systemTrustCertValidateEmails, Help: "email subject alternative names"},
				{Name: "alt-uri", Type: List, Help: "URI subject alternative names, e.g. https://host.example/"},
				{Name: "key-type", Values: keyTypeValues, Help: "RSA key size or elliptic curve of the new key (default rsa-2048)"},
				digestArg,
				lifetimeArg,
				{Name: "country", Help: "subject C, a two letter code (default NL)", Validate: systemTrustCertValidateCountry},
				{Name: "state", Help: "subject ST, state or province", Validate: systemTrustCertValidateLine},
				{Name: "city", Help: "subject L, the city", Validate: systemTrustCertValidateLine},
				{Name: "organization", Help: "subject O", Validate: systemTrustCertValidateLine},
				{Name: "organizational-unit", Help: "subject OU", Validate: systemTrustCertValidateLine},
				{Name: "email", Help: "subject emailAddress", Validate: systemTrustCertValidateLine},
				{Name: "certificate-file", Help: "PEM file with the certificate to import"},
				{Name: "key-file", Help: "PEM file with the private key of the imported certificate (optional)"},
				{Name: "csr-file", Help: "PEM file with the signing request to sign"},
				{Name: "replace", Type: Bool, Help: "replace the certificate with the same description"},
			},
			Check: systemTrustCertCheckAdd,
			Run:   systemTrustCertAdd},
		&Command{Name: "set", Help: "rename a certificate",
			Long: `Everything else is part of the signed certificate: use add ... replace for a new one or reissue to renew it.`,
			Args: []Arg{item, {Name: "description", Help: "the new description", Required: true, Validate: systemTrustCertValidateLine}},
			Run:  systemTrustCertSet},
		&Command{Name: "remove", Help: "delete a certificate and its private key",
			Long: `Certificates in use (by the web GUI, a VPN, ...) can not be removed.`,
			Args: []Arg{item}, Run: systemTrustCertRemove},
		&Command{Name: "dump", Help: "show the certificate (or signing request) decoded by openssl, with its fingerprint",
			Args: []Arg{item}, Run: systemTrustCertDump},
		&Command{Name: "export", Help: "save the certificate, its key, its signing request or all as PKCS #12",
			Long: `The file is named like OPNsense suggests (<description>_crt.pem, <description>_cert.p12) unless file= is
given, file=- writes to stdout. An existing file is only overwritten with overwrite. Keys and PKCS #12 files are
written with mode 0600. pkcs12 contains the certificate, its key and the CA chain, encrypted with password=.`,
			Args: []Arg{
				item,
				{Name: "type", Values: []string{"cert", "key", "csr", "pkcs12"}, Default: "cert", Help: "what to export"},
				{Name: "password", Help: "password of the PKCS #12 file (pkcs12 only)"},
				{Name: "file", Help: "file to write, - for stdout (default: the name suggested by OPNsense)"},
				{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
			},
			Check: systemTrustCertCheckExport,
			Run:   systemTrustCertExport},
		&Command{Name: "reissue", Help: "sign a new certificate for the same key and subject (renew)",
			Long: `Only certificates issued by a CA of the trust store and with a stored private key can be reissued,
self-signed ones can not (OPNsense answers "missing CA key"): replace them with add ... replace.`,
			Args:    []Arg{item, lifetimeArg, {Name: "digest", Values: trust.CertDigests, Help: "signature digest (default: keep)"}},
			Confirm: "This replaces the certificate by a newly signed one, services using it are not restarted.",
			Run:     systemTrustCertReissue},
		&Command{Name: "import-signed", Help: "complete a signing request (add method=csr) with the certificate signed by a CA",
			Long: `The certificate must belong to the request's key and verify against the trust store (its CA must be
trusted by the firewall).`,
			Args: []Arg{item, {Name: "certificate-file", Required: true, Help: "PEM file with the signed certificate"}},
			Run:  systemTrustCertImportSigned},
	)
}

// --- validation

func systemTrustCertValidateLine(value string) error {
	if strings.ContainsAny(value, "\n\r") {
		return errors.New("must be one line")
	}
	return nil
}

func systemTrustCertValidateCountry(value string) error {
	if len(value) != 2 || strings.ToUpper(value) != value || strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return fmt.Errorf("must be a two letter country code like NL or DE, got %q", value)
	}
	return nil
}

func systemTrustCertValidateEmails(value string) error {
	for _, email := range splitList(value) {
		if !strings.Contains(email, "@") {
			return fmt.Errorf("must be email addresses, got %q", email)
		}
	}
	return nil
}

// systemTrustCertCheckAdd enforces the arguments of the method before anything is read or sent
func systemTrustCertCheckAdd(args *Args) error {
	var method = strings.ToLower(args.String("method"))
	var spec, known = systemTrustCertMethodArgs[method]
	if !known {
		return fmt.Errorf("unknown method %q", method)
	}
	for _, name := range spec.required {
		if !args.Has(name) || args.String(name) == "" {
			return fmt.Errorf("method=%s needs %s=", method, name)
		}
	}
	var allowed = map[string]bool{"description": true, "method": true, "replace": true}
	for _, name := range append(spec.required, spec.optional...) {
		allowed[name] = true
	}
	for _, name := range args.Given() {
		if !allowed[name] {
			return fmt.Errorf("method=%s does not take %s= (type \"add ?\" for help)", method, name)
		}
	}
	return nil
}

func systemTrustCertCheckExport(args *Args) error {
	if args.Has("password") && args.String("type") != "pkcs12" {
		return errors.New("password= is only used with type=pkcs12")
	}
	if args.Bool("overwrite") && args.String("file") == "-" {
		return errors.New("overwrite has no effect with file=- (stdout)")
	}
	return nil
}

// systemTrustCertReadFile reads a PEM file given as argument
func systemTrustCertReadFile(name string, path string) (string, error) {
	var info, err = os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s: %s is a directory", name, path)
	}
	if info.Size() > systemTrustCertMaxFile {
		return "", fmt.Errorf("%s: %s is larger than %d bytes, not a PEM file", name, path, systemTrustCertMaxFile)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return string(content), nil
}

// --- lookups

func systemTrustCertUuid(cert trust.Cert) string {
	return cert.Uuid
}

func systemTrustCertNames(cert trust.Cert) []string {
	return []string{cert.Descr, cert.Refid}
}

// systemTrustCertSelect loads all certificates and finds the one selector refers to
func systemTrustCertSelect(c *Context, api *trust.TrustApi, selector string) (trust.Cert, error) {
	var certs, err = api.CertList()
	if err != nil {
		return trust.Cert{}, err
	}
	return Select(c, selector, certs, systemTrustCertUuid, systemTrustCertNames)
}

// systemTrustCertItemNames completes item names (descriptions) from the API
func systemTrustCertItemNames(c *Context) []string {
	var api, err = trustApi(c)
	if err != nil {
		return nil
	}
	var certs, listErr = api.CertList()
	if listErr != nil {
		return nil
	}
	var names []string
	for _, cert := range certs {
		if cert.Descr != "" {
			names = append(names, cert.Descr)
		}
	}
	return names
}

// systemTrustCertIssuerNames completes issuer= with the descriptions of the CAs
func systemTrustCertIssuerNames(c *Context) []string {
	var api, err = trustApi(c)
	if err != nil {
		return nil
	}
	var issuers, listErr = api.CertIssuers()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(issuers))
	for _, issuer := range issuers {
		names = append(names, issuer.Descr)
	}
	return names
}

// --- output

// systemTrustCertIssuer describes who signed the certificate: the CA of the trust store, self-signed or the
// issuer's common name for certificates of foreign CAs
func systemTrustCertIssuer(cert trust.Cert) string {
	switch {
	case cert.CarefName != "":
		return cert.CarefName
	case cert.Caref != "":
		return cert.Caref
	case cert.CertificatePEM == "":
		return ""
	case cert.IsSelfSigned():
		return "self-signed"
	}
	if parsed, err := cert.X509(); err == nil {
		if parsed.Issuer.CommonName != "" {
			return parsed.Issuer.CommonName
		}
		return parsed.Issuer.String()
	}
	return ""
}

// systemTrustCertType renders the type like the type argument, csr for pending signing requests
func systemTrustCertType(cert trust.Cert) string {
	if cert.IsPending() {
		return "csr"
	}
	for _, certType := range systemTrustCertTypes {
		if certType.api == cert.CertType {
			return certType.arg
		}
	}
	// OPNsense leaves cert_type empty for CA certificates
	if parsed, err := cert.X509(); err == nil && parsed.IsCA {
		return "ca"
	}
	return cert.CertType
}

// systemTrustCertKeyType renders the key type like the key-type argument
func systemTrustCertKeyType(cert trust.Cert) string {
	if _, err := strconv.Atoi(cert.KeyType); err == nil {
		return "rsa-" + cert.KeyType
	}
	return cert.KeyType
}

func systemTrustCertInUse(cert trust.Cert) string {
	switch {
	case cert.InUseFlag():
		return "yes"
	case cert.IsUser == "1":
		return "user"
	}
	return "no"
}

// systemTrustCertValidUntil renders the end of the validity as local date, marking expired certificates
func systemTrustCertValidUntil(cert trust.Cert, now time.Time, layout string) string {
	var notAfter, ok = cert.NotAfter()
	if !ok {
		return ""
	}
	var text = notAfter.Local().Format(layout)
	if notAfter.Before(now) {
		text += " (expired)"
	}
	return text
}

func systemTrustCertTime(value time.Time, ok bool) string {
	if !ok {
		return ""
	}
	return value.Local().Format(time.DateTime)
}

// systemTrustCertFields are the fields of show and print detail, the private key is never shown
func systemTrustCertFields(cert trust.Cert, now time.Time) [][2]string {
	var state = "certificate"
	if cert.IsPending() {
		state = "signing request (waiting for the signed certificate, see import-signed)"
	}
	var serial, fingerprint, daysLeft string
	if parsed, err := cert.X509(); err == nil {
		serial = parsed.SerialNumber.String()
		fingerprint = trust.CertFingerprint(parsed)
	}
	if notAfter, ok := cert.NotAfter(); ok {
		daysLeft = strconv.Itoa(int(notAfter.Sub(now).Hours() / 24))
	}
	var privateKey = "no"
	if cert.HasPrivateKey {
		privateKey = "stored on the firewall"
	}
	var join = func(value string) string {
		return strings.Join(trust.CertSplitLines(value), ",")
	}
	var notBefore, hasNotBefore = cert.NotBefore()
	var notAfter, hasNotAfter = cert.NotAfter()
	return [][2]string{
		{"uuid", cert.Uuid},
		{"refid", cert.Refid},
		{"description", cert.Descr},
		{"state", state},
		{"common-name", cert.CommonName},
		{"subject", cert.Name},
		{"issuer", systemTrustCertIssuer(cert)},
		{"issuer-refid", cert.Caref},
		{"type", systemTrustCertType(cert)},
		{"purpose", cert.Purpose},
		{"key-type", systemTrustCertKeyType(cert)},
		{"digest", cert.Digest},
		{"alt-dns", join(cert.AltNamesDNS)},
		{"alt-ip", join(cert.AltNamesIP)},
		{"alt-email", join(cert.AltNamesEmail)},
		{"alt-uri", join(cert.AltNamesURI)},
		{"valid-from", systemTrustCertTime(notBefore, hasNotBefore)},
		{"valid-until", systemTrustCertTime(notAfter, hasNotAfter)},
		{"days-left", daysLeft},
		{"serial", serial},
		{"fingerprint", fingerprint},
		{"private-key", privateKey},
		{"in-use", YesNo(cert.InUse)},
		{"user-certificate", YesNo(cert.IsUser)},
	}
}

// systemTrustCertMatches is the client side search= of print: the API's searchPhrase also matches the base64
// payloads (and the private key), so short phrases would match nearly everything
func systemTrustCertMatches(cert trust.Cert, search string) bool {
	if search == "" {
		return true
	}
	search = strings.ToLower(search)
	for _, value := range []string{cert.Descr, cert.CommonName, cert.AltNamesDNS, cert.AltNamesIP, cert.AltNamesEmail,
		cert.AltNamesURI, systemTrustCertIssuer(cert), cert.Refid, cert.Uuid} {
		if strings.Contains(strings.ToLower(value), search) {
			return true
		}
	}
	return false
}

func systemTrustCertPrint(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var certs, raw, searchErr = api.CertSearchRaw("")
	if searchErr != nil {
		return searchErr
	}

	var now = time.Now()
	var expiring = args.Has("expiring")
	var deadline = now.Add(time.Duration(args.Int("expiring")) * 24 * time.Hour)
	var shown []trust.Cert
	var shownRaw []json.RawMessage
	for i, cert := range certs {
		if !systemTrustCertMatches(cert, args.String("search")) {
			continue
		}
		if expiring {
			if notAfter, ok := cert.NotAfter(); !ok || notAfter.After(deadline) {
				continue
			}
		}
		shown = append(shown, cert)
		shownRaw = append(shownRaw, raw[i])
	}

	var uuids = make([]string, len(shown))
	for i, cert := range shown {
		uuids[i] = cert.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range shownRaw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(shown))
		for i, cert := range shown {
			items[i] = systemTrustCertFields(cert, now)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(shown))
		for i, cert := range shown {
			rows[i] = []string{cert.Descr, cert.CommonName, systemTrustCertIssuer(cert), systemTrustCertType(cert),
				systemTrustCertValidUntil(cert, now, time.DateOnly), systemTrustCertInUse(cert)}
		}
		c.Items([]string{"DESCRIPTION", "COMMON-NAME", "ISSUER", "TYPE", "VALID-UNTIL", "IN-USE"}, rows, uuids)
	}
	return nil
}

func systemTrustCertShow(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var cert, selectErr = systemTrustCertSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(systemTrustCertFields(cert, time.Now()))
	return nil
}

func systemTrustCertDump(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var cert, selectErr = systemTrustCertSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if cert.IsExternal() {
		// raw_dump only knows the certificates of the trust store
		return fmt.Errorf("certificate %q is managed outside the trust store, use show", cert.Descr)
	}
	var dump, dumpErr = api.CertDump(cert.Uuid)
	if dumpErr != nil {
		return dumpErr
	}
	c.Printf("%s", dump)
	if !strings.HasSuffix(dump, "\n") {
		c.Println()
	}
	return nil
}

// --- changes

// systemTrustCertRequest builds the library request from the arguments of add (Check accepted them already)
func systemTrustCertRequest(api *trust.TrustApi, args *Args) (trust.CertRequest, error) {
	var method = strings.ToLower(args.String("method"))
	var request = trust.CertRequest{
		Method:             systemTrustCertMethods[method],
		Description:        args.String("description"),
		Lifetime:           args.Int("lifetime"),
		Digest:             strings.ToLower(args.String("digest")),
		CommonName:         args.String("common-name"),
		Country:            args.String("country"),
		State:              args.String("state"),
		City:               args.String("city"),
		Organization:       args.String("organization"),
		OrganizationalUnit: args.String("organizational-unit"),
		Email:              args.String("email"),
		AltNamesDNS:        args.List("alt-dns"),
		AltNamesIP:         args.List("alt-ip"),
		AltNamesEmail:      args.List("alt-email"),
		AltNamesURI:        args.List("alt-uri"),
	}
	for _, certType := range systemTrustCertTypes {
		if strings.EqualFold(certType.arg, args.String("type")) {
			request.Type = certType.api
		}
	}
	for _, keyType := range systemTrustCertKeyTypes {
		if strings.EqualFold(keyType.arg, args.String("key-type")) {
			request.KeyType = keyType.api
		}
	}

	var err error
	for _, file := range []struct {
		arg    string
		target *string
	}{{"certificate-file", &request.CertificatePEM}, {"key-file", &request.PrivateKeyPEM}, {"csr-file", &request.SigningRequestPEM}} {
		if args.Has(file.arg) {
			if *file.target, err = systemTrustCertReadFile(file.arg, args.String(file.arg)); err != nil {
				return request, err
			}
		}
	}

	if args.Has("issuer") {
		var issuer, issuerErr = api.CertIssuerByName(args.String("issuer"))
		if issuerErr != nil {
			return request, issuerErr
		}
		request.IssuerRef = issuer.Refid
	}
	return request, nil
}

func systemTrustCertAdd(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var request, requestErr = systemTrustCertRequest(api, args)
	if requestErr != nil {
		return requestErr
	}

	var certs, listErr = api.CertList()
	if listErr != nil {
		return listErr
	}
	var existing []trust.Cert
	for _, cert := range certs {
		if strings.EqualFold(cert.Descr, request.Description) {
			existing = append(existing, cert)
		}
	}

	switch {
	case len(existing) == 0:
		var uuid, createErr = api.CertCreate(request)
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	case len(existing) > 1:
		var uuids = make([]string, len(existing))
		for i, cert := range existing {
			uuids[i] = cert.Uuid
		}
		return &coreapi.TooManyFoundError{Name: fmt.Sprintf("there are %d certificates with description %q (%s), rename or remove them with set or remove",
			len(existing), request.Description, strings.Join(uuids, ", "))}
	case !args.Bool("replace"):
		return fmt.Errorf("a certificate with description %q exists already (%s), rename it with set or replace it with add ... replace",
			existing[0].Descr, existing[0].Uuid)
	}

	var cert = existing[0]
	if err := api.CertReplace(cert.Uuid, request); err != nil {
		return err
	}
	if cert.InUseFlag() {
		c.Infof("replaced the certificate %q, it is in use: restart the services using it", cert.Descr)
	} else {
		c.Infof("replaced the existing certificate %q", cert.Descr)
	}
	c.Println(cert.Uuid)
	return nil
}

func systemTrustCertSet(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var cert, selectErr = systemTrustCertSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if cert.IsExternal() {
		return fmt.Errorf("certificate %q is managed outside the trust store and can not be changed", cert.Descr)
	}
	var description = args.String("description")
	return api.CertUpdate(cert.Uuid, trust.CertPatch{Description: &description})
}

func systemTrustCertRemove(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var cert, selectErr = systemTrustCertSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if cert.IsExternal() {
		return fmt.Errorf("certificate %q is managed outside the trust store and can not be removed", cert.Descr)
	}
	return api.CertRemove(cert.Uuid)
}

func systemTrustCertReissue(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var cert, selectErr = systemTrustCertSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if cert.IsExternal() {
		return fmt.Errorf("certificate %q is managed outside the trust store and can not be reissued", cert.Descr)
	}
	if err := api.CertReissue(cert.Uuid, args.Int("lifetime"), strings.ToLower(args.String("digest"))); err != nil {
		return err
	}
	if cert.InUseFlag() {
		c.Infof("certificate %q is in use: restart the services using it", cert.Descr)
	}
	return nil
}

func systemTrustCertImportSigned(c *Context, args *Args) error {
	var certificate, readErr = systemTrustCertReadFile("certificate-file", args.String("certificate-file"))
	if readErr != nil {
		return readErr
	}
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var cert, selectErr = systemTrustCertSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.CertImportSigned(cert.Uuid, certificate)
}

func systemTrustCertExport(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	var cert, selectErr = systemTrustCertSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if cert.IsExternal() {
		return fmt.Errorf("certificate %q is managed outside the trust store, it can not be exported", cert.Descr)
	}
	var exportType = strings.ToLower(args.String("type"))
	var content, filename, exportErr = api.CertExport(cert.Uuid, systemTrustCertExportTypes[exportType], args.String("password"))
	if exportErr != nil {
		return exportErr
	}

	var output = args.String("file")
	if output == "-" {
		_, err = c.Out.Write(content)
		return err
	}
	if output != "" {
		filename = output
	}
	var mode os.FileMode = 0o644
	if exportType == "key" || exportType == "pkcs12" {
		mode = 0o600
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if args.Bool("overwrite") {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(filename, flags, mode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
		}
		return err
	}
	if mode == 0o600 {
		// an overwritten file keeps its mode, keys must not stay readable
		if err := file.Chmod(mode); err != nil {
			_ = file.Close()
			return err
		}
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	c.Infof("saved %s (%d bytes)", filename, len(content))
	return nil
}
