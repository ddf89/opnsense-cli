package cli

import (
	"errors"
	"fmt"
	"math/big"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/trust"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// /system/trust/revocation: the certificate revocation lists of System > Trust > Revocation. Every certificate
// authority has at most one list, so the items are the CAs (like in the GUI): the # of print, the refid or the
// description of the CA. An internal list is built and signed by OPNsense from the revoked certificates (revoke,
// unrevoke), an imported list is stored as given (add/set method=import crl-file=…)

const systemTrustRevocationItemHelp = "the #, description or refid of the certificate authority"

// systemTrustRevocationMethods maps the method argument to the API crlmethod
var systemTrustRevocationMethods = map[string]string{"internal": trust.CrlMethodInternal, "import": trust.CrlMethodImport}

// systemTrustRevocationReasons are the reason= values in API code order (RFC 5280 names in kebab-case)
var systemTrustRevocationReasons = []string{"unspecified", "key-compromise", "ca-compromise", "affiliation-changed", "superseded",
	"cessation-of-operation", "certificate-hold"}

func init() {
	var menu = Root.Menu("system/trust/revocation")
	menu.Help = "certificate revocation lists, one per certificate authority (System > Trust > Revocation)"

	var item = Arg{Name: "item", Help: systemTrustRevocationItemHelp, Positional: true, Required: true, Complete: systemTrustRevocationCompleteItems}
	var fieldArgs = func(add bool) []Arg {
		var defaultValue = func(value string) string {
			if add {
				return value
			}
			return ""
		}
		var descriptionHelp = "description of the list (1-255 characters)"
		if add {
			descriptionHelp += ", default: the description of the CA"
		}
		return []Arg{
			{Name: "description", Help: descriptionHelp, Validate: systemTrustRevocationValidateDescription},
			{Name: "lifetime", Type: Int, Help: "days an internal list is valid after each change", Default: defaultValue(trust.CrlDefaultLifetime),
				Validate: systemTrustRevocationValidateLifetime},
			{Name: "method", Help: "internal: built and signed by OPNsense from the revoked certificates, import: an existing list (crl-file=)",
				Values: []string{"internal", "import"}, Default: defaultValue("internal")},
			{Name: "crl-file", Help: "file with the list to import (PEM), only with method=import"},
		}
	}

	menu.Add(
		&Command{Name: "print", Help: "list the certificate authorities with their revocation lists", Args: []Arg{
			{Name: "detail", Help: "show all fields of every list", Type: Bool},
			{Name: "json", Help: "one JSON object per line, as the API returns them (one per CA)", Type: Bool},
			{Name: "search", Help: "only CAs whose description, refid or list description contains this text (case-insensitive)"},
		}, Run: systemTrustRevocationPrint},
		&Command{Name: "show", Help: "show the revocation list of a CA with the revoked certificates", Args: []Arg{item}, Run: systemTrustRevocationShow},
		&Command{Name: "add", Help: "create the revocation list of a CA, prints the refid of the CA",
			Long: `An internal list (the default) is signed with the key of the CA and starts empty, see revoke. A CA
has at most one list: add fails when it has one unless replace is given, then the list is replaced
completely. replace refuses to drop a list that revokes certificates, unrevoke them or remove the list first.`,
			Args:  append(append([]Arg{item}, fieldArgs(true)...), Arg{Name: "replace", Help: "replace an existing list", Type: Bool}),
			Check: systemTrustRevocationCheckAdd, Run: systemTrustRevocationAdd},
		&Command{Name: "set", Help: "change the revocation list of a CA, other fields are kept",
			Long: `crl-file= replaces an imported list. Switching an internal list to method=import drops its revoked
certificates, switching an imported list to method=internal starts an empty internal list.`,
			Args:  append([]Arg{item}, fieldArgs(false)...),
			Check: systemTrustRevocationCheckSet, Run: systemTrustRevocationSet},
		&Command{Name: "revoke", Help: "revoke certificates of the CA on its internal list (or change their reason)",
			Args: []Arg{item,
				{Name: "certificate", Type: List, Required: true, Complete: systemTrustRevocationCompleteCertificates,
					Help: "the certificates issued by the CA: description, refid, uuid or serial (hex like 01 or 7c:a9:7b)"},
				{Name: "reason", Values: systemTrustRevocationReasons, Default: "unspecified", Help: "the revocation reason (RFC 5280)"},
			}, Run: systemTrustRevocationRevoke},
		&Command{Name: "unrevoke", Help: "take certificates off the internal list of the CA",
			Args: []Arg{item,
				{Name: "certificate", Type: List, Required: true, Complete: systemTrustRevocationCompleteCertificates,
					Help: "the revoked certificates: description, refid, uuid or serial (hex)"},
			}, Run: systemTrustRevocationUnrevoke},
		&Command{Name: "remove", Help: "delete the revocation list of a CA", Args: []Arg{item},
			Confirm: "This deletes the revocation list: the certificates on it are no longer reported as revoked.",
			Run:     systemTrustRevocationRemove},
		&Command{Name: "dump", Help: "show the list as text (openssl crl -text on the firewall)", Args: []Arg{item}, Run: systemTrustRevocationDump},
		&Command{Name: "export", Help: "save the list in PEM format",
			Long: `The file is named after the description of the list (<description>.crl, like the GUI download) unless
file= is given, file=- writes to stdout. An existing file is only overwritten with overwrite.`,
			Args: []Arg{item,
				{Name: "file", Help: "file to write, - for stdout (default: <description of the list>.crl)"},
				{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
			},
			Check: func(args *Args) error {
				if args.Bool("overwrite") && args.String("file") == "-" {
					return errors.New("overwrite has no effect with file=- (stdout)")
				}
				return nil
			},
			Run: systemTrustRevocationExport},
	)
}

// --- validation

func systemTrustRevocationValidateDescription(value string) error {
	if err := trust.CrlValidateDescription(value); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "the description "))
	}
	return nil
}

func systemTrustRevocationValidateLifetime(value string) error {
	if value == "" {
		return errors.New("must not be empty")
	}
	return ValidateRange(1, trust.CrlMaxLifetime)(value)
}

// systemTrustRevocationCheckAdd: crl-file= goes with method=import
func systemTrustRevocationCheckAdd(args *Args) error {
	if args.Has("crl-file") && args.String("crl-file") == "" {
		return errors.New("crl-file must not be empty")
	}
	var importing = args.String("method") == "import"
	if args.Has("crl-file") && !importing {
		return errors.New("crl-file is only used with method=import")
	}
	if importing && !args.Has("crl-file") {
		return errors.New("method=import needs crl-file=, the list to import")
	}
	return nil
}

// systemTrustRevocationCheckSet: no crl-file= with method=internal (the current method is checked by Run)
func systemTrustRevocationCheckSet(args *Args) error {
	if !args.Has("description") && !args.Has("lifetime") && !args.Has("method") && !args.Has("crl-file") {
		return errors.New("nothing to change, give at least one of description=, lifetime=, method= or crl-file= (type \"set ?\" for help)")
	}
	if args.Has("crl-file") && args.String("crl-file") == "" {
		return errors.New("crl-file must not be empty")
	}
	if args.Has("crl-file") && args.Has("method") && args.String("method") == "internal" {
		return errors.New("crl-file is only used with method=import")
	}
	return nil
}

// systemTrustRevocationReadFile reads the list to import and checks that it is one
func systemTrustRevocationReadFile(path string) (string, error) {
	var data, err = os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if _, err := trust.CrlParse(string(data)); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return string(data), nil
}

// --- lookups

// systemTrustRevocationAuthorities lists the CAs (with or without list) in API order
func systemTrustRevocationAuthorities(c *Context) (*trust.TrustApi, []trust.CrlAuthority, error) {
	var api, err = trustApi(c)
	if err != nil {
		return nil, nil, err
	}
	authorities, err := api.CrlList()
	if err != nil {
		return nil, nil, err
	}
	return api, authorities, nil
}

func systemTrustRevocationRefid(authority trust.CrlAuthority) string {
	return authority.Refid
}

func systemTrustRevocationNames(authority trust.CrlAuthority) []string {
	return []string{authority.Descr}
}

// systemTrustRevocationSelect resolves the item argument to a CA
func systemTrustRevocationSelect(c *Context, args *Args) (*trust.TrustApi, trust.CrlAuthority, error) {
	var api, authorities, err = systemTrustRevocationAuthorities(c)
	if err != nil {
		return nil, trust.CrlAuthority{}, err
	}
	authority, err := Select(c, args.String("item"), authorities, systemTrustRevocationRefid, systemTrustRevocationNames)
	return api, authority, err
}

// systemTrustRevocationNoList is the error for a CA without list
func systemTrustRevocationNoList(authority trust.CrlAuthority) error {
	return &coreapi.NotFoundError{Name: fmt.Sprintf("revocation list of the certificate authority %q, add one first", authority.Descr)}
}

// systemTrustRevocationGet returns the existing list of the selected CA
func systemTrustRevocationGet(c *Context, args *Args) (*trust.TrustApi, trust.CrlAuthority, *trust.Crl, error) {
	var api, authority, err = systemTrustRevocationSelect(c, args)
	if err != nil {
		return nil, authority, nil, err
	}
	crl, err := api.CrlGet(authority.Refid)
	if err != nil {
		return nil, authority, nil, err
	}
	if !crl.Exists() {
		return nil, authority, nil, systemTrustRevocationNoList(authority)
	}
	return api, authority, crl, nil
}

// --- output

func systemTrustRevocationType(crl *trust.Crl) string {
	switch {
	case crl == nil || !crl.Exists():
		return ""
	case crl.Imported():
		return "imported"
	default:
		return "internal"
	}
}

func systemTrustRevocationTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format(time.DateTime)
}

// systemTrustRevocationReasonName renders a reason code (RFC 5280) like the reason= values
func systemTrustRevocationReasonName(code int) string {
	if code >= 0 && code < len(systemTrustRevocationReasons) {
		return systemTrustRevocationReasons[code]
	}
	switch code {
	case 8:
		return "remove-from-crl"
	case 9:
		return "privilege-withdrawn"
	case 10:
		return "aa-compromise"
	}
	return strconv.Itoa(code)
}

// systemTrustRevocationSummary is what print shows about a list
type systemTrustRevocationSummary struct {
	crl     *trust.Crl
	revoked string // number of entries
	number  string // CRL number
	updated time.Time
	next    time.Time
}

func systemTrustRevocationSummarize(crl *trust.Crl) systemTrustRevocationSummary {
	var summary = systemTrustRevocationSummary{crl: crl}
	if crl == nil || !crl.Exists() {
		return summary
	}
	summary.revoked = strconv.Itoa(len(crl.Revoked()))
	if list, err := crl.Parse(); err == nil {
		summary.revoked = strconv.Itoa(len(list.RevokedCertificateEntries))
		summary.updated, summary.next = list.ThisUpdate, list.NextUpdate
		if list.Number != nil {
			summary.number = list.Number.String()
		}
	}
	return summary
}

func systemTrustRevocationLifetime(crl *trust.Crl) string {
	if crl == nil || !crl.Exists() || crl.Imported() || crl.Lifetime == "" {
		return ""
	}
	return crl.Lifetime + " days"
}

func systemTrustRevocationDescription(authority trust.CrlAuthority) string {
	if authority.CrlDescr == nil {
		return ""
	}
	return *authority.CrlDescr
}

func systemTrustRevocationFields(authority trust.CrlAuthority, summary systemTrustRevocationSummary) [][2]string {
	return [][2]string{
		{"ca", authority.Descr},
		{"ca-refid", authority.Refid},
		{"description", systemTrustRevocationDescription(authority)},
		{"type", systemTrustRevocationType(summary.crl)},
		{"revoked", summary.revoked},
		{"lifetime", systemTrustRevocationLifetime(summary.crl)},
		{"number", summary.number},
		{"last-update", systemTrustRevocationTime(summary.updated)},
		{"next-update", systemTrustRevocationTime(summary.next)},
	}
}

func systemTrustRevocationPrint(c *Context, args *Args) error {
	var api, err = trustApi(c)
	if err != nil {
		return err
	}
	authorities, raw, err := api.CrlListRaw()
	if err != nil {
		return err
	}

	var search = strings.ToLower(args.String("search"))
	var refids []string
	var selected []int
	for i, authority := range authorities {
		if search != "" && !strings.Contains(strings.ToLower(authority.Descr+"\n"+authority.Refid+"\n"+systemTrustRevocationDescription(authority)), search) {
			continue
		}
		selected = append(selected, i)
		refids = append(refids, authority.Refid)
	}

	if args.Bool("json") {
		for _, i := range selected {
			c.Println(string(raw[i]))
		}
		return nil
	}

	var summaries = make([]systemTrustRevocationSummary, len(selected))
	for n, i := range selected {
		if !authorities[i].HasCrl() {
			continue
		}
		var crl, err = api.CrlGet(authorities[i].Refid)
		if err != nil {
			return err
		}
		summaries[n] = systemTrustRevocationSummarize(crl)
	}

	if args.Bool("detail") {
		var items = make([][][2]string, len(selected))
		for n, i := range selected {
			items[n] = systemTrustRevocationFields(authorities[i], summaries[n])
		}
		c.Details(items, refids)
		return nil
	}
	var rows = make([][]string, len(selected))
	for n, i := range selected {
		var summary = summaries[n]
		rows[n] = []string{authorities[i].Descr, systemTrustRevocationDescription(authorities[i]), systemTrustRevocationType(summary.crl),
			summary.revoked, systemTrustRevocationLifetime(summary.crl), systemTrustRevocationTime(summary.updated)}
	}
	c.Items([]string{"CA", "DESCRIPTION", "TYPE", "REVOKED", "LIFETIME", "UPDATED"}, rows, refids)
	return nil
}

func systemTrustRevocationShow(c *Context, args *Args) error {
	var api, authority, crl, err = systemTrustRevocationGet(c, args)
	if err != nil {
		return err
	}
	authority.CrlDescr = &crl.Descr
	c.Fields(systemTrustRevocationFields(authority, systemTrustRevocationSummarize(crl)))

	var rows [][]string
	var list, parseErr = crl.Parse()
	if parseErr != nil {
		// not expected: OPNsense builds or validates the list. Show what the API knows
		c.Infof("warning: %v", parseErr)
		for _, ref := range crl.Revoked() {
			var code, _ = strconv.Atoi(ref.Reason)
			rows = append(rows, []string{"", systemTrustRevocationReasonName(code), "", ref.Descr})
		}
	} else {
		certificates, err := api.CrlCertificates(authority.Refid)
		if err != nil {
			return err
		}
		var names = map[string]string{}
		for _, certificate := range certificates {
			names[trust.CrlSerialHex(certificate.Serial)] = certificate.Descr
		}
		// an internal list is rebuilt on every change with the time of the change as revocation date, the
		// OCSP index has the real ones
		var times = map[string]time.Time{}
		if !crl.Imported() {
			if times, err = api.CrlRevocationTimes(authority.Refid); err != nil {
				return err
			}
		}
		for _, entry := range list.RevokedCertificateEntries {
			var serial = trust.CrlSerialHex(entry.SerialNumber)
			var revoked, known = times[serial]
			if !known {
				revoked = entry.RevocationTime
			}
			rows = append(rows, []string{serial, systemTrustRevocationReasonName(entry.ReasonCode), systemTrustRevocationTime(revoked), names[serial]})
		}
	}
	if len(rows) > 0 {
		c.Println()
		c.Table([]string{"SERIAL", "REASON", "REVOKED", "CERTIFICATE"}, rows)
	}
	return nil
}

// --- changes

// systemTrustRevocationRevokedCount counts the certificates a list revokes (internal: the API list, imported: the entries)
func systemTrustRevocationRevokedCount(crl *trust.Crl) int {
	if crl.Imported() {
		if list, err := crl.Parse(); err == nil {
			return len(list.RevokedCertificateEntries)
		}
		return 0
	}
	return len(crl.Revoked())
}

func systemTrustRevocationAdd(c *Context, args *Args) error {
	var api, authority, err = systemTrustRevocationSelect(c, args)
	if err != nil {
		return err
	}
	crl, err := api.CrlGet(authority.Refid)
	if err != nil {
		return err
	}
	if crl.Exists() {
		if !args.Bool("replace") {
			return fmt.Errorf("the certificate authority %q has a revocation list already, use set to change it or add replace", authority.Descr)
		}
		if count := systemTrustRevocationRevokedCount(crl); count > 0 {
			var hint = "unrevoke them or remove the list first"
			if crl.Imported() {
				hint = "remove the list first"
			}
			return fmt.Errorf("the revocation list of %q revokes %d certificate(s), replace would drop them: %s", authority.Descr, count, hint)
		}
	}

	var settings = trust.CrlSettings{
		Descr:    args.String("description"),
		Lifetime: args.String("lifetime"),
		Method:   systemTrustRevocationMethods[args.String("method")],
	}
	if settings.Descr == "" {
		settings.Descr = authority.Descr
	}
	if settings.Method == trust.CrlMethodImport {
		if settings.Text, err = systemTrustRevocationReadFile(args.String("crl-file")); err != nil {
			return err
		}
	}
	if err := api.CrlSet(authority.Refid, settings); err != nil {
		return err
	}
	c.Println(authority.Refid)
	return nil
}

func systemTrustRevocationSet(c *Context, args *Args) error {
	var api, authority, crl, err = systemTrustRevocationGet(c, args)
	if err != nil {
		return err
	}
	var settings = trust.CrlSettings{Descr: crl.Descr, Lifetime: crl.Lifetime, Method: crl.Method}
	if args.Has("description") {
		settings.Descr = args.String("description")
	}
	if args.Has("lifetime") {
		settings.Lifetime = args.String("lifetime")
	}
	if args.Has("method") {
		settings.Method = systemTrustRevocationMethods[args.String("method")]
	}

	switch settings.Method {
	case trust.CrlMethodImport:
		switch {
		case args.Has("crl-file"):
			if settings.Text, err = systemTrustRevocationReadFile(args.String("crl-file")); err != nil {
				return err
			}
		case crl.Imported():
			settings.Text = crl.Text
		default:
			return errors.New("method=import needs crl-file=, the list to import")
		}
		if count := len(crl.Revoked()); !crl.Imported() && count > 0 {
			c.Infof("the %d revoked certificate(s) of the internal list are dropped", count)
		}
	default:
		if args.Has("crl-file") {
			return errors.New("crl-file is only used with method=import")
		}
		if !crl.Imported() {
			settings.Revoked = map[string]string{}
			for _, ref := range crl.Revoked() {
				settings.Revoked[ref.Refid] = ref.Reason
			}
		}
	}
	return api.CrlSet(authority.Refid, settings)
}

// systemTrustRevocationCandidate is a certificate revoke / unrevoke can refer to
type systemTrustRevocationCandidate struct {
	refid  string
	uuid   string
	descr  string
	serial *big.Int
}

// systemTrustRevocationCandidates are the certificates issued by the CA, plus those on its list that no longer exist
func systemTrustRevocationCandidates(api *trust.TrustApi, crl *trust.Crl) ([]systemTrustRevocationCandidate, error) {
	var certificates, err = api.CrlCertificates(crl.Caref)
	if err != nil {
		return nil, err
	}
	var candidates []systemTrustRevocationCandidate
	var known = map[string]bool{}
	for _, certificate := range certificates {
		candidates = append(candidates, systemTrustRevocationCandidate{refid: certificate.Refid, uuid: certificate.Uuid, descr: certificate.Descr,
			serial: certificate.Serial})
		known[certificate.Refid] = true
	}
	for _, ref := range crl.Certificates {
		if !known[ref.Refid] {
			candidates = append(candidates, systemTrustRevocationCandidate{refid: ref.Refid, descr: ref.Descr})
		}
	}
	return candidates, nil
}

// systemTrustRevocationResolve finds the refids of the certificates the selectors refer to: refid, uuid, description
// (exact, case-insensitive) or serial
func systemTrustRevocationResolve(authority trust.CrlAuthority, candidates []systemTrustRevocationCandidate, selectors []string) ([]string, error) {
	var refids []string
	for _, selector := range selectors {
		var matches []systemTrustRevocationCandidate
		for _, match := range []func(systemTrustRevocationCandidate) bool{
			func(candidate systemTrustRevocationCandidate) bool {
				return strings.EqualFold(candidate.refid, selector) || candidate.uuid != "" && strings.EqualFold(candidate.uuid, selector)
			},
			func(candidate systemTrustRevocationCandidate) bool {
				return strings.EqualFold(candidate.descr, selector)
			},
			func(candidate systemTrustRevocationCandidate) bool {
				var serial, ok = trust.CrlParseSerial(selector)
				return ok && candidate.serial != nil && candidate.serial.Cmp(serial) == 0
			},
		} {
			matches = coreapi.Filter(candidates, match)
			if len(matches) > 0 {
				break
			}
		}
		switch len(matches) {
		case 0:
			return nil, &coreapi.NotFoundError{Name: fmt.Sprintf("certificate %q of the certificate authority %q, use its description, refid, uuid or serial",
				selector, authority.Descr)}
		case 1:
			refids = append(refids, matches[0].refid)
		default:
			var found = make([]string, len(matches))
			for i, match := range matches {
				found[i] = match.refid
			}
			return nil, &coreapi.TooManyFoundError{Name: fmt.Sprintf("certificate %q matches %d certificates (refids %s), use the refid",
				selector, len(matches), strings.Join(found, ", "))}
		}
	}
	return refids, nil
}

// systemTrustRevocationInternal returns the selected CA with its internal list and the certificates selected by certificate=
func systemTrustRevocationInternal(c *Context, args *Args) (*trust.TrustApi, trust.CrlAuthority, []string, error) {
	var api, authority, crl, err = systemTrustRevocationGet(c, args)
	if err != nil {
		return nil, authority, nil, err
	}
	if crl.Imported() {
		return nil, authority, nil, fmt.Errorf("the revocation list of %q is imported, only internal lists can revoke certificates (set method=internal)",
			authority.Descr)
	}
	candidates, err := systemTrustRevocationCandidates(api, crl)
	if err != nil {
		return nil, authority, nil, err
	}
	refids, err := systemTrustRevocationResolve(authority, candidates, args.List("certificate"))
	return api, authority, refids, err
}

func systemTrustRevocationRevoke(c *Context, args *Args) error {
	var api, authority, refids, err = systemTrustRevocationInternal(c, args)
	if err != nil {
		return err
	}
	var code = strconv.Itoa(systemTrustRevocationReasonIndex(args.String("reason")))
	return api.CrlRevoke(authority.Refid, code, refids...)
}

func systemTrustRevocationReasonIndex(name string) int {
	for i, reason := range systemTrustRevocationReasons {
		if strings.EqualFold(reason, name) {
			return i
		}
	}
	return 0
}

func systemTrustRevocationUnrevoke(c *Context, args *Args) error {
	var api, authority, refids, err = systemTrustRevocationInternal(c, args)
	if err != nil {
		return err
	}
	return api.CrlUnrevoke(authority.Refid, refids...)
}

func systemTrustRevocationRemove(c *Context, args *Args) error {
	var api, authority, err = systemTrustRevocationSelect(c, args)
	if err != nil {
		return err
	}
	if err := api.CrlRemove(authority.Refid); err != nil {
		if coreapi.IsNotFound(err) {
			return systemTrustRevocationNoList(authority)
		}
		return err
	}
	return nil
}

func systemTrustRevocationDump(c *Context, args *Args) error {
	var api, authority, err = systemTrustRevocationSelect(c, args)
	if err != nil {
		return err
	}
	dump, err := api.CrlDump(authority.Refid)
	if err != nil {
		if coreapi.IsNotFound(err) {
			return systemTrustRevocationNoList(authority)
		}
		return err
	}
	c.Printf("%s", dump)
	if dump != "" && !strings.HasSuffix(dump, "\n") {
		c.Println()
	}
	return nil
}

var systemTrustRevocationUnsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func systemTrustRevocationExport(c *Context, args *Args) error {
	var _, authority, crl, err = systemTrustRevocationGet(c, args)
	if err != nil {
		return err
	}
	if crl.Text == "" {
		return systemTrustRevocationNoList(authority)
	}

	var filename = args.String("file")
	if filename == "-" {
		_, err = c.Out.Write([]byte(crl.Text))
		return err
	}
	if filename == "" {
		filename = strings.Trim(systemTrustRevocationUnsafeFileChars.ReplaceAllString(crl.Descr, "_"), "_.") + ".crl"
	}
	var flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if args.Bool("overwrite") {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	file, err := os.OpenFile(filename, flags, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists, add overwrite to replace it", filename)
		}
		return err
	}
	if _, err := file.WriteString(crl.Text); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	c.Infof("saved %s (%d bytes)", filename, len(crl.Text))
	return nil
}

// --- completion, errors are ignored

func systemTrustRevocationCompleteItems(c *Context) []string {
	var _, authorities, err = systemTrustRevocationAuthorities(c)
	if err != nil {
		return nil
	}
	var names []string
	for _, authority := range authorities {
		names = append(names, authority.Descr)
	}
	return names
}

// systemTrustRevocationCompleteCertificates completes the descriptions of all certificates issued by a CA (the item
// is not known while completing)
func systemTrustRevocationCompleteCertificates(c *Context) []string {
	var api, err = trustApi(c)
	if err != nil {
		return nil
	}
	var certificates, listErr = api.CrlCertificates("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, certificate := range certificates {
		if certificate.Caref != "" && certificate.Descr != "" {
			names = append(names, certificate.Descr)
		}
	}
	return names
}
