package captiveportal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Vouchers of Services > Captive Portal > Vouchers (api/captiveportal/voucher). Vouchers live in the database of a
// voucher provider: an authentication server of type Voucher (System > Access > Servers, a legacy page without
// API), grouped by a free group name

// Voucher is one voucher of a group as list_vouchers returns it (without password)
type Voucher struct {
	Username Value `json:"username"`
	// Validity is the time in seconds the voucher can be used after its first login
	Validity Value `json:"validity"`
	// StartTime is the unix time of the first login (now for unused vouchers), EndTime StartTime + Validity
	StartTime Value `json:"starttime"`
	EndTime   Value `json:"endtime"`
	// ExpiryTime is the unix time the voucher expires regardless of use, 0 for never
	ExpiryTime Value `json:"expirytime"`
	// State is unused, valid or expired
	State        Value `json:"state"`
	VoucherGroup Value `json:"vouchergroup"`
}

// GeneratedVoucher is a new voucher with its password, only returned once by VoucherGenerate
type GeneratedVoucher struct {
	Username     Value `json:"username"`
	Password     Value `json:"password"`
	VoucherGroup Value `json:"vouchergroup"`
	Validity     Value `json:"validity"`
	ExpiryTime   Value `json:"expirytime"`
	StartTime    Value `json:"starttime"`
}

// VoucherMaxCount is the maximum number of vouchers OPNsense generates at once
const VoucherMaxCount = 10000

func (opn *CaptivePortalApi) voucherEndpoint(method string, parts ...string) string {
	var endpoint = opn.endpoint("voucher", method)
	for _, part := range parts {
		endpoint += "/" + url.PathEscape(part)
	}
	return endpoint + "/"
}

// VoucherProviders returns the names of the voucher providers (authentication servers of type Voucher)
func (opn *CaptivePortalApi) VoucherProviders() ([]string, error) {
	var providers []string
	if err := opn.DoJSON("GET", opn.endpoint("voucher", "list_providers"), nil, &providers); err != nil {
		return nil, err
	}
	return providers, nil
}

// checkProviderGroup refuses empty names and names with / (they can not be passed in the URL path)
func checkProviderGroup(provider string, group *string) error {
	if strings.TrimSpace(provider) == "" || strings.Contains(provider, "/") {
		return fmt.Errorf("invalid voucher provider %q", provider)
	}
	if group != nil && (strings.TrimSpace(*group) == "" || strings.ContainsAny(*group, "/&#")) {
		return fmt.Errorf("invalid voucher group %q: must not be empty or contain / & #", *group)
	}
	return nil
}

// VoucherGroups returns the voucher groups of a provider ([] also for an unknown provider)
func (opn *CaptivePortalApi) VoucherGroups(provider string) ([]string, error) {
	if err := checkProviderGroup(provider, nil); err != nil {
		return nil, err
	}
	var groups []string
	if err := opn.DoJSON("GET", opn.voucherEndpoint("list_voucher_groups", provider), nil, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// VoucherList returns the vouchers of a group of a provider ([] for unknown groups or providers)
func (opn *CaptivePortalApi) VoucherList(provider string, group string) ([]Voucher, error) {
	if err := checkProviderGroup(provider, &group); err != nil {
		return nil, err
	}
	var vouchers []Voucher
	if err := opn.DoJSON("GET", opn.voucherEndpoint("list_vouchers", provider, group), nil, &vouchers); err != nil {
		return nil, err
	}
	return vouchers, nil
}

// statusAnswer decodes the {"status":"error"} answers of the voucher actions, which otherwise answer a list
func statusAnswer(answer json.RawMessage) (string, bool) {
	var status struct {
		Status string `json:"status"`
	}
	if trimmed := bytes.TrimSpace(answer); len(trimmed) > 0 && trimmed[0] == '{' && json.Unmarshal(trimmed, &status) == nil {
		return status.Status, true
	}
	return "", false
}

var errVoucherProvider = errors.New("unknown voucher provider (or not a voucher server)")

// VoucherGenerate creates count vouchers in group, valid for validity seconds after the first login and, with
// expiry > 0, at most until expiry seconds from now. The passwords are only returned here
func (opn *CaptivePortalApi) VoucherGenerate(provider string, group string, count int, validity int, expiry int) ([]GeneratedVoucher, error) {
	if err := checkProviderGroup(provider, &group); err != nil {
		return nil, err
	}
	if count < 1 || count > VoucherMaxCount {
		return nil, fmt.Errorf("count must be 1 to %d, got %d", VoucherMaxCount, count)
	}
	if validity < 1 || expiry < 0 {
		return nil, fmt.Errorf("validity must be positive and expiry not negative, got %d and %d", validity, expiry)
	}
	var body = map[string]string{"count": fmt.Sprint(count), "validity": fmt.Sprint(validity), "expirytime": fmt.Sprint(expiry),
		"vouchergroup": group}
	var answer json.RawMessage
	if err := opn.DoJSON("POST", opn.voucherEndpoint("generate_vouchers", provider), body, &answer); err != nil {
		return nil, err
	}
	if status, isStatus := statusAnswer(answer); isStatus {
		return nil, fmt.Errorf("%s: %w (status %q)", provider, errVoucherProvider, status)
	}
	var vouchers []GeneratedVoucher
	if err := json.Unmarshal(answer, &vouchers); err != nil {
		return nil, fmt.Errorf("unexpected answer from generate_vouchers: %w", err)
	}
	return vouchers, nil
}

// voucherAction posts a voucher action that answers {"status":ok} (or drop) on success
func (opn *CaptivePortalApi) voucherAction(endpoint string, body any, success string) (map[string]any, error) {
	var answer map[string]any
	if err := opn.DoJSON("POST", endpoint, body, &answer); err != nil {
		return nil, err
	}
	if status, _ := answer["status"].(string); status != success {
		return nil, fmt.Errorf("%w (status %v)", errVoucherProvider, answer["status"])
	}
	return answer, nil
}

// VoucherExpire ends the validity of the voucher with this username now (the voucher stays in the database).
// OPNsense does not report unknown usernames
func (opn *CaptivePortalApi) VoucherExpire(provider string, username string) error {
	if err := checkProviderGroup(provider, nil); err != nil {
		return err
	}
	if username == "" {
		return errors.New("username must not be empty")
	}
	var _, err = opn.voucherAction(opn.voucherEndpoint("expire_voucher", provider), map[string]string{"username": username}, "ok")
	return err
}

// VoucherDropExpired deletes the expired vouchers of a group and returns how many were deleted
func (opn *CaptivePortalApi) VoucherDropExpired(provider string, group string) (int, error) {
	if err := checkProviderGroup(provider, &group); err != nil {
		return 0, err
	}
	var answer, err = opn.voucherAction(opn.voucherEndpoint("drop_expired_vouchers", provider, group), nil, "drop")
	if err != nil {
		return 0, err
	}
	var count, _ = answer["count"].(float64)
	return int(count), nil
}

// VoucherDropGroup deletes all vouchers of a group (used or not)
func (opn *CaptivePortalApi) VoucherDropGroup(provider string, group string) error {
	if err := checkProviderGroup(provider, &group); err != nil {
		return err
	}
	var _, err = opn.voucherAction(opn.voucherEndpoint("drop_voucher_group", provider, group), nil, "drop")
	return err
}
