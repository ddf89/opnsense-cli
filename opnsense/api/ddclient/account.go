package ddclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Account is a DDNS account of Services > Dynamic DNS > Settings (dyndns/accounts/search_item). The JSON names are
// the API's; the password is never kept, PasswordSet tells whether one is stored
type Account struct {
	Uuid    string `json:"uuid"`
	Enabled string `json:"enabled"` // "1" or "0"
	// Service is the provider key (e.g. dyndns2, cloudflare, custom), the choices depend on the backend
	Service string `json:"service"`
	// Protocol is the protocol of a custom service (dyndns1, dyndns2, get, post, put), only filled by AccountGet
	// (search_item has no protocol column)
	Protocol    string `json:"-"`
	Server      string `json:"server"`
	Username    string `json:"username"`
	PasswordSet bool   `json:"-"`
	ResourceId  string `json:"resourceId"`
	// Hostnames are comma separated
	Hostnames string `json:"hostnames"`
	Wildcard  string `json:"wildcard"`
	Zone      string `json:"zone"`
	// Checkip is the method to find the current address (e.g. web_icanhazip, if, if6), CheckipName its display name
	Checkip        string `json:"checkip"`
	CheckipName    string `json:"%checkip"`
	Dynipv6host    string `json:"dynipv6host"`
	CheckipTimeout string `json:"checkip_timeout"`
	ForceSsl       string `json:"force_ssl"`
	Ttl            string `json:"ttl"`
	// Interface is the interface key (lan, wan, opt1) whose address the if/if6 check methods use
	Interface     string `json:"interface"`
	InterfaceName string `json:"%interface"`
	Description   string `json:"description"`
	// CurrentIp is the address last registered at the provider, CurrentMtime when (ISO 8601), both empty before
	// the first update
	CurrentIp    string `json:"current_ip"`
	CurrentMtime string `json:"current_mtime"`
}

// AccountFields are the fields to send on create / update (API name → value), fields not given are kept on update
// and get the defaults of OPNsense on create
type AccountFields map[string]string

// AccountDefaults are the values of a new account for the fields OPNsense has defaults for (checkip has none that
// is valid), plus the empty optional fields: a replace sends them for the fields not given. The password is not
// in it, it can not be cleared
var AccountDefaults = AccountFields{
	"enabled": "1", "protocol": "", "server": "", "username": "", "resourceId": "", "wildcard": "0", "zone": "",
	"dynipv6host": "", "checkip_timeout": "10", "force_ssl": "1", "ttl": "300", "interface": "", "description": "",
}

// AccountOptionFields are the option fields of an account
var AccountOptionFields = []string{"service", "protocol", "checkip", "interface"}

// AccountList returns the accounts where any column contains searchPhrase ("" for all) in API order (sorted by
// description) and the rows as the API returned them without the password
func (opn *DdclientApi) AccountList(searchPhrase string) ([]Account, []json.RawMessage, error) {
	var rows, err = coreapi.Search[map[string]json.RawMessage](opn.OPNsense, opn.endpoint("accounts", "search_item"), searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var accounts = make([]Account, len(rows))
	var raws = make([]json.RawMessage, len(rows))
	for i, row := range rows {
		var password string
		if raw, found := row["password"]; found {
			_ = json.Unmarshal(raw, &password)
			delete(row, "password")
			delete(row, "%password")
		}
		var encoded, encodeErr = json.Marshal(row)
		if encodeErr != nil {
			return nil, nil, encodeErr
		}
		if err := json.Unmarshal(encoded, &accounts[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected account from OPNsense: %w", err)
		}
		accounts[i].PasswordSet = password != ""
		raws[i] = encoded
	}
	return accounts, raws, nil
}

// AccountGet returns the account with this uuid (with its protocol) or a *NotFoundError
func (opn *DdclientApi) AccountGet(uuid string) (Account, error) {
	var account, err = opn.accountExists(uuid)
	if err != nil {
		return Account{}, err
	}
	account.Protocol, err = opn.AccountProtocol(uuid)
	return account, err
}

// AccountProtocol returns the protocol of an account (get_item, search_item lacks it)
func (opn *DdclientApi) AccountProtocol(uuid string) (string, error) {
	if err := validateUuid(uuid); err != nil {
		return "", err
	}
	var answer struct {
		Account struct {
			Protocol optionMap `json:"protocol"`
		} `json:"account"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("accounts", "get_item", uuid), nil, &answer); err != nil {
		return "", err
	}
	return answer.Account.Protocol.selected(), nil
}

// AccountOptions returns the choices of the option fields of a new account (see AccountOptionFields): the
// services and check methods depend on the backend, the interfaces on the firewall
func (opn *DdclientApi) AccountOptions() (map[string][]Option, error) {
	var answer struct {
		Account map[string]json.RawMessage `json:"account"`
	}
	if err := opn.DoJSON("GET", opn.endpoint("accounts", "get_item"), nil, &answer); err != nil {
		return nil, err
	}
	if answer.Account == nil {
		return nil, errors.New("unexpected answer of dyndns/accounts/get_item: no account")
	}
	var options = map[string][]Option{}
	for _, field := range AccountOptionFields {
		var choices optionMap
		if err := json.Unmarshal(answer.Account[field], &choices); err != nil {
			return nil, fmt.Errorf("unexpected %s choices from dyndns/accounts/get_item: %w", field, err)
		}
		options[field] = choices.options()
	}
	return options, nil
}

// AccountCreate adds an account and returns its uuid
func (opn *DdclientApi) AccountCreate(fields AccountFields) (string, error) {
	return opn.Mutate(opn.endpoint("accounts", "add_item"), map[string]any{"account": fields})
}

// AccountUpdate changes the given fields of the account, it returns a *NotFoundError for unknown uuids (set_item
// would create the account)
func (opn *DdclientApi) AccountUpdate(uuid string, fields AccountFields) error {
	if len(fields) == 0 {
		return errNoChanges
	}
	if _, err := opn.accountExists(uuid); err != nil {
		return err
	}
	_, err := opn.Mutate(opn.endpoint("accounts", "set_item", uuid), map[string]any{"account": fields})
	return err
}

// AccountSetEnabled enables or disables the account (via set_item, not the toggle)
func (opn *DdclientApi) AccountSetEnabled(uuid string, enabled bool) error {
	var flag = "0"
	if enabled {
		flag = "1"
	}
	return opn.AccountUpdate(uuid, AccountFields{"enabled": flag})
}

// AccountRemove deletes the account
func (opn *DdclientApi) AccountRemove(uuid string) error {
	if err := validateUuid(uuid); err != nil {
		return err
	}
	if _, err := opn.Mutate(opn.endpoint("accounts", "del_item", uuid), nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: "account " + uuid, Err: err}
		}
		return err
	}
	return nil
}

// AccountForceRefresh makes the service update the accounts at their providers now: OPNsense stops the service,
// resets the cached state of the accounts and starts the service (also when it was stopped). It needs the native
// backend and the service enabled
func (opn *DdclientApi) AccountForceRefresh(uuids ...string) error {
	if len(uuids) == 0 {
		return errors.New("no account given")
	}
	for _, uuid := range uuids {
		if err := validateUuid(uuid); err != nil {
			return err
		}
	}
	var answer struct {
		Status string `json:"status"`
	}
	if err := opn.DoJSON("POST", opn.endpoint("accounts", "force_refresh", strings.Join(uuids, ",")), nil, &answer); err != nil {
		return err
	}
	if answer.Status != "ok" {
		return fmt.Errorf("force refresh failed: status %q", answer.Status)
	}
	return nil
}

func (opn *DdclientApi) accountExists(uuid string) (Account, error) {
	if err := validateUuid(uuid); err != nil {
		return Account{}, err
	}
	var accounts, _, err = opn.AccountList("")
	if err != nil {
		return Account{}, err
	}
	for _, account := range accounts {
		if account.Uuid == uuid {
			return account, nil
		}
	}
	return Account{}, &coreapi.NotFoundError{Name: "account " + uuid}
}
