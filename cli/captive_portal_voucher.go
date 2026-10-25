package cli

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"time"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/captiveportal"
)

// /captive-portal/voucher: the vouchers of Services > Captive Portal > Vouchers (api/captiveportal/voucher).
// Vouchers live in a voucher provider (an authentication server of type Voucher, made on the legacy page
// System > Access > Servers, without API) and are grouped by name. provider= may be left out when there is only one.
// Generated passwords are only shown once: generate writes them to a CSV file like the GUI

func init() {
	var menu = Root.Menu("captive-portal/voucher")
	menu.Help = "captive portal vouchers: providers, groups, generate, expire, drop (Services > Captive Portal > Vouchers)"
	var provider = Arg{Name: "provider", Help: "the voucher provider (authentication server), may be left out when there is only one",
		Complete: captivePortalVoucherProviderNames}
	var group = Arg{Name: "group", Required: true, Help: "the voucher group", Complete: captivePortalVoucherGroupNames}
	menu.Add(
		&Command{Name: "providers", Help: "list the voucher providers (authentication servers of type Voucher)",
			Run: captivePortalVoucherProviders},
		&Command{Name: "groups", Help: "list the voucher groups of a provider", Args: []Arg{provider}, Run: captivePortalVoucherGroups},
		&Command{Name: "print", Help: "list the vouchers of a group (all groups without group=)",
			Long: `STATE is unused, valid (in use) or expired. VALID-UNTIL is the end of the validity after the first login
(for unused vouchers counted from now), EXPIRES the fixed expiry time, if any.`,
			Args: []Arg{provider,
				{Name: "group", Help: "only this voucher group", Complete: captivePortalVoucherGroupNames},
				{Name: "state", Values: []string{"unused", "valid", "expired"}, Help: "only vouchers in this state"},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			}, Run: captivePortalVoucherPrint},
		&Command{Name: "generate", Help: "generate vouchers and save them with their passwords as CSV",
			Long: `The vouchers (username, password, group, expiry time, validity in seconds) are written like the GUI does to
<group>.csv (mode 0600) or file=; file=- writes them to stdout. The passwords can not be shown again later.

  generate group=event count=50 validity=4h expiry=168h`,
			Args: []Arg{provider,
				{Name: "group", Required: true, Validate: captivePortalVoucherValidateGroup, Help: "the voucher group (new or existing)"},
				{Name: "count", Type: Int, Required: true, Validate: ValidateRange(1, captiveportal.VoucherMaxCount), Help: "number of vouchers, at most 10000"},
				{Name: "validity", Type: Duration, Required: true, Validate: captivePortalVoucherValidateDuration(true),
					Help: "how long a voucher can be used after its first login, e.g. 4h (whole seconds)"},
				{Name: "expiry", Type: Duration, Validate: captivePortalVoucherValidateDuration(false),
					Help: "the vouchers expire this long from now whether used or not, e.g. 168h; default never"},
				{Name: "file", Help: "file to write, - for stdout (default: <group>.csv)"},
				{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
			},
			Check: captivePortalCheckFileArgs,
			Run:   captivePortalVoucherGenerate},
		&Command{Name: "expire", Help: "end the validity of vouchers now",
			Args: []Arg{{Name: "item", Type: List, Positional: true, Required: true,
				Help: "the # of print or the usernames of the vouchers (comma separated)"}, provider},
			Confirm: "This expires the vouchers, logged in clients using them lose access at their next check.",
			Run:     captivePortalVoucherExpire},
		&Command{Name: "drop-expired", Help: "delete the expired vouchers of a group", Args: []Arg{provider, group},
			Confirm: "This deletes the expired vouchers of the group.", Run: captivePortalVoucherDropExpired},
		&Command{Name: "drop-group", Help: "delete all vouchers of a group, also unused and valid ones", Args: []Arg{provider, group},
			Confirm: "This deletes all vouchers of the group, also unused and valid ones.", Run: captivePortalVoucherDropGroup},
	)
}

func captivePortalVoucherValidateGroup(value string) error {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "/&#") {
		return fmt.Errorf("must not be empty or contain / & #, got %q", value)
	}
	return openvpnInstanceValidateText(value)
}

func captivePortalVoucherValidateDuration(required bool) func(string) error {
	return func(value string) error {
		var duration, err = parseDuration(value)
		if err != nil {
			return err
		}
		if duration < 0 || (required && duration < time.Second) || duration%time.Second != 0 {
			return fmt.Errorf("must be whole seconds like 3600 or 4h, got %q", value)
		}
		return nil
	}
}

// captivePortalVoucherProvider returns the provider of provider= (case-insensitive), the only one without it
func captivePortalVoucherProvider(api *captiveportal.CaptivePortalApi, args *Args) (string, error) {
	var providers, err = api.VoucherProviders()
	if err != nil {
		return "", err
	}
	var given = strings.TrimSpace(args.String("provider"))
	if given == "" {
		switch len(providers) {
		case 1:
			return providers[0], nil
		case 0:
			return "", &coreapi.NotFoundError{Name: "voucher provider: there is none, add an authentication server of type Voucher (System > Access > Servers)"}
		default:
			return "", fmt.Errorf("there are several voucher providers, choose one with provider=: %s", strings.Join(providers, ", "))
		}
	}
	for _, provider := range providers {
		if strings.EqualFold(provider, given) {
			return provider, nil
		}
	}
	if len(providers) == 0 {
		return "", &coreapi.NotFoundError{Name: fmt.Sprintf("voucher provider %q, there are no voucher providers", given)}
	}
	return "", &coreapi.NotFoundError{Name: fmt.Sprintf("voucher provider %q, valid are: %s", given, strings.Join(providers, ", "))}
}

func captivePortalVoucherProviderNames(c *Context) []string {
	var api, err = captivePortalApi(c)
	if err != nil {
		return nil
	}
	var providers, _ = api.VoucherProviders()
	return providers
}

func captivePortalVoucherGroupNames(c *Context) []string {
	var api, err = captivePortalApi(c)
	if err != nil {
		return nil
	}
	var providers, listErr = api.VoucherProviders()
	if listErr != nil || len(providers) != 1 {
		return nil
	}
	var groups, _ = api.VoucherGroups(providers[0])
	return groups
}

func captivePortalVoucherProviders(c *Context, _ *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	providers, err := api.VoucherProviders()
	if err != nil {
		return err
	}
	var rows = make([][]string, len(providers))
	for i, provider := range providers {
		rows[i] = []string{provider}
	}
	c.Table([]string{"PROVIDER"}, rows)
	return nil
}

func captivePortalVoucherGroups(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	provider, err := captivePortalVoucherProvider(api, args)
	if err != nil {
		return err
	}
	groups, err := api.VoucherGroups(provider)
	if err != nil {
		return err
	}
	var rows = make([][]string, len(groups))
	for i, group := range groups {
		rows[i] = []string{group}
	}
	c.Table([]string{"GROUP"}, rows)
	return nil
}

func captivePortalVoucherTime(value captiveportal.Value) string {
	if value.Int() <= 0 {
		return ""
	}
	return time.Unix(value.Int(), 0).Local().Format(time.DateTime)
}

func captivePortalVoucherPrint(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	provider, err := captivePortalVoucherProvider(api, args)
	if err != nil {
		return err
	}
	var groups = []string{args.String("group")}
	if !args.Has("group") {
		if groups, err = api.VoucherGroups(provider); err != nil {
			return err
		}
	}
	var vouchers []captiveportal.Voucher
	for _, group := range groups {
		var list, listErr = api.VoucherList(provider, group)
		if listErr != nil {
			return listErr
		}
		for _, voucher := range list {
			if state := args.String("state"); state == "" || strings.EqualFold(string(voucher.State), state) {
				vouchers = append(vouchers, voucher)
			}
		}
	}
	if args.Bool("json") {
		for _, voucher := range vouchers {
			if err := c.JSON(voucher); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, len(vouchers))
	var ids = make([]string, len(vouchers))
	for i, voucher := range vouchers {
		ids[i] = string(voucher.Username)
		rows[i] = []string{string(voucher.Username), string(voucher.VoucherGroup), string(voucher.State),
			(time.Duration(voucher.Validity.Int()) * time.Second).String(), captivePortalVoucherTime(voucher.EndTime),
			captivePortalVoucherTime(voucher.ExpiryTime)}
	}
	c.Items([]string{"USERNAME", "GROUP", "STATE", "VALIDITY", "VALID-UNTIL", "EXPIRES"}, rows, ids)
	return nil
}

func captivePortalVoucherGenerate(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var group = args.String("group")
	var output = args.String("file")
	if err := captivePortalCheckOutput(output, group+".csv", args.Bool("overwrite")); err != nil {
		return err
	}
	provider, err := captivePortalVoucherProvider(api, args)
	if err != nil {
		return err
	}
	vouchers, err := api.VoucherGenerate(provider, group, args.Int("count"), int(args.Duration("validity")/time.Second),
		int(args.Duration("expiry")/time.Second))
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	var writer = csv.NewWriter(&buffer)
	_ = writer.Write([]string{"username", "password", "vouchergroup", "expirytime", "validity"})
	for _, voucher := range vouchers {
		_ = writer.Write([]string{string(voucher.Username), string(voucher.Password), string(voucher.VoucherGroup),
			string(voucher.ExpiryTime), string(voucher.Validity)})
	}
	writer.Flush()
	c.Infof("generated %d vouchers in group %q of %s", len(vouchers), group, provider)
	return captivePortalWriteOutput(c, output, group+".csv", buffer.Bytes(), args.Bool("overwrite"))
}

func captivePortalVoucherExpire(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	provider, err := captivePortalVoucherProvider(api, args)
	if err != nil {
		return err
	}
	var printed = c.Session.lastPrint[c.Menu.Path()]
	var usernames []string
	for _, selector := range args.List("item") {
		var index int
		if _, scanErr := fmt.Sscanf(selector, "%d", &index); scanErr == nil && fmt.Sprint(index) == selector && printed != nil {
			if index < 0 || index >= len(printed) {
				return &coreapi.NotFoundError{Name: fmt.Sprintf("voucher #%d, the last print showed %s", index, itemCount(len(printed)))}
			}
			selector = printed[index]
		}
		usernames = append(usernames, selector)
	}
	for _, username := range usernames {
		if err := api.VoucherExpire(provider, username); err != nil {
			return fmt.Errorf("voucher %s: %w", username, err)
		}
	}
	return nil
}

func captivePortalVoucherDropExpired(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	provider, err := captivePortalVoucherProvider(api, args)
	if err != nil {
		return err
	}
	count, err := api.VoucherDropExpired(provider, args.String("group"))
	if err != nil {
		return err
	}
	c.Infof("deleted %d expired vouchers", count)
	return nil
}

func captivePortalVoucherDropGroup(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	provider, err := captivePortalVoucherProvider(api, args)
	if err != nil {
		return err
	}
	return api.VoucherDropGroup(provider, args.String("group"))
}
