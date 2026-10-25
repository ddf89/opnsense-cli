package openvpn

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// Instance is an OpenVPN server or client of VPN > OpenVPN > Instances (api/openvpn/instances), as search
// returns it. Option fields hold the option key(s), lists are comma separated, flags "0"/"1".
// Ca, Cert and Crl are trust store refids, TlsKey the uuid of a static key, LocalGroup a group gid, Authmode
// authentication server names.
//
// Quirks (OPNsense 26.7): search returns Password and AuthGenTokenSecret in clear text; vpnid must be sent on add,
// an empty vpnid makes OPNsense assign the next free one - also on set, where it silently renumbers the instance
type Instance struct {
	Uuid                 string `json:"uuid,omitempty"`
	Vpnid                string `json:"vpnid"`
	Enabled              string `json:"enabled"`
	DevType              string `json:"dev_type"` // tun, tap or ovpn (DCO)
	Verb                 string `json:"verb"`     // 0-11
	Proto                string `json:"proto"`    // udp, udp4, udp6, tcp, tcp4, tcp6
	Port                 string `json:"port"`
	PortShare            string `json:"port-share"`
	Local                string `json:"local"`
	Topology             string `json:"topology"` // net30, p2p, subnet
	Remote               string `json:"remote"`   // client: host[:port] list
	Role                 string `json:"role"`     // server or client
	Server               string `json:"server"`   // IPv4 tunnel network
	ServerIpv6           string `json:"server_ipv6"`
	Nopool               string `json:"nopool"`
	BridgeGateway        string `json:"bridge_gateway"`
	BridgePool           string `json:"bridge_pool"`
	Route                string `json:"route"`
	PushRoute            string `json:"push_route"`
	PushExcludedRoutes   string `json:"push_excluded_routes"`
	Cert                 string `json:"cert"`
	Crl                  string `json:"crl"`
	Ca                   string `json:"ca"`
	CertDepth            string `json:"cert_depth"`
	RemoteCertTls        string `json:"remote_cert_tls"`
	VerifyClientCert     string `json:"verify_client_cert"` // none or require
	UseOcsp              string `json:"use_ocsp"`
	Auth                 string `json:"auth"`
	DataCiphers          string `json:"data-ciphers"`
	DataCiphersFallback  string `json:"data-ciphers-fallback"`
	TlsKey               string `json:"tls_key"`
	Authmode             string `json:"authmode"`
	LocalGroup           string `json:"local_group"`
	VariousFlags         string `json:"various_flags"`
	VariousPushFlags     string `json:"various_push_flags"`
	PushInactive         string `json:"push_inactive"`
	UsernameAsCommonName string `json:"username_as_common_name"`
	Strictusercn         string `json:"strictusercn"` // 0 no, 1 yes, 2 case insensitive
	Username             string `json:"username"`
	Password             string `json:"password"`
	Maxclients           string `json:"maxclients"`
	KeepaliveInterval    string `json:"keepalive_interval"`
	KeepaliveTimeout     string `json:"keepalive_timeout"`
	RenegSec             string `json:"reneg-sec"`
	AuthGenToken         string `json:"auth-gen-token"`
	AuthGenTokenRenewal  string `json:"auth-gen-token-renewal"`
	AuthGenTokenSecret   string `json:"auth-gen-token-secret"`
	ProvisionExclusive   string `json:"provision_exclusive"`
	RedirectGateway      string `json:"redirect_gateway"`
	RouteMetric          string `json:"route_metric"`
	RegisterDns          string `json:"register_dns"`
	DnsDomain            string `json:"dns_domain"`
	DnsDomainSearch      string `json:"dns_domain_search"`
	DnsServers           string `json:"dns_servers"`
	NtpServers           string `json:"ntp_servers"`
	TunMtu               string `json:"tun_mtu"`
	Fragment             string `json:"fragment"`
	Mssfix               string `json:"mssfix"`
	CarpDependOn         string `json:"carp_depend_on"`
	Description          string `json:"description"`
	CompressMigrate      string `json:"compress_migrate"`
	IfconfigPoolPersist  string `json:"ifconfig-pool-persist"`
	HttpProxy            string `json:"http-proxy"`
	VerifyX509Name       string `json:"verify-x509-name"`
}

// InstanceFields holds a partial instance for InstanceCreate / InstanceUpdate keyed by the API field name (see
// InstanceFieldNames). Only the given keys are sent, OPNsense keeps all other fields (or uses its defaults on add).
// An empty value clears the field
type InstanceFields map[string]string

// InstanceFieldNames are the writable fields of an instance
var InstanceFieldNames = []string{
	"vpnid", "enabled", "dev_type", "verb", "proto", "port", "port-share", "local", "topology", "remote", "role",
	"server", "server_ipv6", "nopool", "bridge_gateway", "bridge_pool", "route", "push_route", "push_excluded_routes",
	"cert", "crl", "ca", "cert_depth", "remote_cert_tls", "verify_client_cert", "use_ocsp", "auth", "data-ciphers",
	"data-ciphers-fallback", "tls_key", "authmode", "local_group", "various_flags", "various_push_flags",
	"push_inactive", "username_as_common_name", "strictusercn", "username", "password", "maxclients",
	"keepalive_interval", "keepalive_timeout", "reneg-sec", "auth-gen-token", "auth-gen-token-renewal",
	"auth-gen-token-secret", "provision_exclusive", "redirect_gateway", "route_metric", "register_dns", "dns_domain",
	"dns_domain_search", "dns_servers", "ntp_servers", "tun_mtu", "fragment", "mssfix", "carp_depend_on",
	"description", "compress_migrate", "ifconfig-pool-persist", "http-proxy", "verify-x509-name",
}

// InstanceSecretFields are the fields holding secrets, which should not be shown
var InstanceSecretFields = []string{"password", "auth-gen-token-secret"}

func (opn *OpenVPNApi) instanceName(uuid string) string {
	return fmt.Sprintf("openvpn instance %s", uuid)
}

func checkInstanceFields(fields InstanceFields) error {
	for name := range fields {
		if !slices.Contains(InstanceFieldNames, name) {
			return fmt.Errorf("unknown openvpn instance field %q", name)
		}
	}
	return nil
}

// InstanceList returns all instances, searchPhrase is a substring match over all columns ("" for all)
func (opn *OpenVPNApi) InstanceList(searchPhrase string) ([]Instance, error) {
	return coreapi.Search[Instance](opn.OPNsense, opn.endpoint("instances", "search"), searchPhrase)
}

// InstanceGet returns the instance with the given uuid or a *NotFoundError
func (opn *OpenVPNApi) InstanceGet(uuid string) (Instance, error) {
	var instances, err = opn.InstanceList("")
	if err != nil {
		return Instance{}, err
	}
	for _, instance := range instances {
		if strings.EqualFold(instance.Uuid, uuid) {
			return instance, nil
		}
	}
	return Instance{}, &coreapi.NotFoundError{Name: opn.instanceName(uuid)}
}

// InstanceGetByDescription returns the only instance with this description (case-insensitive).
// Returns *NotFoundError when there is none, *TooManyFoundError (naming the uuids) when there are several
func (opn *OpenVPNApi) InstanceGetByDescription(description string) (Instance, error) {
	if description == "" {
		return Instance{}, errors.New("cannot look up an openvpn instance by an empty description")
	}
	var instances, err = opn.InstanceList(description)
	if err != nil {
		return Instance{}, err
	}
	var matches = coreapi.Filter(instances, func(instance Instance) bool {
		return strings.EqualFold(instance.Description, description)
	})
	var name = fmt.Sprintf("openvpn instance with description %q", description)
	switch len(matches) {
	case 0:
		return Instance{}, &coreapi.NotFoundError{Name: name}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, len(matches))
		for i, match := range matches {
			uuids[i] = match.Uuid
		}
		sort.Strings(uuids)
		return Instance{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%d openvpn instances with description %q (uuids: %s)",
			len(matches), description, strings.Join(uuids, ", "))}
	}
}

// InstanceForm returns the get answer: for "" the defaults of a new instance, else the instance with this uuid
// (*NotFoundError when it does not exist). The option fields list every choice, e.g. the CAs and certificates
// of the trust store, the static keys, authentication servers and groups
func (opn *OpenVPNApi) InstanceForm(uuid string) (Form, error) {
	var endpoint = opn.endpoint("instances", "get")
	if uuid != "" {
		endpoint += "/" + uuid
	}
	var form, err = opn.getForm(endpoint, "instance")
	if err != nil {
		return nil, err
	}
	if form == nil {
		return nil, &coreapi.NotFoundError{Name: opn.instanceName(uuid)}
	}
	return form, nil
}

// InstanceCreate adds an instance from fields and returns its uuid. Without a vpnid OPNsense assigns the next
// free one (add without any vpnid fails with "A value is required."). Duplicates are not checked
func (opn *OpenVPNApi) InstanceCreate(fields InstanceFields) (string, error) {
	if err := checkInstanceFields(fields); err != nil {
		return "", err
	}
	var body = InstanceFields{"vpnid": ""}
	for name, value := range fields {
		body[name] = value
	}
	return opn.Mutate(opn.endpoint("instances", "add"), map[string]InstanceFields{"instance": body})
}

// InstanceUpdate sends only the given fields to the instance with this uuid, all other fields are kept.
// Returns *NotFoundError when the uuid does not exist (checked first, set would create it), *ValidationError when
// OPNsense rejects the change. An empty vpnid is refused: OPNsense would renumber the instance
func (opn *OpenVPNApi) InstanceUpdate(uuid string, fields InstanceFields) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	if err := checkInstanceFields(fields); err != nil {
		return err
	}
	if vpnid, given := fields["vpnid"]; given && vpnid == "" {
		return errors.New("an empty vpnid would make OPNsense assign a new one, leave it out to keep the current")
	}
	if _, err := opn.InstanceGet(uuid); err != nil {
		return err
	}
	return opn.instanceSet(uuid, fields)
}

// instanceSet posts fields to set/uuid without checking that uuid exists
func (opn *OpenVPNApi) instanceSet(uuid string, fields InstanceFields) error {
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("instances", "set"), uuid), map[string]InstanceFields{"instance": fields})
	// set creates the instance for a well-formed unknown uuid (InstanceUpdate checks first) and answers a malformed
	// uuid with a bare {"result":"failed"}
	var validationErr *coreapi.ValidationError
	if errors.As(err, &validationErr) && len(validationErr.Validations) == 0 {
		return &coreapi.NotFoundError{Name: opn.instanceName(uuid), Err: err}
	}
	return err
}

// InstanceRemove deletes the instance with this uuid, returns *NotFoundError when it does not exist.
// A running instance keeps running until the configuration is applied (InstancesReconfigure)
func (opn *OpenVPNApi) InstanceRemove(uuid string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	var _, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("instances", "del"), uuid), nil)
	if coreapi.IsNotFound(err) {
		return &coreapi.NotFoundError{Name: opn.instanceName(uuid), Err: err}
	}
	return err
}

// InstanceSetEnabled enables or disables the instance with this uuid and returns whether its state changed.
// Like every change it takes effect with InstancesReconfigure
func (opn *OpenVPNApi) InstanceSetEnabled(uuid string, enabled bool) (bool, error) {
	if uuid == "" {
		return false, errors.New("uuid must not be empty")
	}
	var state = "0"
	if enabled {
		state = "1"
	}
	// toggle/<uuid>/<0|1> sets the state, without it toggle flips it
	var endpoint = fmt.Sprintf("%s/%s/%s", opn.endpoint("instances", "toggle"), uuid, state)
	var result struct {
		Result  string `json:"result"`
		Changed bool   `json:"changed"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return false, err
	}
	switch result.Result {
	case "Enabled", "Disabled":
		return result.Changed, nil
	case "failed": // unknown uuid
		return false, &coreapi.NotFoundError{Name: opn.instanceName(uuid)}
	default:
		return false, fmt.Errorf("unexpected result from %s: %q", endpoint, result.Result)
	}
}

// InstancesReconfigure applies the saved configuration (configd "openvpn configure"): writes the configuration
// of every instance, (re)starts the enabled instances whose configuration changed or which are not running and
// stops removed ones
func (opn *OpenVPNApi) InstancesReconfigure() error {
	return opn.serviceAction(opn.endpoint("service", "reconfigure"))
}

// InstanceStart starts the instance with this uuid. OPNsense answers ok for any id and silently ignores disabled
// instances, so callers should check that the instance exists and is enabled
func (opn *OpenVPNApi) InstanceStart(uuid string) error {
	return opn.instanceServiceAction("start_service", uuid)
}

// InstanceStop stops the instance with this uuid (see InstanceStart)
func (opn *OpenVPNApi) InstanceStop(uuid string) error {
	return opn.instanceServiceAction("stop_service", uuid)
}

// InstanceRestart restarts the instance with this uuid (see InstanceStart)
func (opn *OpenVPNApi) InstanceRestart(uuid string) error {
	return opn.instanceServiceAction("restart_service", uuid)
}

// instanceServiceAction posts service/<method>/<id>: the id of an instance is its uuid, legacy servers and
// clients use their vpnid
func (opn *OpenVPNApi) instanceServiceAction(method string, uuid string) error {
	if uuid == "" {
		return errors.New("uuid must not be empty")
	}
	return opn.serviceAction(fmt.Sprintf("%s/%s", opn.endpoint("service", method), uuid))
}

// serviceAction POSTs a service action, which answers {"result":"ok"} (a GET is answered with "failed")
func (opn *OpenVPNApi) serviceAction(endpoint string) error {
	var result struct {
		Result string `json:"result"`
	}
	if err := opn.DoJSON("POST", endpoint, nil, &result); err != nil {
		return err
	}
	if !strings.EqualFold(result.Result, "ok") {
		return fmt.Errorf("%s failed: %q", endpoint, result.Result)
	}
	return nil
}
