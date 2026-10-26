## WAT

Implementation of the OPNsense WebAPI to be used on the CLI or as a library - written in Golang

Developed and tested against OPNsense 26.7. It uses the current (snake_case) API endpoints, so older releases are not tested and may not work.
The Dnsmasq commands need the Dnsmasq MVC API, which was introduced with OPNsense 25.1.

Covered (everything OPNsense 26.7 exposes through its MVC API, legacy PHP pages have no API and are left out):

- **DNS & DHCP**: Unbound (host overrides and aliases, settings, ACLs, forwarding / DNS over TLS, blocklists,
  statistics), Dnsmasq (hosts, domains, DHCP ranges, options, tags, boot, leases, settings), Kea DHCPv4/v6
  (subnets, reservations, options, prefix delegation, HA peers, leases), DHCP relay, router advertisements
- **Firewall**: rules, NAT (source, port forward, one-to-one, NPTv6), aliases and pf tables, interface groups,
  categories, traffic shaper, states, sessions, statistics, log
- **VPN**: OpenVPN (instances, static keys, client overrides, sessions, client export), IPsec (connections,
  authentication rounds, children, pools, VTIs, keys, sessions, SAD/SPD), WireGuard (instances, peers incl.
  client config generator, status)
- **Interfaces**: VLAN, LAGG, bridge, GIF, GRE, VXLAN, loopback devices, virtual IPs / CARP, static neighbors,
  settings, overview, ARP/NDP tables, netstat, host discovery, counters and throughput
- **System**: users, groups, privileges, API keys, services, firmware and packages, HA sync, snapshots, cron,
  tunables, logging, backups, factory defaults, gateways, routes, trust (CAs, certificates, CRLs), health
  graphs, memory, NTP status, resources, activity, reboot / shutdown
- **Services**: captive portal (zones, templates, sessions, vouchers), intrusion detection (Suricata settings,
  rule sets, rules, policies, alerts), Monit
- **Tools**: API connection check, ping, traceroute, port probe, DNS lookup, packet capture, top talkers,
  NetFlow and Insight

## Installation

Its precompiled and has no dependencies, so just download the binary for your platform, and you are good to go

    Pick a release from the releases page of this repository
    chmod +x opn-*

Or build it yourself (needs Go, see `go.mod` for the version), the binaries end up in `dist/`

    make build

You need to create a .env (dotenv) for the secrets, or expose them into your ENV using `export`

    # trailing slash is fine
    OPN_URL=https://localhost:10443
    OPN_APIKEY=5GWbPwKfXVLzgJnewKuu1IPw2HS7s510jKHmTM+rLA1y9VfEFE57yj/kJiWbXREB0EgpBK48u4gnyign
    OPN_APISECRET=EtpPVbiCBdtvG5VDlYJQfLu7Qck2hRffoLi2vb73arn5bKzxEbGdti8+iZetgc9eHABJy6XYG6/UsW/1
    # if we should not verify SSL while talking to opn, enable that
    #OPN_NOSSLVERIFY=1

## Usage: cli

`opn` is a menu driven CLI in the style of MikroTik RouterOS (with a bit of Junos): the commands live in a tree of
menus like `/dnsmasq/host`, take `name=value` arguments and work the same in three modes

- **interactive shell**: run `opn` without arguments. The prompt shows the current menu, TAB completes menus,
  commands, argument names and item names, `?` shows the help of the current menu (or of a command:
  `add ?`), the history is kept in `~/.opn_history`, Ctrl-C clears the line or stops a running command
  (`follow`, `monitor-traffic`, ...) without leaving the shell, `exit` or Ctrl-D quits
- **one-shot**: `opn <path> <command> <arguments>`, e.g. `opn /dnsmasq host print`
- **scripts**: when stdin is not a terminal `opn` runs it line by line (`opn < setup.rsc`), `/import setup.rsc` does the
  same for a file. A menu path alone on a line changes the menu for the following lines, `#` starts a comment,
  the first error stops the script with `error: <file>:<line>: ...` and exit code 1

```
$ opn
[opn@opnsense-dev] /> /dnsmasq/host
[opn@opnsense-dev] /dnsmasq/host> add host=web domain=example.lan ip=10.0.0.5,fd00::5
1f0c...
[opn@opnsense-dev] /dnsmasq/host> print
#  HOST  DOMAIN       IP                 HWADDR  CNAME  DESCRIPTION
0  web   example.lan  10.0.0.5, fd00::5  -       -      -
[opn@opnsense-dev] /dnsmasq/host> set 0 description="web server"
[opn@opnsense-dev] /dnsmasq/host> ../service reconfigure
```

A path is absolute with a leading `/`, relative to the current menu otherwise, `..` goes up; the path and the
command can be separated by spaces or `/`. Every name may be abbreviated as long as it is unique. These are all
the same:

    opn /dnsmasq host print
    opn dnsmasq/host print
    opn '/dnsmasq host print'    # a single argument is split like a shell line
    opn /dns ho pr

`opn /check` tests the connection: it makes one read-only API call and prints the firewall's host name, versions,
TLS state and latency. When it fails, the error names the step (`dns`, `connect`, `tls`, `auth`, `api`) with a
hint, and the exit code is 1:

    $ opn /check
    url:       https://opnsense-dev
    status:    ok
    hostname:  OPNsense.internal
    versions:  OPNsense 26.7-amd64, FreeBSD 15.1-RELEASE-p1, OpenSSL 3.5.7
    tls:       not verified (OPN_NOSSLVERIFY=1)
    protocol:  HTTP/2.0
    latency:   121ms
    $ OPN_APISECRET=wrong opn /check
    error: auth: authentication failed (check OPN_APIKEY and OPN_APISECRET, and that the key's user is not disabled)

`opn version` (or `opn --version`) prints the version of opn, the release tag it was built from, without
contacting the firewall; `version detail` adds the Go version and platform.

`opn -v ...` logs every API request (method, URL, status, duration) to stderr, credentials are never logged.
`opn -h` and `opn <path> ?` show the help. Errors are printed as `error: ...` on stderr with exit code 1
(2 for an unknown option).

### Menus

| menu | commands | key arguments, items |
|---|---|---|
| `/unbound/host-override` | `print show add set remove enable disable` | `host= domain= rr=A\|AAAA\|MX\|TXT ip= mx= mx-priority= txtdata= ttl= ptr= description= disabled`; items: `host.domain`, `host.domain/RR` when the FQDN has several records |
| `/unbound/service` | `status restart reconfigure` | |
| `/unbound/settings`, `/unbound/advanced` | `print set` | General and Advanced pages: `enabled port= interface= dnssec dns64 register-dhcp ...`, `hide-version prefetch serve-expired ...` |
| `/unbound/acl` | `print show add set remove enable disable default-action` | `name= action=allow\|deny\|refuse\|... networks= description= disabled`; items: the name |
| `/unbound/forward` | `print show add set remove enable disable system-nameservers` | query forwarding and DNS over TLS: `type=forward\|dot domain= server= port= verify= forward-first`, `set type=` converts |
| `/unbound/blocklist` | `print show add set remove enable disable types update allow block test` | DNSBL policies: `type= lists= allowlists= blocklists= wildcards= source-nets= nxdomain`; `update` downloads and loads, `allow`/`block` a domain |
| `/unbound/host-alias` | `print show add set remove enable disable` | aliases of host overrides: `host=<override> hostname= domain= description=` |
| `/unbound/statistics` | `print queries history counters reset` | totals and top (blocked) domains `top=`, recent queries, unbound-control counters; needs `/unbound/settings set statistics=yes` |
| `/unbound/diagnostics` | `cache infra local-zones local-data insecure` | dumps of the resolver state |
| `/dnsmasq/host` | `print show add set remove` | `host= domain= ip= cname= alias= hwaddr= client-id= lease-time= local ignore description= comments=` (lists comma separated); items: `host.domain` or the hostname |
| `/dnsmasq/domain` | `print show add set remove` | `domain= ip= port= source-ip= sequence= description=`; items: the domain |
| `/dnsmasq/lease` | `print` | |
| `/dnsmasq/service` | `status start stop restart reconfigure` | |
| `/dnsmasq/settings` | `print set` | general DNS and DHCP settings: `enabled interface= port= strict-bind register-dhcp dhcp-first domain-needed ...` |
| `/dnsmasq/range` | `print show add set remove` | DHCP ranges: `interface= start= end= subnet-mask= lease-time= mode=static prefix-len= ra-mode= set-tag= domain=` |
| `/dnsmasq/option` | `print show add set remove codes` | DHCP options: `type=set\|match option= option6= interface= tag= set-tag= value= force`; `codes` lists the option names |
| `/dnsmasq/tag`, `/dnsmasq/boot` | `print show add set remove` | DHCP tags `name=`; boot/PXE entries `interface= tag= filename= servername= address=`; tags are given by name |
| `/kea/dhcp4/subnet`, `/kea/dhcp6/subnet` | `print show add set remove` | `subnet= pools= description= valid-lifetime= auto-options routers= dns-servers= domain-name= ...` (v6: `interface= pd-allocator= ...`); items: the network or description |
| `/kea/dhcp4/reservation`, `/kea/dhcp6/reservation` | `print show add set remove` | `ip-address= mac-address= client-id= hostname= description=` (v6: `duid= prefix=`), the subnet is found from the address; items: hostname, MAC or IP |
| `/kea/dhcp4/option`, `/kea/dhcp6/option`, `/kea/dhcp6/pd-pool` | `print show add set remove` | custom options `code= encoding= data= force`; prefix delegation pools `subnet= prefix= delegated-length=` |
| `/kea/dhcp4/peer`, `/kea/dhcp6/peer` | `print show add set remove` | HA peers: `name= role=primary\|standby url=` |
| `/kea/dhcp4/lease`, `/kea/dhcp6/lease` | `print remove` | `print interface= search= detail json` |
| `/kea/dhcp4/settings`, `/kea/dhcp6/settings`, `/kea/ctrl-agent`, `/kea/ddns` | `print set` | `enabled interfaces= valid-lifetime= firewall-rules ...`, control agent `http-host= http-port=`, DDNS `server-ip= server-port=` |
| `/kea/service`, `/radvd/service` | `status start stop restart reconfigure` | stop and restart ask for confirmation |
| `/dhcrelay/destination`, `/dhcrelay/relay` | `print show add set remove` (`enable disable`) | destinations `name= servers=`; relays `interface= destination= agent-info disabled` |
| `/dhcrelay/service` | `reconfigure` | |
| `/radvd/entry` | `print show add set remove enable disable` | router advertisements, one per interface: `interface= mode= dns-servers= dns-search= routes= min-interval= max-interval= disabled` |
| `/system/cron` | `print show add set remove enable disable commands apply` | `description= command= parameters= minutes= hours= days= months= weekdays= who= disabled`; items: the description |
| `/system/tunable` | `print show add set remove apply` | `name= value= description=`, `print changed`; items: the tunable name |
| `/system/logging` | `print set stats` | `set enabled= local= max-preserve= max-file-size=` |
| `/system/logging/destination` | `print show add set remove enable disable` | `hostname= transport= port= program= level= facility= certificate= rfc5424 description= disabled`; items: the description |
| `/system/logging/service` | `status restart reconfigure` | |
| `/system/backup` | `print providers download diff revert remove` | `provider=`, `download [item] file= overwrite`, `diff from= to=`; items: backup ids like `config-1792886029.2372.xml`, `current` |
| `/system/defaults` | `print reset` | |
| `/system/wizard` | `print` | read-only, passwords are never shown |
| `/system` | `reboot shutdown` | `reboot wait timeout= poll-interval=` |
| `/system/resource` | `print monitor` | versions, uptime, memory, disks, ...; `monitor` streams the CPU usage, `once` |
| `/system/activity` | `print` | top: `lines= follow interval=` |
| `/system/user` | `print show add set remove enable disable password` | `name= password= full-name= email= groups= privileges= shell= expires= disabled`; `password` asks without echo; root and the user of the API key can't be removed or disabled |
| `/system/user/api-key` | `print add remove` | `add <user> file= overwrite` prints key and secret once; the key opn uses can't be removed |
| `/system/group` | `print show add set remove` | `name= description= members= privileges= source-networks=`; the admins group is protected |
| `/system/privilege` | `print show grant revoke` | `print user= group= granted`, `grant <privilege> user= group=` |
| `/system/service` | `print show start stop restart` | all services (System > Diagnostics > Services); stopping or restarting webgui, configd, openssh, pf or routing needs `confirm=yes` |
| `/system/firmware` | `status check audit update upgrade log` | `audit type=security\|health\|connection`; actions run on the firewall, opn follows their log (`background` only starts them) |
| `/system/firmware/package`, `/system/firmware/plugin` | `print show license install remove reinstall lock unlock` | `print all`; everything that changes packages asks for confirmation |
| `/system/firmware/changelog`, `/system/firmware/settings` | `print show`, `print set` | settings: `mirror= flavour= type= subscription=` (masked) |
| `/system/ha` | `print set apply status sync` | High Availability: `pfsync-interface= pfsync-peer-ip= synchronize-to-ip= username= password= sync-items=`; `/system/ha/service` controls services on the backup node |
| `/system/snapshot` | `print show add set remove activate` | ZFS boot environments: `add name= from=` (refused on UFS) |
| `/system/license` | `print` | `print package=` shows a package's license |
| `/system/health` | `print export reset-data` | RRD reports: `print` lists them, `print metric= resolution=1m\|5m\|1h\|1d from= to=` shows values; `/system/health/settings` switches collection on |
| `/system/memory` | `print` | kernel memory per malloc type, `zone` per UMA zone, `sort= limit=` |
| `/system/ntp` | `status` | NTP peers and GPS, `follow` |
| `/system/gateway` | `print show add set remove enable disable apply monitor` | `name= interface= protocol=ipv4\|ipv6 address= priority= weight= upstream far-gateway monitor= monitor-disabled latency-low= latency-high= loss-low= loss-high= description= disabled`; items: the gateway name; dynamic gateways (`WAN_DHCP`) are changed by storing an override |
| `/system/gateway/group` | `print show add set remove apply` | `name= tier1=..tier5= trigger=member-down\|packet-loss\|high-latency\|packet-loss-or-latency pool=default\|round-robin\|round-robin-sticky description=`; items: the group name |
| `/system/route` | `print show add set remove enable disable apply` | `network= gateway= description= disabled`; items: the network |
| `/system/route/status` | `print remove` | the kernel routing table: `print protocol= interface= resolve follow`, `remove` (refuses default routes without `allow-default`) |
| `/system/trust/authority` | `print show add set remove dump export` | `add method=internal\|intermediate\|import common-name= key-type= digest= lifetime= issuer= certificate-file= key-file=`, `export type=cert\|key file= overwrite`; items: the description or refid |
| `/system/trust/certificate` | `print show add set remove reissue import-signed dump export` | `add method=internal\|self-signed\|csr\|import\|sign-csr issuer= type=server\|client\|combined\|ca common-name= alt-dns= alt-ip= ...`, `print expiring=30`, `export type=cert\|key\|csr\|pkcs12 password= file= overwrite` |
| `/system/trust/revocation` | `print show add set remove revoke unrevoke dump export` | one list per CA: `revoke <ca> certificate= reason=`, `add method=internal\|import crl-file= lifetime=` |
| `/system/trust/settings` | `print set apply` | `store-intermediate-certs install-crls fetch-crls min-protocol= cipher-string= ...`, `print options=<field>` |
| `/log` | `print files clear` | `print [log=]system lines= follow search= severity=`; logs: a scope like `system`, `configd`, `dnsmasq` or `<module>/<scope>`, see `files` |
| `/firewall/log` | `print filters stats` | `print lines= follow stream interval= action= interface= dir= proto= src= dst= port= search= scan=`, `stats by= scan=` |
| `/firewall/rule` | `print show add set remove enable disable move apply confirm-apply revert export import` | `action=pass\|block\|reject interface= direction= ip-protocol= protocol= source= destination= source-port= destination-port= log quick categories= gateway= description= disabled` (`!` inverts an address) and the advanced pf options; `add place-before=`, `print interface= stats`; items: the description. Automatic rules are shown, never changed |
| `/firewall/nat/source`, `destination`, `one-to-one`, `npt` | `print show add set remove enable disable move apply export import` | source: `interface= source= destination= target= target-port= no-nat static-port`; destination (port forward): `interface= protocol= destination= destination-port= target= target-port= nat-reflection= filter-rule=`; one-to-one: `type=binat\|nat external= source=`; npt: `internal-prefix= external-prefix= track-interface=` |
| `/firewall/nat/source/mode` | `print set` | `set mode=automatic\|hybrid\|manual\|disabled` |
| `/firewall/alias` | `print show add set remove enable disable apply export import categories countries` | `name= type=host\|network\|port\|url\|urltable\|geoip\|networkgroup\|mac\|asn\|dynipv6host\|authgroup\|external content= categories= updatefreq= description= disabled`; items: the alias name. Built-in aliases are read-only |
| `/firewall/alias/table` | `print add remove flush find update-bogons` | the live pf tables: `print [alias]`, `add <alias> address=`, `find <address>` |
| `/firewall/alias/geoip` | `print set update` | GeoIP source of geoip aliases: `set url=` (`url=` clears; masked in print/json, used after `/firewall/alias apply`), `update` downloads the database |
| `/firewall/group` | `print show add set remove apply` | interface groups: `name= members= sequence= no-group description=` |
| `/firewall/category` | `print show add set remove` | `name= color=` |
| `/firewall/shaper/pipe`, `queue`, `rule` | `print show add set remove enable disable` | pipe: `bandwidth=100Mbit scheduler= mask= delay= codel pie description=`; queue: `pipe= weight=`; rule: `interface= protocol= source= destination= direction= target=<pipe or queue>` |
| `/firewall/shaper` | `status reconfigure flush-reload` | `status detail follow` (`apply` is an alias of `reconfigure`) |
| `/firewall/state` | `print remove kill flush flush-sources rule-ids` | `print search= rule= interface= protocol= src= dst= port= sort= limit= follow`, `kill <filters>`, `flush drop-own-connection` |
| `/firewall/session` | `print` | pftop: `sort= limit= search= follow` |
| `/firewall/statistics` | `print states` | pf statistics: `print section=info\|memory\|timeouts\|interfaces\|rules` |
| `/firewall/migration` | `print export flush` | legacy rules left to migrate: `export type=filter\|outbound file=` |
| `/vpn/openvpn/instance` | `print show add set remove enable disable start stop restart apply` | `role=server\|client description= protocol= port= dev-type= topology= tunnel-network= local-networks= remote-networks= ca= cert= tls-key= authentication= ...`; items: the description. Passwords are masked |
| `/vpn/openvpn/static-key` | `print show add set remove` | `description= mode=auth\|crypt\|crypt-v2` (generated unless `key=` / `key-file=`), `set regenerate` |
| `/vpn/openvpn/client-override` | `print show add set remove enable disable` | `common-name= servers= tunnel-network= local-networks= remote-networks= redirect-gateway= dns-servers= block description= disabled`; items: the common name |
| `/vpn/openvpn/session` | `print remove` | connected clients: `print type=server\|client follow`, `remove` (alias `kill`) disconnects |
| `/vpn/openvpn/route` | `print` | |
| `/vpn/openvpn/export` | `print show accounts templates set download` | `download <server> account= template= hostname= port= file= overwrite p12-password=` (only enabled servers can be exported) |
| `/vpn/ipsec/connection` | `print show add set remove enable disable` | `description= version=ike\|ikev1\|ikev2 proposals= local-addresses= remote-addresses= mobike ...`; items: the description |
| `/vpn/ipsec/local`, `remote`, `child` | `print show add set remove enable disable` | authentication rounds `connection= round= auth= id= certs= pubkeys=`; children (CHILD SAs) `connection= mode= local-ts= remote-ts= esp-proposals= start-action=` |
| `/vpn/ipsec/pool`, `vti`, `manual-spd` | `print show add set remove enable disable` | address pools `name= network= dns=`, VTIs `reqid= local= remote= tunnel-local= tunnel-remote=` (device ipsec&lt;reqid&gt;), manual SPD entries |
| `/vpn/ipsec/pre-shared-key`, `key-pair` | `print show add set remove` (`generate export`) | `local-id= remote-id= type=PSK\|EAP key=`; key pairs `name= type=rsa\|ecdsa`, `export` the public key; secrets are never shown |
| `/vpn/ipsec/settings` | `print set` | Mobile & Advanced settings (charon options, log levels, RADIUS, ...) |
| `/vpn/ipsec/service` | `status enable disable start stop restart reconfigure apply` | `enable` + `reconfigure` switches IPsec on; stop and restart ask for confirmation |
| `/vpn/ipsec/session`, `sad`, `spd`, `lease` | `print show phase2 connect disconnect`, `print remove`, `print pools` | phase 1/2 sessions, kernel SAD/SPD, pool leases; disconnect and remove ask for confirmation |
| `/vpn/wireguard/instance` | `print show add set remove enable disable` | `name= port= tunnel-address= peers= mtu= dns= disable-routes gateway= disabled`; the key pair is generated unless `private-key=`, private keys are never shown |
| `/vpn/wireguard/peer` | `print show add set remove enable disable generate config` | `name= public-key= psk= generate-psk tunnel-address= endpoint-address= endpoint-port= keepalive= instances=`; `generate` creates a peer with a new key pair and writes its client .conf |
| `/vpn/wireguard/settings`, `status`, `service` | `print set`, `print`, `status start stop restart reconfigure` | the global enable switch; `wg show` with handshakes and transfer (`follow`) |
| `/captive-portal/zone` | `print show add set remove enable disable` | `description= interfaces= auth-servers= idle-timeout= hard-timeout= concurrent-logins roaming certificate=`; zones are added disabled, `enable` asks for confirmation |
| `/captive-portal/template` | `print show set remove upload download download-default` | login page templates as zip files |
| `/captive-portal/session`, `voucher` | `print disconnect`, `providers groups print generate expire drop-expired drop-group` | logged in clients (`zone= follow`); vouchers: `generate` writes a CSV |
| `/captive-portal/service` | `status start stop restart reconfigure` | |
| `/ids/settings`, `/ids/service` | `print set`, `status start stop restart reconfigure reload-rules` | Suricata: `enabled mode=pcap\|netmap\|divert interfaces= home-networks= ...`; start, restart and reconfigure ask for confirmation |
| `/ids/ruleset` | `print show enable disable update` | rule sets to download, `update` downloads; `/ids/ruleset/property` holds their properties |
| `/ids/rule` | `print show set enable disable reset` | installed rules by sid (no `#`): `print search= limit= page=`, `set <sid> action=alert\|drop` |
| `/ids/policy`, `/ids/user-rule` | `print show add set remove enable disable` | policies `description= priority= rulesets= match-action= new-action=`; user rules `source= destination= fingerprint= action=`; `/ids/policy/adjustment` lists rule adjustments |
| `/ids/alert` | `print show` | `print log= follow`, `/ids/alert/log` lists and removes the alert log files |
| `/monit/service`, `/monit/test`, `/monit/alert` | `print show add set remove` (`enable disable`) | monitored services `name= type= pidfile= match= path= address= tests=`, tests `name= condition= action=`, alert recipients `recipient= events= format=` |
| `/monit/settings`, `/monit/status`, `/monit/service-control` | `print set`, `print`, `status start stop restart reconfigure` | general settings (passwords hidden), the status report, the daemon |
| `/interface` | `print monitor-traffic` | `print`: counters since boot; `monitor-traffic interface= interval= once` |
| `/interface/vlan` | `print show add set remove apply` | `parent= tag= pcp= proto=auto\|802.1q\|802.1ad name= description=`; items: the device name (vlan01) or description |
| `/interface/lagg`, `bridge` | `print show add set remove apply` | lagg `members= protocol= lacp-fast-timeout hash= mtu=`, bridge `members= stp protocol=rstp\|stp span= ...`; apply asks for confirmation |
| `/interface/gif`, `gre`, `vxlan`, `loopback` | `print show add set remove apply` | tunnels `local-address= remote-address= tunnel-local-address= tunnel-remote-address=`, vxlan `vni= remote-address= group= interface=`, loopback `description=` |
| `/interface/vip` | `print show add set remove apply` | virtual IPs: `interface= mode=ipalias\|carp\|proxyarp address= vhid= password= adv-base= adv-skew=`; the CARP password is never shown. `/interface/vip-status` shows CARP status and toggles maintenance mode (asks for confirmation) |
| `/interface/neighbor` | `print show add set remove apply` | static ARP/NDP entries: `address= mac-address= description=` |
| `/interface/settings` | `print set apply` | offloading, VLAN hardware filter, IPv6 and DHCPv6 settings; apply reconfigures all interfaces and asks for confirmation |
| `/interface/overview`, `assignment` | `print show reload`, `print` | state and statistics of every device, reload (asks for confirmation); assignments are read only |
| `/interface/arp`, `ndp`, `netstat` | `print flush`, `print`, `interfaces sockets protocols bpf memory netisr` | ARP (`flush` asks for confirmation) and NDP tables, netstat |
| `/interface/host-discovery` | `print status start stop restart reconfigure` | hosts found by hostwatch, `/interface/host-discovery/settings` |
| `/tool` | `torch` | top talkers: `interface= lines= interval= once` |
| `/tool` | `ping traceroute port-probe dns-lookup` | `ping <address> count= size= source=`, `traceroute <address> protocol=udp\|icmp`, `port-probe <address> port=`, `dns-lookup <name> server=` |
| `/tool/sniffer` | `print start stop view download remove` | packet capture: `start interface= host= port= protocol= count= duration=`, `download <capture> file= overwrite` (pcap files in a zip) |
| `/tool/netflow` | `print set status reconfigure reset-data` | NetFlow: `interfaces= egress-only= version= targets= collect`; `/tool/netflow/cache print` |
| `/tool/insight` | `print history export` | NetFlow data: `print by=interface\|protocol\|service\|talker\|flow from= to= measure= limit=`, `history`, CSV `export` |
| `/ddclient/account` | `print show add set remove enable disable refresh` | Dynamic DNS accounts (plugin os-ddclient): `description= service= username= password= hostnames= check-ip= interface= zone= ttl= disabled`; items: the description; print shows the current address and last update, `print options=service` the services of the backend; passwords are never printed, `refresh` forces an update at the provider (asks for confirmation) |
| `/ddclient/settings`, `/ddclient/service` | `print set`, `status start stop restart reconfigure` | `enabled verbose allow-ipv6 interval= backend=native\|ddclient` |
| `/node-exporter/settings`, `/node-exporter/service` | `print set`, `status start stop restart reconfigure` | Prometheus node exporter (plugin os-node_exporter): `enabled listen-address= listen-port= collectors=` |
| `/` | `import check version` | `import file`; `check` tests the API connection, `version` shows opn's version (see below) |

`/ddclient` and `/node-exporter` need their plugin (`/system/firmware/plugin install os-ddclient`,
`os-node_exporter`); without it they say so. Let the node exporter listen on a LAN address or 127.0.0.1 rather than
the default 0.0.0.0 (all interfaces, WAN included).

`help` and `exit` work in every menu. `opn <menu> ?` and `opn <menu> <command> ?` list everything with its help.

### Items, add, set, remove

`show`, `set`, `remove`, `enable` and `disable` take the item as first argument (or `item=`): the `#` of the last
`print` in that menu, the uuid, or its name (see the table, e.g. `web.example.lan`). In the shell and in scripts
the `#` refers to the rows of the last print (with its `search=`) and stays valid until the next print; an item
removed meanwhile is refused instead of hitting another one. In a one-shot call there is no print before, `#` is
the position in the full list.

    /unbound/host-override print search=example.lan
    /unbound/host-override set 0 ttl=300
    /unbound/host-override remove www.example.lan/TXT

- `add` creates an item and prints its uuid. It fails when an item with the same key (FQDN and record type,
  description, tunable name, ...) exists already, unless `replace` is given: then that item is overwritten
  completely, arguments not given are reset to their defaults
- `set` changes only the given arguments (`description=` clears one), it never creates an item
- `remove` deletes, `enable` / `disable` toggle the RouterOS style `disabled` argument (`add ... disabled`,
  `set 0 disabled=no`)
- changes are silent on success (apart from the uuid of `add`), like RouterOS
- booleans are flags (`local`, `local=no`, `disabled=yes`), lists are comma separated (`ip=10.0.0.1,fd00::1`,
  `ip=` clears), values with spaces are quoted (`description="web server"`)

Everything that can be checked locally (addresses, ports, ranges, required arguments, ...) is validated before
any API call.

### Applying changes

Changes are only saved to the configuration. Apply them like in the web UI:

| after changing | run |
|---|---|
| unbound host overrides | `/unbound/service reconfigure` |
| dnsmasq hosts / domains | `/dnsmasq/service reconfigure` |
| cron jobs | `/system/cron apply` |
| tunables | `/system/tunable apply` |
| logging settings, destinations | `/system/logging/service reconfigure` |
| gateways, gateway groups | `/system/gateway apply`, `/system/gateway/group apply` |
| static routes | `/system/route apply` |
| trust settings | `/system/trust/settings apply` (CAs, certificates and CRLs apply immediately) |
| OpenVPN instances, static keys | `/vpn/openvpn/instance apply` (client overrides apply on the next connect) |
| filter rules, NAT | `/firewall/rule apply` or `/firewall/nat/<kind> apply` (both reload the whole ruleset, see below) |
| aliases, interface groups | `/firewall/alias apply` (also activates a changed `/firewall/alias/geoip` URL), `/firewall/group apply` |
| shaper | `/firewall/shaper reconfigure` |
| Unbound settings, ACLs, forwards | `/unbound/service reconfigure general` (blocklists: `/unbound/blocklist update`) |
| Dnsmasq settings, DHCP ranges, options, tags, boot | `/dnsmasq/service reconfigure` |
| Kea, router advertisements, DHCP relay | `/kea/service reconfigure`, `/radvd/service reconfigure`, `/dhcrelay/service reconfigure` |
| interface devices, virtual IPs, neighbors, settings | `apply` in the menu, e.g. `/interface/vlan apply` |
| IPsec | `/vpn/ipsec/service reconfigure` (`enable` first to switch IPsec on) |
| WireGuard | `/vpn/wireguard/service reconfigure` |
| captive portal | `/captive-portal/service reconfigure` |
| IDS rule sets, rules, policies, user rules / settings | `/ids/service reload-rules` / `/ids/service reconfigure` |
| Monit | `/monit/service-control reconfigure` |
| NetFlow, health settings | `/tool/netflow reconfigure`, `/system/health/settings reconfigure` |
| HA settings | `/system/ha apply` |
| Dynamic DNS (os-ddclient), node exporter (os-node_exporter) | `/ddclient/service reconfigure`, `/node-exporter/service reconfigure` |

```
opn /unbound host-override add host=foo domain=bar.tld ip=10.10.10.1    # not resolvable yet
opn /unbound service reconfigure                                        # now it is
```

### Dangerous commands

`/system reboot`, `/system shutdown`, `/system/defaults reset`, `/system/backup revert`, `/system/backup remove`,
`/log clear`, `/system/route/status remove`, `/system/trust/certificate reissue`, `/system/trust/revocation remove`,
`/vpn/openvpn/instance stop|restart`, `/vpn/openvpn/session remove`, `/firewall/rule apply|revert|import`, the NAT
`apply` and `import`, `/firewall/alias/table flush`, `/firewall/state remove|kill|flush|flush-sources`,
`/firewall/shaper flush-reload`, `/firewall/migration flush`, `/ddclient/account refresh`, removing users, groups and API keys, firmware
update / upgrade and package changes, `/system/ha sync`, `/system/snapshot activate`, the stop / restart of most
services, `/interface/lagg|bridge|settings apply`, `/interface/overview reload`, `/interface/arp flush`, the
CARP commands of `/interface/vip-status`, IPsec session disconnect and SAD/SPD remove, captive portal zone
enable, session disconnect and voucher expire / drop, IDS start / restart / reconfigure and the `reset-data` of
health and NetFlow ask `[y/N]` in the shell. In one-shot calls and
scripts there is nobody to ask: they refuse to run unless `confirm=yes` is given.

    opn /system reboot confirm=yes wait timeout=10m    # wait polls until the firewall is back up

`/firewall/rule apply` uses OPNsense's savepoint with automatic rollback where the firewall offers it (up to 26.1):
it prints a revision, and unless `/firewall/rule confirm-apply <revision>` follows within 60 seconds the previous
rules come back. OPNsense 26.7 has no rollback any more, there `apply` (like the NAT `apply`) loads the rules
directly, so a wrong rule can cut off your access.

### Output

- `print` shows a table with a `#` column, `print detail` all fields of every item, `print json` one raw API
  object per line (ndjson, e.g. for `jq`), `search=` filters
- `show` prints one item as `name: value` lines
- data goes to stdout, messages and hints (`replaced the existing host ...`, `already disabled`) to stderr
- streaming commands (`/log print follow`, `/firewall/log print follow|stream`, `/interface monitor-traffic`,
  `/system/resource monitor`, `/system/activity print follow`, `/tool torch`, `/system/gateway monitor`,
  `/firewall/state print follow`, `/vpn/openvpn/session print follow`, ...) run until Ctrl-C, reconnect dropped
  streams and exit 0 when stopped. `once` (monitors) prints a single measurement, `json` the raw events

    opn /firewall log print follow json action=block | jq .src
    opn /log print configd lines=0 follow search="dnsmasq status"

### Migrating from the old flags

The cobra style commands (`opn unbound hostoverride create --host ...`) are gone. Old `create` is `add` (with
`replace` for the old create-or-update), `update` is `set`, `rm` is `remove`, `list` is `print`; flags became
arguments (`--search x` is `search=x`, `-n 10` is `lines=10`, `-f/--follow` is `follow`, `--json` is `json`,
`--yes` is `confirm=yes`, `--enabled 0` is `disabled`) and `--uuid X` / `--host --domain` selectors became the item.

| old | new |
|---|---|
| `unbound hostoverride create --host h --domain d --ip X [--addptr 0] [--mxprio 10] [--enabled 0]` | `/unbound/host-override add host=h domain=d ip=X [ptr=no] [mx-priority=10] [disabled]` (`replace` to overwrite) |
| `unbound hostoverride update (--uuid U \| --host h --domain d [--rr TXT]) --ttl 300` | `/unbound/host-override set (U \| h.d \| h.d/TXT \| #) ttl=300` |
| `unbound hostoverride show\|rm ...`, `list --search s` | `/unbound/host-override show\|remove <item>`, `print search=s` |
| `unbound service status\|restart\|reconfigure` | `/unbound/service status\|restart\|reconfigure` |
| `dnsmasq host create --host h --domain d --ip a --ip b` | `/dnsmasq/host add host=h domain=d ip=a,b` |
| `dnsmasq host update --host h --domain d --new-host n --new-domain m` | `/dnsmasq/host set h.d host=n domain=m` |
| `dnsmasq domain create --domain d --ip X --srcip S` | `/dnsmasq/domain add domain=d ip=X source-ip=S` |
| `dnsmasq domain update --domain d --new-ip Y` | `/dnsmasq/domain set d ip=Y` |
| `dnsmasq leases list` | `/dnsmasq/lease print` |
| `dnsmasq service status\|start\|stop\|restart\|reconfigure` | `/dnsmasq/service ...` |
| `system cron create --command c --description x --enabled 0` | `/system/cron add command=c description=x disabled` |
| `system cron update --description x --new-description y --hours 4` | `/system/cron set x description=y hours=4` |
| `system cron show\|rm\|enable\|disable --description x`, `commands`, `apply` | `/system/cron show\|remove\|enable\|disable x`, `commands`, `apply` |
| `system tunable set --name n --value v` | `/system/tunable add name=n value=v` (or `set n value=v`) |
| `system tunable list --changed`, `show\|rm --name n`, `apply` | `/system/tunable print changed`, `show\|remove n`, `apply` |
| `system logging show`, `set --loglocal=false --maxpreserve 31 --maxfilesize ..` | `/system/logging print`, `set local=no max-preserve=31 max-file-size=..` |
| `system logging stats --search s` | `/system/logging stats search=s` |
| `system logging destination create --hostname h --enabled=false` | `/system/logging/destination add hostname=h disabled` |
| `system logging destination update\|show\|rm\|enable\|disable --description x` | `/system/logging/destination set\|show\|remove\|enable\|disable x` |
| `system logging service status\|restart\|reconfigure` | `/system/logging/service ...` |
| `system backup list -p P`, `providers` | `/system/backup print provider=P`, `providers` |
| `system backup download --id I -o f -f` | `/system/backup download I file=f overwrite` |
| `system backup diff --from A --to B` | `/system/backup diff from=A to=B` (or `diff A`, against current) |
| `system backup revert\|rm --id I --yes` | `/system/backup revert\|remove I confirm=yes` |
| `system wizard show`, `system defaults show` | `/system/wizard print`, `/system/defaults print` |
| `system defaults reset --yes` | `/system/defaults reset confirm=yes` |
| `power reboot --yes [--wait --timeout 10m]` | `/system reboot confirm=yes [wait timeout=10m]` |
| `power off --yes` | `/system shutdown confirm=yes` |
| `diag log list` | `/log files` |
| `diag log show <log> -n 50 -f --search w --severity error --json` | `/log print <log> lines=50 follow search=w severity=error json` |
| `diag log clear <log> --yes` | `/log clear <log> confirm=yes` |
| `diag firewall log -n 50 [-f\|--stream] --action block -s text` | `/firewall/log print lines=50 [follow\|stream] action=block search=text` |
| `diag firewall filters`, `stats --by action --limit 5000` | `/firewall/log filters`, `stats by=action scan=5000` |
| `diag traffic [--interface lan]` (one measurement), `diag traffic -f` | `/interface monitor-traffic once [interface=lan]`, `/interface monitor-traffic` |
| `diag traffic interfaces` | `/interface print` |
| `diag traffic top [-f] --interface wan -n 10` | `/tool torch [once] interface=wan lines=10` |
| `diag cpu`, `diag cpu -f` | `/system/resource monitor once`, `/system/resource monitor` |
| `diag activity -n 20 [-f --interval 2s]` | `/system/activity print lines=20 [follow interval=2s]` |
| `diag system` | `/system/resource print` |

Note the inversion of the monitors: `diag traffic`, `diag traffic top` and `diag cpu` measured once unless `-f` was
given, `monitor-traffic`, `torch` and `monitor` run until Ctrl-C unless `once` is given.

## Usage: GoLang library

    import (
      "fmt"

      opn_api "opnsense-cli/opnsense/api"
      opn_dnsmasq "opnsense-cli/opnsense/api/dnsmasq"
      opn_unbound "opnsense-cli/opnsense/api/unbound"
    )
     
    func createUnboundHostEntry() error {
        opnConnection, err := opn_api.ConfigureFromEnv()
        if err != nil {
            return fmt.Errorf("error getting OPNsense connection: %w", err)
        }
        unbound := opn_unbound.UnboundApi{OPNsense: opnConnection}

        var dnsHostEntry = opn_unbound.HostOverride{
            Host:   "test",
            Domain: "foo.tld",
            Ip:     "10.10.10.1",
        }

        if _, err := unbound.HostOverrideCreateOrUpdate(dnsHostEntry); err != nil {
            return err
        }
        return unbound.ServiceReconfigure()
    }

    func createDnsmasqHostEntry() error {
        opnConnection, err := opn_api.ConfigureFromEnv()
        if err != nil {
            return fmt.Errorf("error getting OPNsense connection: %w", err)
        }
        dnsmasq := opn_dnsmasq.DnsmasqApi{OPNsense: opnConnection}

        var host = opn_dnsmasq.Host{
            Host:   "test",
            Domain: "foo.lan",
            Ip:     "10.0.0.10,fd00::10",
            Hwaddr: "aa:bb:cc:dd:ee:ff",
        }

        // returns the uuid and whether an existing entry with the same FQDN was updated
        if _, _, err := dnsmasq.HostCreateOrUpdate(host); err != nil {
            return err
        }
        return dnsmasq.ServiceReconfigure()
    }

## Development

The easiest way is the devcontainer in `.devcontainer/` (e.g. VSCode "Reopen in Container"). It starts a Go container
plus an `opnsense-dev` container running OPNsense 26.7 (needs `/dev/kvm`). On start, `.devcontainer/wait-for-keys.sh`
waits for the API key OPNsense generates and writes it to `~/.opnsense-env` (`OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET`,
sourced by your shell) and `~/.vscopnsense-env` (`OPN_APIKEY` / `OPN_APISECRET`). The VSCode "Refresh Keys" task re-runs it.

    # run the cli against the dev instance
    set -a; . ~/.vscopnsense-env; set +a
    export OPN_URL=https://opnsense-dev OPN_NOSSLVERIFY=1
    go run . /unbound service status
    go run .              # the interactive shell

    # or use the "Launch Container" debug config in .vscode/launch.json

    # tests / vet
    make test
    make vet

    # integration tests of the library and the opn binary against a live OPNsense (one package per area below
    # integration/), they only touch records they created (with a random run prefix, swept at the end), create
    # them disabled where possible and never run dangerous commands (reboot, reset, revert, apply, firmware ...).
    # Uses OPN_URL / OPN_APIKEY / OPN_APISECRET, or the devcontainer keys with https://opnsense-dev, and they are
    # skipped when there are no credentials or the instance is unreachable
    make integration

    # building, binaries for linux, macos, windows (amd64 / arm64) end up in dist/
    make build
    make release VERSION=1.2.3

    # publishing a release: pushing a tag runs .github/workflows/release.yml, which tests, builds linux amd64/arm64
    # and macos arm64 with the tag as version and creates a GitHub release of the same name with the binaries
    git tag 1.2.3 && git push origin 1.2.3

The `http/` folder contains requests for the IntelliJ / VSCode REST clients to explore the API by hand.

## Contributions

If you like to add a new command implementing OPNsense API reference https://docs.opnsense.org/development/api.html#introduction - open a PR and iam happy to add it. Be bold. 
