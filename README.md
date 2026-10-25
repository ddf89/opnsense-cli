## WAT

Implementation of the OPNsense WebAPI to be used on the CLI or as a library - written in Golang

Developed and tested against OPNsense 26.7. It uses the current (snake_case) API endpoints, so older releases are not tested and may not work.
The Dnsmasq commands need the Dnsmasq MVC API, which was introduced with OPNsense 25.1.

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

## Commands included

Just run 

    opn 

to see a full list. Currently implemented

- managing host overrides for unbound (CRUD + list) and the unbound service
- managing host overrides / static DHCP reservations and domain overrides for dnsmasq (CRUD + list)
- the dnsmasq service and listing its DHCP leases
- system: cron jobs, tunables, logging (incl. remote destinations), configuration backups, the setup wizard settings and factory defaults
- power: reboot and power off
- diagnostics: tail / follow log files and the firewall log, traffic, cpu, activity and a system summary


## Usage: cli

    opn --help
    # -v / --verbose logs every API request (method, URL, status, duration) to stderr, credentials are never logged
    opn -v unbound service status

    # unbound host DNS entries (A, AAAA, MX, TXT)
    # create replaces an existing entry with the same host, domain and rr: flags not given are reset to their defaults
    opn unbound hostoverride create --host foo --domain bar.tld --ip 10.10.10.1 [--rr A|AAAA|MX|TXT] [--ttl 300] [--mx mail.bar.tld --mxprio 10] [--txtdata "..."] [--addptr 0|1] [--description ..] [--enabled 0|1]
    # update only changes the given flags, it fails if there is no matching entry
    opn unbound hostoverride update (--uuid X | --host foo --domain bar.tld [--rr A]) --ip 10.10.10.2
    opn unbound hostoverride show (--uuid X | --host foo --domain bar.tld [--rr A])
    opn unbound hostoverride rm (--uuid X | --host foo --domain bar.tld [--rr A])
    opn unbound hostoverride list [--search phrase]

    # unbound service
    opn unbound service restart
    opn unbound service reconfigure
    opn unbound service status

    # dnsmasq host overrides / static DHCP reservations
    # create replaces an existing entry with the same host and domain: fields without a flag are cleared
    opn dnsmasq host create --host foo [--domain bar.lan] [--ip 10.0.0.1 --ip fd00::1] [--cname a.bar.lan] [--alias b.bar.lan] [--hwaddr aa:bb:cc:dd:ee:ff] [--client-id ..] [--lease-time ..] [--local] [--ignore] [--description ..] [--comments ..]
    # update only changes the given flags (--cname "" clears a field), it fails if there is no matching entry
    opn dnsmasq host update (--uuid X | --host foo [--domain bar.lan]) [--new-host ..] [--new-domain ..] --ip 10.0.0.2
    opn dnsmasq host show (--uuid X | --host foo [--domain bar.lan])
    opn dnsmasq host rm (--uuid X | --host foo [--domain bar.lan])
    opn dnsmasq host list [--search phrase]

    # dnsmasq domain overrides (forward a domain to another DNS server, run create once per server)
    # create replaces an existing entry with the same domain and ip: flags not given are reset to their defaults
    opn dnsmasq domain create --domain corp.lan [--ip 10.0.0.53] [--port 5353] [--srcip ..] [--sequence 1] [--description ..]
    # update only changes the given flags, --domain / --ip select the entry
    opn dnsmasq domain update (--uuid X | --domain corp.lan [--ip ..]) [--new-domain ..] [--new-ip 10.0.0.54] [--port ..]
    opn dnsmasq domain show (--uuid X | --domain corp.lan [--ip ..])
    opn dnsmasq domain rm (--uuid X | --domain corp.lan [--ip ..])
    opn dnsmasq domain list [--search phrase]

    # update / show / rm fail with "not found" when nothing matches (also for an unknown --uuid),
    # if a lookup by name matches several entries, select one with --uuid

    # dnsmasq service and DHCP leases
    opn dnsmasq service status|start|stop|restart|reconfigure
    opn dnsmasq leases list [--search phrase]

    # system: cron jobs, selected by --uuid or --description (must be unique)
    opn system cron list [--search phrase]
    opn system cron commands
    opn system cron create --command "firmware changelog cron" [--parameters ..] [--minutes 0] [--hours 0] [--days *] [--months *] [--weekdays *] [--who root] [--description ..] [--enabled 0|1]
    opn system cron update (--uuid X | --description ..) [--new-description ..] [field flags...]   (only the given flags are changed)
    opn system cron show|rm|enable|disable (--uuid X | --description ..)
    opn system cron apply

    # system: tunables (sysctl / loader.conf), selected by --name or --uuid
    opn system tunable list [--search phrase] [--changed]
    opn system tunable set --name kern.ipc.maxsockbuf --value 16777216 [--description ..]   (--value "" for the built-in default)
    opn system tunable show|rm (--name kern.ipc.maxsockbuf | --uuid X)
    opn system tunable apply

    # system: logging
    opn system logging show
    opn system logging set [--enabled[=false]] [--loglocal[=false]] [--maxpreserve 31] [--maxfilesize ..]
    opn system logging stats [--search phrase]
    opn system logging destination create --hostname 10.0.0.5 [--transport udp4|tcp4|udp6|tcp6|tls4|tls6] [--port 514] [--program filterlog,unbound] [--level info,err] [--facility ..] [--certificate refid] [--rfc5424] [--enabled=false] [--description ..]
    opn system logging destination update (--uuid X | --description ..) [--new-description ..] [field flags...]
    opn system logging destination show|rm|enable|disable (--uuid X | --description ..)
    opn system logging destination list [--search phrase]
    opn system logging service status|restart|reconfigure

    # system: configuration backups (provider "this" is the local history)
    opn system backup providers
    opn system backup list [-p provider]
    opn system backup download [--id current|ID] [-o file|-] [-f] [-p provider]
    opn system backup diff --from ID [--to current|ID] [-p provider]
    opn system backup revert --id ID --yes    (replaces the whole running configuration, incl. users and API keys)
    opn system backup rm --id ID --yes

    # system: setup wizard settings (read-only, passwords are never shown) and factory defaults
    opn system wizard show
    opn system defaults show
    opn system defaults reset --yes   (wipes the WHOLE configuration incl. API keys and reboots, there is no undo)

    # power menu, both interrupt all routing / VPN / services
    opn power reboot --yes [--wait [--timeout 10m]]   (--wait polls until the firewall is back up)
    opn power off --yes                               (does not come back by itself, needs console access to power on)

**HINT**: Changes are only saved to the configuration, you have to run `reconfigure` every time you change an entry on `unbound` or `dnsmasq` to apply them, so e.g.

    # this will yet not show up when you run a DNS query
    opn unbound hostoverride create --host foo --domain bar.tld --ip 10.10.10.1
    # after that, it will
    opn unbound service reconfigure

    # same for dnsmasq
    opn dnsmasq host create --host foo --domain bar.lan --ip 10.0.0.1
    opn dnsmasq service reconfigure

The same goes for the system settings: run `opn system cron apply`, `opn system tunable apply` or
`opn system logging service reconfigure` after changing cron jobs, tunables or logging.

## Usage: diagnostics / log streaming

All `opn diag` commands are read-only (except `log clear`). Without `-f/--follow` they print the newest lines or one
measurement and exit (like `tail`), with `--follow` they keep streaming until Ctrl-C. `--json` prints one JSON object
per line (ndjson) for scripting, e.g. `opn diag firewall log -f --json | jq ...`.

    # log files (System > Log Files and the services' log pages), named like system, configd or <module>/<scope>
    # plain names must be in "log list", logs without a menu entry can be given as <module>/<scope>
    opn diag log list
    opn diag log show <name> [-n 50] [-f] [--search "words"] [--severity error,warning] [--json]
    opn diag log clear <name> --yes   (empties the log for everyone)

    # firewall live log, filters are combined with AND
    opn diag firewall log [-n 50] [-f [--interval 1s] | --stream] [--action pass|block|..] [--interface lan] [--dir in|out]
                          [--proto tcp] [--src 10.0.0.0/8] [--dst ..] [--port 443] [-s text] [--scan 1000] [--json]
    opn diag firewall filters
    opn diag firewall stats [--by interface|action|dir|protoname|src|dst|srcport|dstport|label|rid] [--limit 5000]

    # traffic, cpu, activity and system summary
    opn diag traffic [-f] [--interface lan,wan] [--interval 1] [--json]   (bits/s and packets/s per interface)
    opn diag traffic interfaces [--json]                                (counters since boot)
    opn diag traffic top [--interface wan] [-n 10] [-f [--interval 1s]] [--json]   (top talkers)
    opn diag cpu [-f] [--json]
    opn diag activity [-n 20] [-f [--interval 2s]] [--json]
    opn diag system [--json]

`diag log show -f` reconnects a dropped stream and prints the lines logged in the meantime once.
`diag firewall log -f` polls the log and shows every record, `--stream` uses the OPNsense live stream instead,
which is faster but throttled and lossy.

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
    go run . unbound service status

    # or use the "Launch Container" debug config in .vscode/launch.json

    # tests / vet
    make test
    make vet

    # integration tests against a live OPNsense (integration/, integration/system/), they only touch records they
    # created. Uses OPN_URL / OPN_APIKEY / OPN_APISECRET, or the devcontainer keys with https://opnsense-dev,
    # and are skipped when there are no credentials or the instance is unreachable
    make integration

    # building, binaries for linux, macos, windows (amd64 / arm64) end up in dist/
    make build
    make release VERSION=1.2.3

The `http/` folder contains requests for the IntelliJ / VSCode REST clients to explore the API by hand.

## Contributions

If you like to add a new command implementing OPNsense API reference https://docs.opnsense.org/development/api.html#introduction - open a PR and iam happy to add it. Be bold. 
