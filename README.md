## WAT

Implementation of the OPNsense WebAPI to be used on the CLI or as a library - written in Golang

Developed and tested against OPNsense 26.7. It uses the current (snake_case) API endpoints, so older releases are not tested and may not work.
The Dnsmasq commands need the Dnsmasq MVC API, which was introduced with OPNsense 25.1.

Covered: Unbound host overrides, Dnsmasq hosts / static DHCP reservations, domain overrides and leases, the
services, cron jobs, tunables, logging (incl. remote destinations), configuration backups, factory defaults, the
setup wizard settings, reboot / shutdown, and diagnostics: log files and the firewall log (tail and follow),
interface counters and throughput, top talkers, system resources and activity.

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

`opn -v ...` logs every API request (method, URL, status, duration) to stderr, credentials are never logged.
`opn -h` and `opn <path> ?` show the help. Errors are printed as `error: ...` on stderr with exit code 1
(2 for an unknown option).

### Menus

| menu | commands | key arguments, items |
|---|---|---|
| `/unbound/host-override` | `print show add set remove enable disable` | `host= domain= rr=A\|AAAA\|MX\|TXT ip= mx= mx-priority= txtdata= ttl= ptr= description= disabled`; items: `host.domain`, `host.domain/RR` when the FQDN has several records |
| `/unbound/service` | `status restart reconfigure` | |
| `/dnsmasq/host` | `print show add set remove` | `host= domain= ip= cname= alias= hwaddr= client-id= lease-time= local ignore description= comments=` (lists comma separated); items: `host.domain` or the hostname |
| `/dnsmasq/domain` | `print show add set remove` | `domain= ip= port= source-ip= sequence= description=`; items: the domain |
| `/dnsmasq/lease` | `print` | |
| `/dnsmasq/service` | `status start stop restart reconfigure` | |
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
| `/log` | `print files clear` | `print [log=]system lines= follow search= severity=`; logs: a scope like `system`, `configd`, `dnsmasq` or `<module>/<scope>`, see `files` |
| `/firewall/log` | `print filters stats` | `print lines= follow stream interval= action= interface= dir= proto= src= dst= port= search= scan=`, `stats by= scan=` |
| `/interface` | `print monitor-traffic` | `print`: counters since boot; `monitor-traffic interface= interval= once` |
| `/tool` | `torch` | top talkers: `interface= lines= interval= once` |
| `/` | `import` | `import file` |

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

```
opn /unbound host-override add host=foo domain=bar.tld ip=10.10.10.1    # not resolvable yet
opn /unbound service reconfigure                                        # now it is
```

### Dangerous commands

`/system reboot`, `/system shutdown`, `/system/defaults reset`, `/system/backup revert`, `/system/backup remove` and
`/log clear` ask `[y/N]` in the shell. In one-shot calls and scripts there is nobody to ask: they refuse to run
unless `confirm=yes` is given.

    opn /system reboot confirm=yes wait timeout=10m    # wait polls until the firewall is back up

### Output

- `print` shows a table with a `#` column, `print detail` all fields of every item, `print json` one raw API
  object per line (ndjson, e.g. for `jq`), `search=` filters
- `show` prints one item as `name: value` lines
- data goes to stdout, messages and hints (`replaced the existing host ...`, `already disabled`) to stderr
- streaming commands (`/log print follow`, `/firewall/log print follow|stream`, `/interface monitor-traffic`,
  `/system/resource monitor`, `/system/activity print follow`, `/tool torch`) run until Ctrl-C, reconnect dropped
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

    # integration tests of the library and the opn binary against a live OPNsense (integration/, integration/system/),
    # they only touch records they created and never run dangerous commands (reboot, reset, revert, log clear).
    # Uses OPN_URL / OPN_APIKEY / OPN_APISECRET, or the devcontainer keys with https://opnsense-dev, and they are
    # skipped when there are no credentials or the instance is unreachable
    make integration

    # building, binaries for linux, macos, windows (amd64 / arm64) end up in dist/
    make build
    make release VERSION=1.2.3

The `http/` folder contains requests for the IntelliJ / VSCode REST clients to explore the API by hand.

## Contributions

If you like to add a new command implementing OPNsense API reference https://docs.opnsense.org/development/api.html#introduction - open a PR and iam happy to add it. Be bold. 
