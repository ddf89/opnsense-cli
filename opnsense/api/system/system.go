package system

import (
	coreapi "opnsense-cli/opnsense/api"
)

// SystemApi wraps the OPNsense APIs behind System > Settings and System > Configuration
// (api/cron, api/core/tunables, api/syslog, api/core/backup, api/core/defaults, api/core/initial_setup)
//
//goland:noinspection GoNameStartsWithPackageName
type SystemApi struct {
	*coreapi.OPNsense
}
