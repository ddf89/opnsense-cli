package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"opnsense-cli/opnsense/api/auth"

	coreapi "opnsense-cli/opnsense/api"
)

// /system/user export and import: the CSV format of the GUI's "Export as csv" / "Import csv" of System > Access >
// Users (api/auth/user/download, upload), on the shared CsvTransfer. The import is checked against the protection
// of root and the API key's user (see system_user.go) and refuses to grant "All pages" before anything is sent

const systemUserExportHelp = `The export holds no secrets: OPNsense leaves out passwords and their hashes, OTP seeds, SSH keys, uids and
dashboards, and its apikeys column is always empty (should an export contain secrets anyway, export - warns on
stderr). It does hold personal data: names, full names, e-mail addresses, comments, the time of the last password
change, directly granted privileges (priv) and group memberships (group_memberships, as gids). The file is written
with mode 0600.`

const systemUserImportHelp = `A password can not be imported: a new user gets a random password nobody knows (set one with the password
command). API keys are only managed with api-key: opn refuses values in the apikeys column (OPNsense would replace
the user's keys with them). Group memberships are gids, a user is added to and taken out of groups accordingly.
opn refuses the whole file, before anything is sent, when a row is for root or for the user owning the API key opn
uses (remove these rows from a full export first), or grants "All pages" (page-all in priv, or a group with
page-all like admins in group_memberships): manage administrators with set. OPNsense updates the system account
(shell, lock state) of an imported user only on its next change or at boot.`

// systemUserTransferWhat names the users in the messages of export and import
const systemUserTransferWhat = "users"

var systemUserTransfer = CsvTransfer{
	What:    systemUserTransferWhat,
	Key:     "name",
	Export:  systemUserExport,
	Import:  systemUserImport,
	Columns: systemUserCsvColumns,
}

func init() {
	var menu = Root.Menu("system/user")
	var export = systemUserTransfer.ExportCommand()
	export.Run = systemUserExportRun
	export.Long += "\n" + systemUserExportHelp
	var importCommand = systemUserTransfer.ImportCommand()
	importCommand.Long += "\n" + systemUserImportHelp
	// the protection is checked before the question: ConfirmIf runs it and asks the same question
	var question = importCommand.Confirm
	importCommand.Confirm = ""
	importCommand.ConfirmIf = func(c *Context, args *Args) (string, error) {
		var content, _, err = transferRead(args.String("file"), systemUserTransferWhat)
		if err != nil {
			return "", err
		}
		if err := systemUserImportCheck(c, content); err != nil {
			return "", err
		}
		return question, nil
	}
	importCommand.ConfirmHelp = "Asks for confirmation once the file passed the checks: " + question
	menu.Add(export, importCommand)
}

func systemUserExport(c *Context) ([]byte, error) {
	var api, err = systemUserApi(c)
	if err != nil {
		return nil, err
	}
	return api.UserExportCsv()
}

// systemUserExportRun is CsvTransfer's export with a warning when an export to stdout holds secrets
func systemUserExportRun(c *Context, args *Args) error {
	var content, err = systemUserExport(c)
	if err != nil {
		return err
	}
	var file = args.String("file")
	if file == "-" && len(content) > 0 {
		var secrets []string
		if parsed, parseErr := coreapi.ParseCsv(content, systemUserTransferWhat); parseErr == nil {
			secrets = auth.UserCsvSecrets(parsed)
		} else {
			secrets = []string{"unknown (the export could not be parsed)"}
		}
		if len(secrets) > 0 {
			c.Infof("warning: this export holds secrets (columns %s), keep the output private", strings.Join(secrets, ", "))
		}
	}
	return transferSave(c, content, file, args.Bool("overwrite"), systemUserTransferWhat)
}

func systemUserImport(c *Context, content []byte, filename string) (coreapi.CsvImportResult, error) {
	if err := systemUserImportCheck(c, content); err != nil {
		return coreapi.CsvImportResult{}, err
	}
	var api, err = systemUserApi(c)
	if err != nil {
		return coreapi.CsvImportResult{}, err
	}
	return api.UserImportCsv(content, filename)
}

// systemUserCsvColumns returns the columns of the deployed version's export (falling back to those of 26.7)
func systemUserCsvColumns(c *Context) ([]string, error) {
	var content, err = systemUserExport(c)
	if err != nil {
		return nil, err
	}
	if parsed, parseErr := coreapi.ParseCsv(content, systemUserTransferWhat); parseErr == nil && slices.Contains(parsed.Header, "name") {
		return parsed.Header, nil
	}
	return auth.UserCsvColumns, nil
}

// systemUserImportCheck refuses an import file with rows for protected users (root, the API key's user), rows
// granting "All pages" directly or through a group, and API keys. Every refused row is listed
func systemUserImportCheck(c *Context, content []byte) error {
	var parsed, err = coreapi.ParseCsv(content, systemUserTransferWhat)
	if err != nil {
		return err
	}
	var names, hasNames = parsed.Column("name")
	if !hasNames {
		return errors.New("the file has no name column: the import matches users by name")
	}
	api, err := systemUserApi(c)
	if err != nil {
		return err
	}
	owner, err := systemUserApiKeyOwner(c, api)
	if err != nil {
		return err
	}
	var adminGroups []auth.Group // the groups granting page-all, admins in any case
	var memberships, hasMemberships = parsed.Column("group_memberships")
	if hasMemberships && slices.ContainsFunc(memberships, func(value string) bool { return strings.TrimSpace(value) != "" }) {
		var groups, groupsErr = api.GroupList()
		if groupsErr != nil {
			return groupsErr
		}
		for _, group := range groups {
			if slices.Contains(group.Privileges, systemUserAdminPrivilege) || group.Gid == "1999" || group.Name == "admins" {
				adminGroups = append(adminGroups, group)
			}
		}
	}
	var privileges, _ = parsed.Column("priv")
	var apiKeys, _ = parsed.Column("apikeys")

	var problems []string
	for row, name := range names {
		var refuse = func(format string, args ...any) {
			problems = append(problems, fmt.Sprintf("  line %d (%s): %s", row+2, name, fmt.Sprintf(format, args...)))
		}
		var trimmed = strings.TrimSpace(name)
		switch {
		case strings.EqualFold(trimmed, "root"):
			refuse("root is protected by opn")
		case owner != "" && strings.EqualFold(trimmed, owner):
			refuse("the user of the API key opn uses is protected by opn")
		}
		if slices.Contains(systemUserTransferList(privileges[row]), systemUserAdminPrivilege) {
			refuse("priv grants %s (All pages)", systemUserAdminPrivilege)
		}
		for _, gid := range systemUserTransferList(memberships[row]) {
			for _, group := range adminGroups {
				if gid == group.Gid || gid == group.Name {
					refuse("group_memberships adds group %s (gid %s), it grants %s (All pages)", group.Name, group.Gid, systemUserAdminPrivilege)
				}
			}
		}
		if strings.TrimSpace(apiKeys[row]) != "" {
			refuse("apikeys is not empty: it would replace the API keys of the user, manage them with api-key")
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("refusing to import, nothing was sent:\n%s", strings.Join(problems, "\n"))
	}
	return nil
}

// systemUserAdminPrivilege is "All pages", what makes a user an administrator
const systemUserAdminPrivilege = "page-all"

// systemUserTransferList splits a comma separated CSV value
func systemUserTransferList(value string) []string {
	var result []string
	for _, element := range strings.Split(value, ",") {
		if element = strings.TrimSpace(element); element != "" {
			result = append(result, element)
		}
	}
	return result
}
