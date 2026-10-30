package auth

import (
	"strings"

	coreapi "opnsense-cli/opnsense/api"
)

// CSV export / import of the users (api/auth/user/download and upload, the GUI's "Export as csv" / "Import csv" of
// System > Access > Users), see coreapi.DownloadCsv for the format.
//
// OPNsense 26.7 leaves out uid, scope, password, scrambled_password, otp_seed, authorizedkeys, comments and
// dashboard; the apikeys column is always empty (the field renders as ""), so the export holds no secrets. The
// import matches users by name and drops the same columns (a password can not be imported: new users get a random
// one); other unknown columns are ignored. A non-empty apikeys value REPLACES all API keys of the user by the given
// "key|crypted secret" lines. group_memberships are gids, the user is added to and removed from the groups
// accordingly. The import does not run "auth sync user": the system account (shell, SSH keys, lock state) of an
// imported user is updated on its next change through set_item or at boot

// UserCsvColumns are the columns of the user export of OPNsense 26.7, the columns the import understands
var UserCsvColumns = []string{"name", "disabled", "expires", "shell", "pwd_changed_at", "landing_page", "comment", "email",
	"apikeys", "priv", "language", "group_memberships", "descr"}

// UserCsvSecretColumns are the columns of a user CSV that hold secrets when they are not empty: OPNsense 26.7 exports
// only apikeys (always empty), the others are what an older or newer version or a hand made file could contain
var UserCsvSecretColumns = []string{"apikeys", "password", "otp_seed", "authorizedkeys"}

// UserExportCsv returns the users as CSV (';' separated with a header row), see above for what it holds
func (opn *AuthApi) UserExportCsv() ([]byte, error) {
	return opn.DownloadCsv(opn.endpoint("user", "download"))
}

// UserImportCsv uploads a user CSV: rows matching an existing user by name update it, the others add users
func (opn *AuthApi) UserImportCsv(content []byte, filename string) (coreapi.CsvImportResult, error) {
	return opn.UploadCsv(opn.endpoint("user", "upload"), content, filename)
}

// UserCsvSecrets returns the secret columns (UserCsvSecretColumns) that have a value in some row of a user CSV
func UserCsvSecrets(parsed coreapi.Csv) []string {
	var found []string
	for _, column := range UserCsvSecretColumns {
		var values, _ = parsed.Column(column)
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				found = append(found, column)
				break
			}
		}
	}
	return found
}
