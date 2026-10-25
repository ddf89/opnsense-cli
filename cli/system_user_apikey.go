package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"opnsense-cli/opnsense/api/auth"
	"os"
	"strings"
)

// /system/user/api-key: the API keys of the users (api/auth/user/*_api_key). OPNsense stores only a hash of the
// secret: add prints the secret once (or writes it to a file), it can not be read again. The key opn itself uses
// can not be removed through opn

const systemUserApiKeyItemHelp = "the # of print or the key (written item=<key> when the key ends with =)"

func init() {
	var menu = Root.Menu("system/user/api-key")
	menu.Help = "API keys of the users"
	menu.Add(
		&Command{Name: "print", Help: "list the API keys (without secrets)",
			Long: `IN-USE marks the key opn uses for this connection.`,
			Args: []Arg{
				{Name: "user", Help: "only the keys of this user", Complete: systemUserItemNames},
				{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them"},
			}, Run: systemUserApiKeyPrint},
		&Command{Name: "add", Help: "create an API key for a user, prints the key and its secret once",
			Long: `Prints key=<key> and secret=<secret> (the format of the apikey.txt file of the GUI). OPNsense keeps only a
hash of the secret, it is shown this one time. With file= both are written to that file (mode 0600) instead and
only the key is printed; an existing file is only replaced with overwrite.

The key has all privileges of the user.`,
			Args: []Arg{
				{Name: "user", Help: "the name or uuid of the user", Required: true, Positional: true, Complete: systemUserItemNames},
				{Name: "file", Help: "write the key and secret to this file instead of printing the secret"},
				{Name: "overwrite", Type: Bool, Help: "replace an existing file"},
			}, Check: systemUserApiKeyCheckAdd, Run: systemUserApiKeyAdd},
		&Command{Name: "remove", Help: "delete an API key",
			Long:    `opn refuses to remove the key it uses for this connection.`,
			Confirm: "This deletes the API key, programs using it lose access.",
			Args: []Arg{{Name: "item", Help: systemUserApiKeyItemHelp, Positional: true, Required: true,
				Complete: systemUserApiKeyItemNames}},
			Run: systemUserApiKeyRemove},
	)
}

func systemUserApiKeyCheckAdd(args *Args) error {
	if args.Has("overwrite") && !args.Has("file") {
		return errors.New("overwrite only applies to file=")
	}
	if args.Has("file") && args.String("file") == "" {
		return errors.New("file= needs a file name")
	}
	return nil
}

func systemUserApiKeyId(key auth.ApiKey) string {
	return key.Id
}

func systemUserApiKeyNames(key auth.ApiKey) []string {
	return []string{key.Key}
}

func systemUserApiKeyItemNames(c *Context) []string {
	var api, err = systemUserApi(c)
	if err != nil {
		return nil
	}
	var keys, listErr = api.ApiKeyList()
	if listErr != nil {
		return nil
	}
	var names = make([]string, 0, len(keys))
	for _, key := range keys {
		names = append(names, key.Key)
	}
	return names
}

// systemUserApiKeys lists the keys, only those of the user with this name (case-insensitive) when not ""
func systemUserApiKeys(api *auth.AuthApi, user string) ([]auth.ApiKey, error) {
	var keys, err = api.ApiKeyList()
	if err != nil || user == "" {
		return keys, err
	}
	var result = make([]auth.ApiKey, 0, len(keys))
	for _, key := range keys {
		if strings.EqualFold(key.Username, user) {
			result = append(result, key)
		}
	}
	return result, nil
}

func systemUserApiKeyPrint(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var keys, listErr = systemUserApiKeys(api, args.String("user"))
	if listErr != nil {
		return listErr
	}
	if args.Bool("json") {
		for _, key := range keys {
			if err := c.JSON(key); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, len(keys))
	var ids = make([]string, len(keys))
	for i, key := range keys {
		var inUse = ""
		if key.Key == api.ApiKey {
			inUse = "yes"
		}
		rows[i] = []string{key.Username, key.Key, inUse}
		ids[i] = key.Id
	}
	c.Items([]string{"USER", "KEY", "IN-USE"}, rows, ids)
	return nil
}

func systemUserApiKeyAdd(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var file = args.String("file")
	if file != "" && !args.Bool("overwrite") {
		if _, statErr := os.Stat(file); statErr == nil {
			return fmt.Errorf("%s exists already, add overwrite to replace it", file)
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return statErr
		}
	}
	var user, selectErr = systemUserSelect(c, api, args.String("user"))
	if selectErr != nil {
		return selectErr
	}
	var created, createErr = api.ApiKeyCreate(user.Name)
	if createErr != nil {
		return createErr
	}
	var content = fmt.Sprintf("key=%s\nsecret=%s\n", created.Key, created.Secret)
	if file == "" {
		c.Infof("the secret is shown only this once, store it now")
		c.Printf("%s", content)
		return nil
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		return fmt.Errorf("the key %s was created, but writing %s failed (remove the key, its secret is lost): %w",
			created.Key, file, err)
	}
	// WriteFile keeps the mode of an existing file
	if err := os.Chmod(file, 0o600); err != nil {
		return err
	}
	c.Infof("wrote the key and its secret to %s", file)
	c.Println("key=" + created.Key)
	return nil
}

func systemUserApiKeyRemove(c *Context, args *Args) error {
	var api, err = systemUserApi(c)
	if err != nil {
		return err
	}
	var keys, listErr = api.ApiKeyList()
	if listErr != nil {
		return listErr
	}
	var key, selectErr = Select(c, args.String("item"), keys, systemUserApiKeyId, systemUserApiKeyNames)
	if selectErr != nil {
		return selectErr
	}
	if key.Key == api.ApiKey {
		return fmt.Errorf("refusing to remove the API key opn uses for this connection (of user %q)", key.Username)
	}
	return api.ApiKeyRemove(key.Id)
}
