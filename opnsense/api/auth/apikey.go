package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ApiKey is an API key of a user (api/auth/user/search_api_key). Only the key is listed, OPNsense stores a hash
// of the secret and shows the secret only once, when the key is created
type ApiKey struct {
	// Id identifies the key in del_api_key, it is the base64 encoded Key
	Id       string `json:"id"`
	Key      string `json:"key"`
	Username string `json:"username"`
}

// NewApiKey is a created API key with its secret, which can not be read again
type NewApiKey struct {
	Key    string
	Secret string
	// Hostname is the FQDN of the firewall
	Hostname string
}

// ApiKeyList returns the API keys of all users (search_api_key ignores ?searchPhrase=, filter the result)
func (opn *AuthApi) ApiKeyList() ([]ApiKey, error) {
	var keys, err = searchAll[ApiKey](opn, opn.endpoint("user", "search_api_key"))
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].Id == "" {
			keys[i].Id = ApiKeyId(keys[i].Key)
		}
	}
	return keys, nil
}

// ApiKeyId returns the id of a key for del_api_key: the base64 encoded key
func ApiKeyId(key string) string {
	return base64.StdEncoding.EncodeToString([]byte(key))
}

// ApiKeyCreate creates a new API key for the user with this name and returns it with its secret. The secret is
// only available now. Returns *NotFoundError for an unknown user
func (opn *AuthApi) ApiKeyCreate(username string) (NewApiKey, error) {
	if _, err := opn.UserGetByName(username); err != nil {
		return NewApiKey{}, err
	}
	var answer struct {
		Result   string `json:"result"`
		Hostname string `json:"hostname"`
		Key      string `json:"key"`
		Secret   string `json:"secret"`
	}
	var endpoint = opn.endpoint("user", "add_api_key") + "/" + escapePathSegment(username)
	// a GET does nothing and answers {"result":"failed"}
	if err := opn.DoJSON("POST", endpoint, nil, &answer); err != nil {
		return NewApiKey{}, err
	}
	if answer.Result != "ok" || answer.Key == "" || answer.Secret == "" {
		return NewApiKey{}, fmt.Errorf("creating an API key for %q failed: result %q", username, answer.Result)
	}
	return NewApiKey{Key: answer.Key, Secret: answer.Secret, Hostname: answer.Hostname}, nil
}

// ApiKeyRemove deletes the API key with this id (see ApiKey.Id). Returns *NotFoundError for an unknown key
func (opn *AuthApi) ApiKeyRemove(id string) error {
	if id == "" || strings.ContainsAny(id, "/?#%") {
		return fmt.Errorf("cannot remove an API key by id %q", id)
	}
	if _, err := base64.StdEncoding.DecodeString(id); err != nil {
		return errors.New("an API key id is the base64 encoded key")
	}
	var endpoint = opn.endpoint("user", "del_api_key") + "/" + id
	var _, err = opn.mutate(endpoint, "API key "+id, nil)
	return err
}

// escapePathSegment escapes a user name for an URL path (names may contain @)
func escapePathSegment(segment string) string {
	return strings.NewReplacer("%", "%25", "/", "%2F", "?", "%3F", "#", "%23", " ", "%20").Replace(segment)
}
