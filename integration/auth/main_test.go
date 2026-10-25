//go:build integration

// Package integrationauth runs the System > Access library (opnsense/api/auth), host discovery
// (opnsense/api/hostdiscovery), the NTP status (opnsense/api/ntpd) and the opn menus /system/user, /system/group,
// /system/privilege, /interface/host-discovery and /system/ntp against a live OPNsense (26.7) instance.
//
//	go test -tags integration ./integration/auth/... -count=1 -v
//
// Configuration (first match wins):
//   - OPN_URL / OPN_APIKEY / OPN_APISECRET / OPN_NOSSLVERIFY, like the CLI
//   - OPN_ENV_FILE: a file setting these variables (KEY=value lines, "export " allowed, like ~/.opnsense-dev2-env)
//   - OPNSENSE_API_KEY / OPNSENSE_API_SECRET (devcontainer, see ~/.opnsense-env) with https://opnsense-dev and no
//     TLS verification
//
// Every test is skipped when there are no credentials or the instance is unreachable.
//
// Safety (the instance is shared, and a mistake here can lock everybody out): users and groups are only created
// with the name prefix a4au-<random run id>, test users get a random password and no shell. root, the user of the
// API key in use, the admins group, the existing API keys and the privileges of existing users and groups are
// never changed: TestMain records them first and fails the run if they differ at the end. The protection of root
// and admins in the CLI is tested with fakes only (except where OPNsense refuses as well). Host discovery is never
// reconfigured or started (hostwatch would sniff the interfaces), its settings are restored exactly. TestMain
// finally sweeps (only) users and groups carrying this run's prefix and fails the run if it found any.
package integrationauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"

	api "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/auth"
)

const (
	defaultUrl = "https://opnsense-dev"
	basePrefix = "a4au-"
)

var (
	// skipReason is set by TestMain when the live instance can not be used, every test skips with it
	skipReason string
	// runPrefix is the name prefix of every user and group this run creates, e.g. a4au-1a2b3c4d
	runPrefix string
	// opnBinary is the CLI built once by TestMain, opnBuildErr is set when that failed
	opnBinary   string
	opnBuildErr error
)

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	var random = make([]byte, 4)
	_, _ = rand.Read(random)
	runPrefix = basePrefix + hex.EncodeToString(random)

	skipReason = configureEnv()
	if skipReason == "" {
		skipReason = probe()
	}
	if skipReason != "" {
		fmt.Fprintf(os.Stderr, "integration/auth: skipping all tests: %s\n", skipReason)
		return m.Run()
	}
	fmt.Fprintf(os.Stderr, "integration/auth: using %s, users and groups are named %s-...\n", os.Getenv("OPN_URL"), runPrefix)

	var before, snapshotErr = protectedSnapshot()
	if snapshotErr != nil {
		fmt.Fprintf(os.Stderr, "integration/auth: recording the protected users and groups failed: %v\n", snapshotErr)
		return 1
	}

	var tmpDir, err = os.MkdirTemp("", "opn-integration-auth-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration/auth: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	opnBinary, opnBuildErr = buildOpn(tmpDir)

	var code = m.Run()

	if leftovers := sweep(); len(leftovers) > 0 {
		fmt.Fprintf(os.Stderr, "integration/auth: the final sweep removed records the tests did not clean up: %s\n",
			strings.Join(leftovers, ", "))
		if code == 0 {
			code = 1
		}
	}
	var after, afterErr = protectedSnapshot()
	if afterErr != nil {
		fmt.Fprintf(os.Stderr, "integration/auth: checking the existing users and groups failed: %v\n", afterErr)
		code = 1
	} else if changes := after.changedSince(before); len(changes) > 0 {
		fmt.Fprintf(os.Stderr, "integration/auth: EXISTING USERS, GROUPS, API KEYS OR PRIVILEGES CHANGED:\n  %s\n",
			strings.Join(changes, "\n  "))
		code = 1
	}
	return code
}

// configureEnv maps the devcontainer variables to the OPN_* variables the library and the CLI read
func configureEnv() string {
	if file := os.Getenv("OPN_ENV_FILE"); file != "" {
		if err := godotenv.Load(file); err != nil {
			return fmt.Sprintf("reading OPN_ENV_FILE: %v", err)
		}
	}
	var fallback = func(name string, value string) {
		if os.Getenv(name) == "" && value != "" {
			_ = os.Setenv(name, value)
		}
	}

	var usingDefaultUrl = os.Getenv("OPN_URL") == ""
	fallback("OPN_APIKEY", os.Getenv("OPNSENSE_API_KEY"))
	fallback("OPN_APISECRET", os.Getenv("OPNSENSE_API_SECRET"))
	fallback("OPN_URL", defaultUrl)
	if usingDefaultUrl {
		fallback("OPN_NOSSLVERIFY", "1") // the devcontainer instance uses a self-signed certificate
	}

	if os.Getenv("OPN_APIKEY") == "" || os.Getenv("OPN_APISECRET") == "" {
		return "no credentials, set OPN_URL / OPN_APIKEY / OPN_APISECRET (or OPN_ENV_FILE, OPNSENSE_API_KEY / OPNSENSE_API_SECRET)"
	}
	if parsed, err := url.Parse(os.Getenv("OPN_URL")); err != nil || parsed.Hostname() == "" {
		return fmt.Sprintf("invalid OPN_URL %q", os.Getenv("OPN_URL"))
	}
	return ""
}

// probe checks quickly that the instance answers authenticated API calls of the auth module
func probe() string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return err.Error()
	}

	var host = core.BaseUrl.Host
	if core.BaseUrl.Port() == "" {
		host = net.JoinHostPort(core.BaseUrl.Hostname(), map[bool]string{true: "443", false: "80"}[core.BaseUrl.Scheme == "https"])
	}
	var conn, dialErr = net.DialTimeout("tcp", host, 5*time.Second)
	if dialErr != nil {
		return fmt.Sprintf("%s is unreachable: %v", host, dialErr)
	}
	_ = conn.Close()

	if _, err := api.Search[map[string]any](core, core.EndpointForPluginControllerMethod("auth", "group", "search"), ""); err != nil {
		return fmt.Sprintf("auth probe failed: %v", err)
	}
	return ""
}

func buildOpn(dir string) (string, error) {
	var binary = filepath.Join(dir, "opn")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	var build = exec.Command("go", "build", "-o", binary, ".")
	build.Dir = filepath.Join("..", "..") // module root
	if output, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %v\n%s", err, output)
	}
	return binary, nil
}

// --- protected state and sweep, with raw API access (deliberately not the library under test)

type rawUser struct {
	Uuid             string `json:"uuid"`
	Uid              string `json:"uid"`
	Name             string `json:"name"`
	Disabled         string `json:"disabled"`
	Expires          string `json:"expires"`
	Priv             string `json:"priv"`
	GroupMemberships string `json:"group_memberships"`
	Password         string `json:"password"`
}

type rawGroup struct {
	Uuid   string `json:"uuid"`
	Gid    string `json:"gid"`
	Name   string `json:"name"`
	Priv   string `json:"priv"`
	Member string `json:"member"`
}

type rawApiKey struct {
	Username string `json:"username"`
	Key      string `json:"key"`
}

type rawPriv struct {
	Id     string   `json:"id"`
	Users  []string `json:"users"`
	Groups []string `json:"groups"`
}

// snapshot is the state this suite must never change, keyed by user / group / API key / privilege, rendered as
// text (secrets only as fingerprints). Users, groups and keys of this run are left out
type snapshot map[string]string

// protectedSnapshot records all users and groups not created by this run (with a fingerprint of the password
// hash, so a changed password shows), all API keys and every privilege's holders outside this run
func protectedSnapshot() (snapshot, error) {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil, err
	}
	var users, usersErr = api.Search[rawUser](core, core.EndpointForModule("auth/user/search"), "")
	if usersErr != nil {
		return nil, usersErr
	}
	var groups, groupsErr = api.Search[rawGroup](core, core.EndpointForModule("auth/group/search"), "")
	if groupsErr != nil {
		return nil, groupsErr
	}
	var keys, keysErr = api.Search[rawApiKey](core, core.EndpointForModule("auth/user/search_api_key"), "")
	if keysErr != nil {
		return nil, keysErr
	}
	var privileges, privErr = api.Search[rawPriv](core, core.EndpointForModule("auth/priv/search"), "")
	if privErr != nil {
		return nil, privErr
	}

	var state = snapshot{}
	for _, user := range users {
		if !ownedByRun(user.Name) {
			state["user "+user.Uuid] = fmt.Sprintf("%s uid=%s disabled=%s expires=%s priv=%s groups=%s password#%x",
				user.Name, user.Uid, user.Disabled, user.Expires, user.Priv, user.GroupMemberships, hashOf(user.Password))
		}
	}
	for _, group := range groups {
		if !ownedByRun(group.Name) {
			state["group "+group.Uuid] = fmt.Sprintf("%s gid=%s priv=%s member=%s", group.Name, group.Gid, group.Priv, group.Member)
		}
	}
	for _, key := range keys {
		if !ownedByRun(key.Username) {
			state[fmt.Sprintf("apikey %x", hashOf(key.Key))] = key.Username
		}
	}
	for _, privilege := range privileges {
		for _, name := range append(append([]string{}, privilege.Users...), privilege.Groups...) {
			if !ownedByRun(name) {
				state["priv "+privilege.Id+" "+name] = "granted"
			}
		}
	}
	return state, nil
}

// changedSince lists what differs from before. Entries that appeared since (other agents share the box) are
// ignored, except new privilege grants to users and groups that existed before
func (after snapshot) changedSince(before snapshot) []string {
	var changes []string
	for key, value := range before {
		if now, found := after[key]; !found {
			changes = append(changes, "gone: "+key+" "+value)
		} else if now != value {
			changes = append(changes, fmt.Sprintf("changed: %s %s -> %s", key, value, now))
		}
	}
	for key := range after {
		if _, found := before[key]; !found && strings.HasPrefix(key, "priv ") {
			changes = append(changes, "new: "+key)
		}
	}
	return changes
}

// hashOf is a short fingerprint, so secrets never appear in the output
func hashOf(text string) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(text); i++ {
		hash = (hash ^ uint32(text[i])) * 16777619
	}
	return hash
}

// ownedByRun reports whether a user or group name carries this run's prefix
func ownedByRun(name string) bool {
	return runPrefix != "" && strings.HasPrefix(name, runPrefix)
}

// sweep removes the users (taken out of their groups first) and groups of this run and returns what it removed
func sweep() []string {
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		return nil
	}
	var removed []string
	var users, _ = api.Search[rawUser](core, core.EndpointForModule("auth/user/search"), runPrefix)
	for _, user := range users {
		if !ownedByRun(user.Name) {
			continue
		}
		_, _ = core.Mutate(core.EndpointForModule("auth/user/set/"+user.Uuid),
			map[string]any{"user": map[string]string{"name": user.Name, "group_memberships": ""}})
		if _, err := core.Mutate(core.EndpointForModule("auth/user/del/"+user.Uuid), nil); err == nil {
			removed = append(removed, "user "+user.Name)
		} else {
			fmt.Fprintf(os.Stderr, "integration/auth: sweep could not remove user %s: %v\n", user.Name, err)
		}
	}
	var groups, _ = api.Search[rawGroup](core, core.EndpointForModule("auth/group/search"), runPrefix)
	for _, group := range groups {
		if !ownedByRun(group.Name) {
			continue
		}
		if _, err := core.Mutate(core.EndpointForModule("auth/group/del/"+group.Uuid), nil); err == nil {
			removed = append(removed, "group "+group.Name)
		} else {
			fmt.Fprintf(os.Stderr, "integration/auth: sweep could not remove group %s: %v\n", group.Name, err)
		}
	}
	return removed
}

// --- helpers shared by the tests

// requireLive skips the test when the instance is not usable
func requireLive(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

func coreApi(t *testing.T) *api.OPNsense {
	t.Helper()
	requireLive(t)
	var core, err = api.ConfigureFromEnv()
	if err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	return core
}

func authApi(t *testing.T) *auth.AuthApi {
	t.Helper()
	return &auth.AuthApi{OPNsense: coreApi(t)}
}

// testName returns a user or group name for one test, e.g. "a4au-1a2b3c4d-alice"
func testName(label string) string {
	return runPrefix + "-" + label
}

// createUser creates a disabled test user with a random password and removes it when the test ends
func createUser(t *testing.T, label string, fields auth.UserFields) auth.User {
	t.Helper()
	var opn = authApi(t)
	var name = testName(label)
	fields.Name = &name
	if fields.Disabled == nil {
		var disabled = true
		fields.Disabled = &disabled
	}
	if fields.Password == nil {
		fields.RandomPassword = true
	}
	var uuid, err = opn.UserCreate(fields)
	if err != nil {
		t.Fatalf("UserCreate %s: %v", name, err)
	}
	t.Cleanup(func() { removeUser(t, uuid) })
	var user, getErr = opn.UserGet(uuid)
	if getErr != nil {
		t.Fatalf("UserGet %s: %v", uuid, getErr)
	}
	return user
}

// removeUser removes a test user (only users of this run) if it still exists
func removeUser(t *testing.T, uuid string) {
	t.Helper()
	var opn = authApi(t)
	var user, err = opn.UserGet(uuid)
	if api.IsNotFound(err) {
		return
	}
	if err != nil || !ownedByRun(user.Name) {
		t.Errorf("cleanup: not removing user %s (%q): %v", uuid, user.Name, err)
		return
	}
	if err := opn.UserRemove(uuid); err != nil {
		t.Errorf("cleanup: removing user %s: %v", user.Name, err)
	}
}

// createGroup creates a test group and removes it when the test ends
func createGroup(t *testing.T, label string, fields auth.GroupFields) auth.Group {
	t.Helper()
	var opn = authApi(t)
	var name = testName(label)
	fields.Name = &name
	var uuid, err = opn.GroupCreate(fields)
	if err != nil {
		t.Fatalf("GroupCreate %s: %v", name, err)
	}
	t.Cleanup(func() { removeGroup(t, uuid) })
	var group, getErr = opn.GroupGet(uuid)
	if getErr != nil {
		t.Fatalf("GroupGet %s: %v", uuid, getErr)
	}
	return group
}

func removeGroup(t *testing.T, uuid string) {
	t.Helper()
	var opn = authApi(t)
	var group, err = opn.GroupGet(uuid)
	if api.IsNotFound(err) {
		return
	}
	if err != nil || !ownedByRun(group.Name) {
		t.Errorf("cleanup: not removing group %s (%q): %v", uuid, group.Name, err)
		return
	}
	if err := opn.GroupRemove(uuid); err != nil {
		t.Errorf("cleanup: removing group %s: %v", group.Name, err)
	}
}

// rawJSON fetches a GET endpoint as generic JSON
func rawJSON(t *testing.T, endpoint string) map[string]any {
	t.Helper()
	var core = coreApi(t)
	var answer map[string]any
	if err := core.DoJSON("GET", core.EndpointForModule(endpoint), nil, &answer); err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	return answer
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	var encoded, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
