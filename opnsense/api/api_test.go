package api

import (
	"os"
	"strings"
	"testing"
)

// configTestEnv isolates ConfigureFromEnv from the developer environment: it runs in an empty
// directory (so godotenv.Load() finds no .env) with the given OPN_* variables set and all others unset
func configTestEnv(t *testing.T, env map[string]string) {
	t.Helper()
	t.Chdir(t.TempDir())
	for _, name := range []string{"OPN_URL", "OPN_APIKEY", "OPN_APISECRET", "OPN_NOSSLVERIFY"} {
		// t.Setenv registers the restore of the original value, then we unset it for this test
		t.Setenv(name, "")
		if value, isset := env[name]; isset {
			t.Setenv(name, value)
		} else {
			_ = os.Unsetenv(name)
		}
	}
}

func TestConfigureFromEnv(t *testing.T) {
	configTestEnv(t, map[string]string{
		"OPN_URL":         "https://opnsense.example:10443//",
		"OPN_APIKEY":      "key",
		"OPN_APISECRET":   "secret",
		"OPN_NOSSLVERIFY": "1",
	})

	var opn, err = ConfigureFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if opn.BaseUrl.String() != "https://opnsense.example:10443" {
		t.Errorf("BaseUrl = %q, trailing slashes not trimmed", opn.BaseUrl.String())
	}
	if opn.ApiKey != "key" || opn.ApiSecret != "secret" || !opn.NoSslVerify {
		t.Errorf("opn = %+v", opn)
	}
	if got := opn.EndpointForPluginControllerMethod("dnsmasq", "service", "status"); got != "https://opnsense.example:10443/api/dnsmasq/service/status" {
		t.Errorf("endpoint = %q", got)
	}
}

func TestConfigureFromEnvSslVerifyDefault(t *testing.T) {
	configTestEnv(t, map[string]string{"OPN_URL": "https://fw", "OPN_APIKEY": "k", "OPN_APISECRET": "s"})

	var opn, err = ConfigureFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if opn.NoSslVerify {
		t.Errorf("NoSslVerify should default to false")
	}
}

func TestConfigureFromEnvDotEnv(t *testing.T) {
	configTestEnv(t, map[string]string{"OPN_APIKEY": "k", "OPN_APISECRET": "s"})
	if err := os.WriteFile(".env", []byte("OPN_URL=https://from-dotenv/\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var opn, err = ConfigureFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if opn.BaseUrl.String() != "https://from-dotenv" {
		t.Errorf("BaseUrl = %q", opn.BaseUrl.String())
	}
}

func TestConfigureFromEnvMissing(t *testing.T) {
	var complete = map[string]string{"OPN_URL": "https://fw", "OPN_APIKEY": "k", "OPN_APISECRET": "s"}
	for _, missing := range []string{"OPN_URL", "OPN_APIKEY", "OPN_APISECRET"} {
		t.Run(missing, func(t *testing.T) {
			var env = map[string]string{}
			for name, value := range complete {
				if name != missing {
					env[name] = value
				}
			}
			configTestEnv(t, env)

			var opn, err = ConfigureFromEnv()
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Errorf("err = %v, want mention of %s", err, missing)
			}
			if opn != nil {
				t.Errorf("opn = %+v, want nil", opn)
			}
		})
	}
}

func TestConfigureFromEnvInvalidUrl(t *testing.T) {
	configTestEnv(t, map[string]string{"OPN_URL": "https://fw:port", "OPN_APIKEY": "k", "OPN_APISECRET": "s"})

	if _, err := ConfigureFromEnv(); err == nil {
		t.Errorf("expected an url parse error")
	}
}
