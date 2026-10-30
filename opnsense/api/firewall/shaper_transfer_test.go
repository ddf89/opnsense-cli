package firewall

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	shaperTransferTestPipe1 = "0f0f0f0f-1111-4222-8333-000000000001"
	shaperTransferTestPipe2 = "0f0f0f0f-1111-4222-8333-000000000002"
	shaperTransferTestQueue = "0f0f0f0f-1111-4222-8333-000000000011"
	shaperTransferTestNew   = "0f0f0f0f-1111-4222-8333-000000000099"
)

// shaperTransferTestApi answers the searches with two pipes (10000, 10002) and one queue (10000) and every upload
// with an import result; uploaded returns the payloads sent
func shaperTransferTestApi(t *testing.T) (*FirewallApi, func() []string) {
	t.Helper()
	var api, requests = newShaperTestApi(t, func(r shaperTestRequest) shaperTestAnswer {
		switch {
		case strings.HasSuffix(r.Path, "/search_pipes"):
			return shaperTestRows(
				ShaperPipe{Uuid: shaperTransferTestPipe1, Number: "10000", Description: "WAN down"},
				ShaperPipe{Uuid: shaperTransferTestPipe2, Number: "10002", Description: "WAN up"})
		case strings.HasSuffix(r.Path, "/search_queues"):
			return shaperTestRows(ShaperQueue{Uuid: shaperTransferTestQueue, Number: "10000", Pipe: shaperTransferTestPipe1, Description: "voip"})
		case strings.HasSuffix(r.Path, "/download_pipes"):
			return shaperTestOk("@uuid;number;description\n" + shaperTransferTestPipe1 + ";10000;WAN down\n")
		}
		return shaperTestOk(map[string]any{"validations": []any{}, "inserted": 1, "updated": 1, "uuids": map[string]int{}})
	})
	return api, func() []string {
		var payloads []string
		for _, request := range requests() {
			if strings.Contains(request.Path, "/upload_") {
				var body map[string]string
				if err := json.Unmarshal([]byte(request.Body), &body); err != nil {
					t.Fatalf("upload body %q: %v", request.Body, err)
				}
				payloads = append(payloads, request.Path+"\n"+body["payload"])
			}
		}
		return payloads
	}
}

func TestShaperPipeExport(t *testing.T) {
	var api, _ = shaperTransferTestApi(t)
	var content, err = api.ShaperPipeExport()
	if err != nil || !strings.HasPrefix(string(content), "@uuid;number;") {
		t.Errorf("got %q / %v", content, err)
	}
}

func TestShaperPipeImportNumbers(t *testing.T) {
	var cases = []struct {
		name string
		in   string
		want string // the payload sent, "" when the file is refused
		err  string
	}{
		{name: "unchanged file is sent as is", in: "@uuid;number;bandwidth\n" + shaperTransferTestPipe1 + ";10000;5\n;10001;6\n",
			want: "@uuid;number;bandwidth\n" + shaperTransferTestPipe1 + ";10000;5\n;10001;6\n"},
		{name: "new rows get free numbers, a number column is added", in: "bandwidth,description\n5,a\n6,b\n",
			want: "bandwidth,description,number\n5,a,10001\n6,b,10003\n"},
		{name: "empty number keeps the current one", in: "@uuid;number;bandwidth\n" + shaperTransferTestPipe2 + ";;5\n;;6\n",
			want: "@uuid;number;bandwidth\n" + shaperTransferTestPipe2 + ";10002;5\n;10001;6\n"},
		{name: "no number column for updates only", in: "@uuid;bandwidth\n" + shaperTransferTestPipe2 + ";5\n",
			want: "@uuid;bandwidth\n" + shaperTransferTestPipe2 + ";5\n"},
		{name: "an unknown @uuid is a new row", in: "@uuid;bandwidth\n" + shaperTransferTestNew + ";5\n",
			want: "@uuid;bandwidth;number\n" + shaperTransferTestNew + ";5;10001\n"},
		{name: "numbers may be swapped", in: "@uuid;number\n" + shaperTransferTestPipe1 + ";10002\n" + shaperTransferTestPipe2 + ";10000\n",
			want: "@uuid;number\n" + shaperTransferTestPipe1 + ";10002\n" + shaperTransferTestPipe2 + ";10000\n"},
		{name: "a number of another pipe", in: "number;bandwidth\n10002;5\n", err: `line 2: the number 10002 is used by the pipe "WAN up"`},
		{name: "a number of an updated pipe", in: "@uuid;number\n" + shaperTransferTestPipe1 + ";10002\n",
			err: `line 2: the number 10002 is used by the pipe "WAN up"`},
		{name: "a number given twice", in: "number;bandwidth\n10005;5\n010005;6\n", err: "line 3: the number 010005 is given on line 2 too"},
		{name: "invalid @uuid", in: "@uuid;bandwidth\n" + strings.ToUpper(shaperTransferTestPipe1) + ";5\n", err: "line 2: invalid @uuid"},
		{name: "@uuid twice", in: "@uuid;bandwidth\n" + shaperTransferTestPipe1 + ";5\n" + shaperTransferTestPipe1 + ";6\n",
			err: "line 3: the @uuid " + shaperTransferTestPipe1 + " is given twice (line 2)"},
		{name: "syntax", in: "bandwidth;description\n5\n", err: "wrong number of fields"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var api, uploaded = shaperTransferTestApi(t)
			var result, err = api.ShaperPipeImport([]byte(test.in), "pipes.csv")
			if test.err != "" {
				if err == nil || !strings.Contains(err.Error(), test.err) {
					t.Errorf("want error %q, got %v", test.err, err)
				}
				if len(uploaded()) != 0 {
					t.Errorf("nothing must be uploaded, got %q", uploaded())
				}
				return
			}
			if err != nil || result.Inserted != 1 || result.Updated != 1 {
				t.Fatalf("got %+v / %v", result, err)
			}
			if got := uploaded(); len(got) != 1 || got[0] != "/api/trafficshaper/settings/upload_pipes\n"+test.want {
				t.Errorf("uploaded %q, want %q", got, test.want)
			}
		})
	}
}

func TestShaperQueueImportPipes(t *testing.T) {
	var cases = []struct {
		name string
		in   string
		want string
		err  string
	}{
		{name: "description and uuid", in: "pipe;weight\nwan DOWN ;5\n" + shaperTransferTestPipe2 + ";6\n",
			want: "pipe;weight;number\n" + shaperTransferTestPipe1 + ";5;10001\n" + shaperTransferTestPipe2 + ";6;10002\n"},
		{name: "queue numbers are separate", in: "@uuid;number;pipe\n" + shaperTransferTestQueue + ";;WAN up\n;10002;WAN up\n",
			want: "@uuid;number;pipe\n" + shaperTransferTestQueue + ";10000;" + shaperTransferTestPipe2 + "\n;10002;" + shaperTransferTestPipe2 + "\n"},
		{name: "unknown pipe", in: "pipe;weight\nnope;5\n", err: `line 2: there is no pipe "nope"`},
		{name: "unknown pipe uuid", in: "pipe;weight\n" + shaperTransferTestNew + ";5\n", err: "line 2: there is no pipe"},
		{name: "number of another queue", in: "number;pipe\n10000;WAN up\n", err: `the number 10000 is used by the queue "voip"`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var api, uploaded = shaperTransferTestApi(t)
			var _, err = api.ShaperQueueImport([]byte(test.in), "queues.csv")
			if test.err != "" {
				if err == nil || !strings.Contains(err.Error(), test.err) {
					t.Errorf("want error %q, got %v", test.err, err)
				}
				if len(uploaded()) != 0 {
					t.Errorf("nothing must be uploaded, got %q", uploaded())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := uploaded(); len(got) != 1 || got[0] != "/api/trafficshaper/settings/upload_queues\n"+test.want {
				t.Errorf("uploaded %q, want %q", got, test.want)
			}
		})
	}
}
