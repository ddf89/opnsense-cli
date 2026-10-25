package ipsec

import (
	"reflect"
	"testing"
)

// TestResourceEndpoints checks the endpoints and containers of every configuration list
func TestResourceEndpoints(t *testing.T) {
	type wrappers struct {
		list   func(api *IPsecApi) ([]Record, error)
		create func(api *IPsecApi, fields Fields) (string, error)
		update func(api *IPsecApi, uuid string, fields Fields) error
		remove func(api *IPsecApi, uuid string) error
		form   func(api *IPsecApi) (Form, error)
		field  string
	}
	for _, res := range []struct {
		resource resource
		wrappers wrappers
	}{
		{connectionResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.ConnectionList("") }, (*IPsecApi).ConnectionCreate,
			(*IPsecApi).ConnectionUpdate, (*IPsecApi).ConnectionRemove, (*IPsecApi).ConnectionForm, "description"}},
		{localResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.LocalList("") }, (*IPsecApi).LocalCreate,
			(*IPsecApi).LocalUpdate, (*IPsecApi).LocalRemove, (*IPsecApi).LocalForm, "id"}},
		{remoteResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.RemoteList("") }, (*IPsecApi).RemoteCreate,
			(*IPsecApi).RemoteUpdate, (*IPsecApi).RemoteRemove, (*IPsecApi).RemoteForm, "cacerts"}},
		{childResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.ChildList("") }, (*IPsecApi).ChildCreate,
			(*IPsecApi).ChildUpdate, (*IPsecApi).ChildRemove, (*IPsecApi).ChildForm, "local_ts"}},
		{poolResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.PoolList("") }, (*IPsecApi).PoolCreate,
			(*IPsecApi).PoolUpdate, (*IPsecApi).PoolRemove, (*IPsecApi).PoolForm, "addrs"}},
		{vtiResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.VtiList("") }, (*IPsecApi).VtiCreate,
			(*IPsecApi).VtiUpdate, (*IPsecApi).VtiRemove, (*IPsecApi).VtiForm, "tunnel_local"}},
		{manualSpdResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.ManualSpdList("") }, (*IPsecApi).ManualSpdCreate,
			(*IPsecApi).ManualSpdUpdate, (*IPsecApi).ManualSpdRemove, (*IPsecApi).ManualSpdForm, "connection_child"}},
		{preSharedKeyResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.PreSharedKeyList("") }, (*IPsecApi).PreSharedKeyCreate,
			(*IPsecApi).PreSharedKeyUpdate, (*IPsecApi).PreSharedKeyRemove, (*IPsecApi).PreSharedKeyForm, "Key"}},
		{keyPairResource, wrappers{func(api *IPsecApi) ([]Record, error) { return api.KeyPairList("") }, (*IPsecApi).KeyPairCreate,
			(*IPsecApi).KeyPairUpdate, (*IPsecApi).KeyPairRemove, (*IPsecApi).KeyPairForm, "publicKey"}},
	} {
		var base = "/api/ipsec/" + res.resource.controller + "/"
		var api, requests = testApi(t, map[string]any{
			"GET " + base + res.resource.search:                    testRows(map[string]any{"uuid": testConnUuid}),
			"GET " + base + res.resource.get:                       `{"` + res.resource.container + `":{"enabled":"1"}}`,
			"POST " + base + res.resource.add:                      `{"result":"saved","uuid":"` + testOtherUuid + `"}`,
			"POST " + base + res.resource.set + "/" + testConnUuid: `{"result":"saved"}`,
			"POST " + base + res.resource.del + "/" + testConnUuid: `{"result":"deleted"}`,
		})
		var w = res.wrappers
		if records, err := w.list(api); err != nil || len(records) != 1 {
			t.Errorf("%s list: %v %v", res.resource.noun, records, err)
		}
		if form, err := w.form(api); err != nil || form.Value("enabled") != "1" {
			t.Errorf("%s form: %v %v", res.resource.noun, form, err)
		}
		if uuid, err := w.create(api, Fields{w.field: "x"}); err != nil || uuid != testOtherUuid {
			t.Errorf("%s create: %q %v", res.resource.noun, uuid, err)
		}
		if err := w.update(api, testConnUuid, Fields{w.field: "y"}); err != nil {
			t.Errorf("%s update: %v", res.resource.noun, err)
		}
		if err := w.remove(api, testConnUuid); err != nil {
			t.Errorf("%s remove: %v", res.resource.noun, err)
		}
		var mutations = testMutations(requests())
		if len(mutations) != 3 || !reflect.DeepEqual(mutations[0].Body, map[string]any{res.resource.container: map[string]any{w.field: "x"}}) ||
			!reflect.DeepEqual(mutations[1].Body, map[string]any{res.resource.container: map[string]any{w.field: "y"}}) || mutations[2].Body != nil {
			t.Errorf("%s: unexpected mutations %+v", res.resource.noun, mutations)
		}
	}
}

func TestPoolAndKeyPairByName(t *testing.T) {
	var api, _ = testApi(t, map[string]any{
		"GET /api/ipsec/pools/search":          testRows(map[string]any{"uuid": testConnUuid, "name": "mobile"}),
		"GET /api/ipsec/key_pairs/search_item": testRows(map[string]any{"uuid": testConnUuid, "name": "fw key"}),
	})
	if pool, err := api.PoolGetByName("MOBILE"); err != nil || pool.Uuid() != testConnUuid {
		t.Errorf("PoolGetByName: %v %v", pool, err)
	}
	if keyPair, err := api.KeyPairGetByName("fw key"); err != nil || keyPair.Uuid() != testConnUuid {
		t.Errorf("KeyPairGetByName: %v %v", keyPair, err)
	}
	if _, err := api.PoolGetByName(""); err == nil {
		t.Error("want an error for an empty name")
	}
}
