package firewall

import (
	"reflect"
	"strings"
	"testing"

	coreapi "opnsense-cli/opnsense/api"
)

const (
	categoryTestUuid = "13830adf-357c-4899-a0ba-fa54986fc472"
	categoryTestPath = "/api/firewall/category/"
)

// categoryTestSearch is a search_item answer of OPNsense 26.7, sorted by name
const categoryTestSearch = `{"rows":[` +
	`{"uuid":"77ee7685-87f3-45ff-9ebc-5e8e41f03aa3","name":"from rules","auto":"1","color":""},` +
	`{"uuid":"13830adf-357c-4899-a0ba-fa54986fc472","name":"web","auto":"0","color":"ff00AA"},` +
	`{"uuid":"90ea96f7-5fd6-42b0-93e1-7ee35d4658b2","name":"Web","auto":"0","color":""}` +
	`],"rowCount":3,"total":3,"current":1}`

func categoryTestHandler(mutation *string) func(r groupTestRequest) (int, string) {
	return func(r groupTestRequest) (int, string) {
		if strings.HasSuffix(r.Path, "/search_item") {
			return 200, categoryTestSearch
		}
		if strings.HasPrefix(*mutation, "500 ") {
			return 500, strings.TrimPrefix(*mutation, "500 ")
		}
		return 200, *mutation
	}
}

func TestCategorySearchAndGet(t *testing.T) {
	var api, requests = newGroupTestApi(t, categoryTestHandler(new(string)))
	var categories, err = api.CategorySearch("we")
	if err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Path != categoryTestPath+"search_item" || got.Query.Get("searchPhrase") != "we" {
		t.Errorf("unexpected request %+v", got)
	}
	var want = []Category{
		{Uuid: "77ee7685-87f3-45ff-9ebc-5e8e41f03aa3", Name: "from rules", Auto: true},
		{Uuid: categoryTestUuid, Name: "web", Color: "ff00AA"},
		{Uuid: "90ea96f7-5fd6-42b0-93e1-7ee35d4658b2", Name: "Web"},
	}
	if !reflect.DeepEqual(categories, want) {
		t.Errorf("got  %+v\nwant %+v", categories, want)
	}

	if category, err := api.CategoryGet(categoryTestUuid); err != nil || category.Name != "web" {
		t.Errorf("CategoryGet: %+v / %v", category, err)
	}
	if _, err := api.CategoryGet("00000000-0000-4000-8000-000000000000"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	// names are case-sensitive
	if category, err := api.CategoryGetByName("Web"); err != nil || category.Uuid != "90ea96f7-5fd6-42b0-93e1-7ee35d4658b2" {
		t.Errorf("CategoryGetByName: %+v / %v", category, err)
	}
	if _, err := api.CategoryGetByName("WEB"); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if _, err := api.CategoryGet(""); err == nil {
		t.Error("want an error for an empty uuid")
	}
	if _, err := api.CategoryGetByName(""); err == nil {
		t.Error("want an error for an empty name")
	}
}

func TestCategoryValidate(t *testing.T) {
	for _, name := range []string{"", " ", "a,b", "a\nb"} {
		if err := CategoryValidateName(name); err == nil {
			t.Errorf("name %q: want an error", name)
		}
	}
	for _, color := range []string{"#ff0000", "fff", "ggg000", "ff00001"} {
		if err := CategoryValidateColor(color); err == nil {
			t.Errorf("color %q: want an error", color)
		}
	}
	if CategoryValidateName("Web servers") != nil || CategoryValidateColor("") != nil || CategoryValidateColor("A0b1C2") != nil {
		t.Error("valid values refused")
	}
}

func TestCategoryCreate(t *testing.T) {
	var answer = `{"result":"saved","uuid":"` + categoryTestUuid + `"}`
	var api, requests = newGroupTestApi(t, categoryTestHandler(&answer))
	var uuid, err = api.CategoryCreate(Category{Name: "web", Color: "ff8800", Auto: true})
	if err != nil || uuid != categoryTestUuid {
		t.Fatalf("got %q / %v", uuid, err)
	}
	var want = map[string]map[string]string{"category": {"name": "web", "color": "ff8800"}}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != categoryTestPath+"add_item" || !reflect.DeepEqual(got.Body, want) {
		t.Errorf("unexpected request %+v", got)
	}

	*requests = nil
	for _, category := range []Category{{Name: ""}, {Name: "a,b"}, {Name: "x", Color: "red"}} {
		if _, err := api.CategoryCreate(category); err == nil {
			t.Errorf("%+v: want an error", category)
		}
	}
	if len(*requests) != 0 {
		t.Errorf("invalid categories must not be sent: %+v", *requests)
	}

	answer = `{"result":"failed","validations":{"category.name":"A category with this name already exists."}}`
	if _, err := api.CategoryCreate(Category{Name: "web"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("want the validation error, got %v", err)
	}
}

func TestCategoryUpdate(t *testing.T) {
	var answer = `{"result":"saved"}`
	var api, requests = newGroupTestApi(t, categoryTestHandler(&answer))

	var color = ""
	if err := api.CategoryUpdate(categoryTestUuid, CategoryPatch{Color: &color}); err != nil {
		t.Fatal(err)
	}
	// the current name is always sent, a missing name is a rename to "" for OPNsense
	var want = map[string]map[string]string{"category": {"name": "web", "color": ""}}
	if got := groupTestMutations(*requests); len(got) != 1 || got[0].Path != categoryTestPath+"set_item/"+categoryTestUuid || !reflect.DeepEqual(got[0].Body, want) {
		t.Errorf("unexpected mutations %+v", got)
	}

	*requests = nil
	var name = "web servers"
	if err := api.CategoryUpdate(categoryTestUuid, CategoryPatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if got := groupTestMutations(*requests); len(got) != 1 || !reflect.DeepEqual(got[0].Body, map[string]map[string]string{"category": {"name": "web servers"}}) {
		t.Errorf("unexpected mutations %+v", got)
	}

	*requests = nil
	var bad = "#000000"
	if err := api.CategoryUpdate(categoryTestUuid, CategoryPatch{Color: &bad}); err == nil {
		t.Error("want an error for an invalid color")
	}
	if err := api.CategoryUpdate("00000000-0000-4000-8000-000000000000", CategoryPatch{Color: &color}); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}
	if err := api.CategoryUpdate("", CategoryPatch{}); err == nil {
		t.Error("want an error for an empty uuid")
	}
	if got := groupTestMutations(*requests); len(got) != 0 {
		t.Errorf("want no mutation, got %+v", got)
	}
}

func TestCategoryRemove(t *testing.T) {
	var answer = `{"result":"deleted"}`
	var api, requests = newGroupTestApi(t, categoryTestHandler(&answer))
	if err := api.CategoryRemove(categoryTestUuid); err != nil {
		t.Fatal(err)
	}
	if got := (*requests)[0]; got.Method != "POST" || got.Path != categoryTestPath+"del_item/"+categoryTestUuid {
		t.Errorf("unexpected request %+v", got)
	}

	answer = `{"result":"not found"}`
	if err := api.CategoryRemove(categoryTestUuid); !coreapi.IsNotFound(err) {
		t.Errorf("want NotFoundError, got %v", err)
	}

	answer = "500 " + `{"errorMessage":"Filter - allow web {Filter.rules.rule.d83fbe7e}\n","errorTitle":"Item categories.category {web} in use by:"}`
	var err = api.CategoryRemove(categoryTestUuid)
	if err == nil || err.Error() != "cannot remove category "+categoryTestUuid+", it is in use by: Filter - allow web {Filter.rules.rule.d83fbe7e}" {
		t.Errorf("want the in use message, got %v", err)
	}

	*requests = nil
	for _, uuid := range []string{"", "a,b"} {
		if err := api.CategoryRemove(uuid); err == nil {
			t.Errorf("%q: want an error", uuid)
		}
	}
	if len(*requests) != 0 {
		t.Errorf("want no requests, got %+v", *requests)
	}
}
