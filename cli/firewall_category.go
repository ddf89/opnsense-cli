package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/firewall"
	"strings"
)

// /firewall/category: Firewall > Categories, tags to group and filter rules. Items are selected by the # of print,
// the uuid or the name. Categories marked auto were created by OPNsense from a rule's category and are removed by it
// when no rule uses them any more. Categories take effect immediately, there is nothing to apply

const firewallCategoryItemHelp = "the #, uuid or name of the category"

// firewallCategoryFieldArgs are the field arguments of add and set
func firewallCategoryFieldArgs(add bool) []Arg {
	var name = Arg{Name: "name", Help: "the category name (unique, no commas)", Required: add, Validate: firewall.CategoryValidateName}
	if !add {
		name.Help = "rename the category"
	}
	return []Arg{
		name,
		{Name: "color", Help: `the color as 6 hex digits like ff8800 (a leading # is accepted), "" for none`,
			Validate: firewallCategoryValidateColor},
	}
}

func init() {
	var menu = Root.Menu("firewall/category")
	menu.Help = "rule categories (Firewall > Categories)"
	var item = Arg{Name: "item", Help: firewallCategoryItemHelp, Positional: true, Required: true, Complete: firewallCategoryItemNames}
	menu.Add(
		&Command{Name: "print", Help: "list the categories",
			Long: `AUTO categories were created by OPNsense from a rule's category, it removes them when no rule uses them.`,
			Args: []Arg{
				{Name: "detail", Help: "show all fields of every category", Type: Bool},
				{Name: "json", Help: "one JSON object per line, as the API returns them", Type: Bool},
				{Name: "search", Help: "only categories where any field contains this text"},
			}, Run: firewallCategoryPrint},
		&Command{Name: "show", Help: "show all fields of one category", Args: []Arg{item}, Run: firewallCategoryShow},
		&Command{Name: "add", Help: "add a category, prints its uuid",
			Long: `If a category with this name (case-sensitive) exists already, add fails unless replace is given, then its
color is replaced (a color not given is cleared).`,
			Args: append(firewallCategoryFieldArgs(true), Arg{Name: "replace", Help: "replace the category with the same name", Type: Bool}),
			Run:  firewallCategoryAdd},
		&Command{Name: "set", Help: "change fields of a category, the others are kept",
			Args: append([]Arg{item}, firewallCategoryFieldArgs(false)...), Check: firewallCategoryCheckSet, Run: firewallCategorySet},
		&Command{Name: "remove", Help: "remove a category",
			Long: `A category used by rules can not be removed, the error names the rules.`,
			Args: []Arg{item}, Run: firewallCategoryRemove},
	)
}

// --- validation

// firewallCategoryColor strips the optional leading "#"
func firewallCategoryColor(value string) string {
	return strings.TrimPrefix(value, "#")
}

func firewallCategoryValidateColor(value string) error {
	if err := firewall.CategoryValidateColor(firewallCategoryColor(value)); err != nil {
		return fmt.Errorf("must be 6 hex digits like ff8800, got %q", value)
	}
	return nil
}

func firewallCategoryCheckSet(args *Args) error {
	if !args.Has("name") && !args.Has("color") {
		return errors.New("set: nothing to change, give name= or color= (type \"set ?\" for help)")
	}
	return nil
}

// --- lookups

// firewallCategorySearch returns the matching categories in API order, with the raw API objects for json output
func firewallCategorySearch(api *firewall.FirewallApi, searchPhrase string) ([]firewall.Category, []json.RawMessage, error) {
	var endpoint = api.EndpointForPluginControllerMethod("firewall", "category", "search_item")
	var rows, err = coreapi.Search[json.RawMessage](api.OPNsense, endpoint, searchPhrase)
	if err != nil {
		return nil, nil, err
	}
	var categories = make([]firewall.Category, len(rows))
	for i, row := range rows {
		if err := json.Unmarshal(row, &categories[i]); err != nil {
			return nil, nil, fmt.Errorf("unexpected category from OPNsense: %w", err)
		}
	}
	return categories, rows, nil
}

func firewallCategoryUuid(category firewall.Category) string {
	return category.Uuid
}

func firewallCategoryNames(category firewall.Category) []string {
	return []string{category.Name}
}

// firewallCategorySelect loads all categories and finds the one selector refers to
func firewallCategorySelect(c *Context, api *firewall.FirewallApi, selector string) (firewall.Category, error) {
	var categories, _, err = firewallCategorySearch(api, "")
	if err != nil {
		return firewall.Category{}, err
	}
	return Select(c, selector, categories, firewallCategoryUuid, firewallCategoryNames)
}

// firewallCategoryItemNames completes item names from the API
func firewallCategoryItemNames(c *Context) []string {
	var api, err = firewallApi(c)
	if err != nil {
		return nil
	}
	var categories, _, searchErr = firewallCategorySearch(api, "")
	if searchErr != nil {
		return nil
	}
	var names = make([]string, 0, len(categories))
	for _, category := range categories {
		names = append(names, category.Name)
	}
	return names
}

// --- output

func firewallCategoryFields(category firewall.Category) [][2]string {
	return [][2]string{
		{"uuid", category.Uuid},
		{"name", category.Name},
		{"color", category.Color},
		{"auto", YesNo(Flag(category.Auto))},
	}
}

func firewallCategoryPrint(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var categories, raw, searchErr = firewallCategorySearch(api, args.String("search"))
	if searchErr != nil {
		return searchErr
	}

	var uuids = make([]string, len(categories))
	for i, category := range categories {
		uuids[i] = category.Uuid
	}
	switch {
	case args.Bool("json"):
		for _, row := range raw {
			c.Println(string(row))
		}
	case args.Bool("detail"):
		var items = make([][][2]string, len(categories))
		for i, category := range categories {
			items[i] = firewallCategoryFields(category)
		}
		c.Details(items, uuids)
	default:
		var rows = make([][]string, len(categories))
		for i, category := range categories {
			rows[i] = []string{category.Name, category.Color, YesNo(Flag(category.Auto))}
		}
		c.Items([]string{"NAME", "COLOR", "AUTO"}, rows, uuids)
	}
	return nil
}

func firewallCategoryShow(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var category, selectErr = firewallCategorySelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	c.Fields(firewallCategoryFields(category))
	return nil
}

// --- changes

func firewallCategoryAdd(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var name = args.String("name")
	var color = firewallCategoryColor(args.String("color"))
	var existing, findErr = api.CategoryGetByName(name)
	if findErr != nil && !coreapi.IsNotFound(findErr) {
		return findErr
	}
	if findErr != nil {
		var uuid, createErr = api.CategoryCreate(firewall.Category{Name: name, Color: color})
		if createErr != nil {
			return createErr
		}
		c.Println(uuid)
		return nil
	}
	if !args.Bool("replace") {
		return fmt.Errorf("a category named %q exists already (%s), change it with set or replace it with add ... replace",
			existing.Name, existing.Uuid)
	}
	if err := api.CategoryUpdate(existing.Uuid, firewall.CategoryPatch{Color: &color}); err != nil {
		return err
	}
	c.Infof("replaced the existing category %q", existing.Name)
	c.Println(existing.Uuid)
	return nil
}

func firewallCategorySet(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var category, selectErr = firewallCategorySelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var patch firewall.CategoryPatch
	if args.Has("name") {
		var name = args.String("name")
		patch.Name = &name
	}
	if args.Has("color") {
		var color = firewallCategoryColor(args.String("color"))
		patch.Color = &color
	}
	return api.CategoryUpdate(category.Uuid, patch)
}

func firewallCategoryRemove(c *Context, args *Args) error {
	var api, err = firewallApi(c)
	if err != nil {
		return err
	}
	var category, selectErr = firewallCategorySelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	return api.CategoryRemove(category.Uuid)
}
