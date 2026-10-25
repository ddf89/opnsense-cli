package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	coreapi "opnsense-cli/opnsense/api"
)

// Category is a rule category of Firewall > Categories (api/firewall/category), used to tag and filter rules
type Category struct {
	Uuid string
	// Name is unique (case-sensitive) and must not contain commas. Renaming a category renames it in legacy rules too
	Name string
	// Color is 6 hex digits without "#" (like ff8800) or empty
	Color string
	// Auto is set for categories OPNsense created from a rule's category, it removes them again when no rule uses
	// them any more (read-only)
	Auto bool
}

// CategoryPatch holds the fields to change, nil fields are kept
type CategoryPatch struct {
	Name  *string
	Color *string
}

var categoryColorPattern = regexp.MustCompile(`^[0-9a-fA-F]{6}$`)

func (c *Category) UnmarshalJSON(data []byte) error {
	var raw struct {
		Uuid  string `json:"uuid"`
		Name  string `json:"name"`
		Auto  string `json:"auto"`
		Color string `json:"color"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = Category{Uuid: raw.Uuid, Name: raw.Name, Color: raw.Color, Auto: raw.Auto == "1"}
	return nil
}

// CategoryValidateName checks a category name: not empty, no commas (rules store a comma separated list) and no
// control characters
func CategoryValidateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("a category name must not be empty")
	}
	for _, char := range name {
		if char == ',' || unicode.IsControl(char) {
			return fmt.Errorf("invalid category name %q: commas and control characters are not allowed", name)
		}
	}
	return nil
}

// CategoryValidateColor checks a color: 6 hex digits without "#" or empty for none
func CategoryValidateColor(color string) error {
	if color != "" && !categoryColorPattern.MatchString(color) {
		return fmt.Errorf("invalid color %q: 6 hex digits like ff8800", color)
	}
	return nil
}

func categoryValidatePatch(patch CategoryPatch) error {
	if patch.Name != nil {
		if err := CategoryValidateName(*patch.Name); err != nil {
			return err
		}
	}
	if patch.Color != nil {
		return CategoryValidateColor(*patch.Color)
	}
	return nil
}

type categoryContainer struct {
	Category map[string]string `json:"category"`
}

func (patch CategoryPatch) body() map[string]string {
	var fields = map[string]string{}
	if patch.Name != nil {
		fields["name"] = *patch.Name
	}
	if patch.Color != nil {
		fields["color"] = *patch.Color
	}
	return fields
}

// CategorySearch returns the categories where any column contains searchPhrase ("" for all), sorted by name
func (opn *FirewallApi) CategorySearch(searchPhrase string) ([]Category, error) {
	return coreapi.Search[Category](opn.OPNsense, opn.endpoint("firewall", "category", "search_item"), searchPhrase)
}

func (opn *FirewallApi) CategoryList() ([]Category, error) {
	return opn.CategorySearch("")
}

// CategoryGet returns the category with the given uuid or a *NotFoundError (get_item answers an unknown uuid with [])
func (opn *FirewallApi) CategoryGet(uuid string) (Category, error) {
	if uuid == "" {
		return Category{}, errors.New("cannot look up a category without uuid")
	}
	var categories, err = opn.CategoryList()
	if err != nil {
		return Category{}, err
	}
	for _, category := range categories {
		if category.Uuid == uuid {
			return category, nil
		}
	}
	return Category{}, &coreapi.NotFoundError{Name: "category " + uuid}
}

// CategoryGetByName returns the category with exactly this name (case-sensitive like OPNsense) or a *NotFoundError
func (opn *FirewallApi) CategoryGetByName(name string) (Category, error) {
	if name == "" {
		return Category{}, errors.New("cannot look up a category by an empty name")
	}
	var categories, err = opn.CategorySearch(name)
	if err != nil {
		return Category{}, err
	}
	for _, category := range categories {
		if category.Name == name {
			return category, nil
		}
	}
	return Category{}, &coreapi.NotFoundError{Name: fmt.Sprintf("category %q", name)}
}

// CategoryCreate adds a category from Name and Color (Auto is ignored) and returns its uuid
func (opn *FirewallApi) CategoryCreate(category Category) (string, error) {
	var patch = CategoryPatch{Name: &category.Name, Color: &category.Color}
	if err := categoryValidatePatch(patch); err != nil {
		return "", err
	}
	return opn.Mutate(opn.endpoint("firewall", "category", "add_item"), categoryContainer{Category: patch.body()})
}

// CategoryUpdate changes the non nil fields of patch, the others are kept. Returns *NotFoundError for an unknown
// uuid (checked first: set_item with a name would create a category). The current name is always sent: set_item
// treats a missing name as a rename to "" in the rules using the category
func (opn *FirewallApi) CategoryUpdate(uuid string, patch CategoryPatch) error {
	if uuid == "" {
		return errors.New("cannot update a category without uuid")
	}
	if err := categoryValidatePatch(patch); err != nil {
		return err
	}
	var existing, err = opn.CategoryGet(uuid)
	if err != nil {
		return err
	}
	if patch.Name == nil {
		patch.Name = &existing.Name
	}
	_, err = opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("firewall", "category", "set_item"), uuid),
		categoryContainer{Category: patch.body()})
	return err
}

// CategoryRemove deletes the category with the given uuid. Returns *NotFoundError if it does not exist, a category
// used by rules can not be removed (the error names the rules)
func (opn *FirewallApi) CategoryRemove(uuid string) error {
	if uuid == "" || strings.Contains(uuid, ",") {
		return fmt.Errorf("cannot remove a category by uuid %q", uuid)
	}
	if _, err := opn.Mutate(fmt.Sprintf("%s/%s", opn.endpoint("firewall", "category", "del_item"), uuid), nil); err != nil {
		if coreapi.IsNotFound(err) {
			return &coreapi.NotFoundError{Name: "category " + uuid, Err: err}
		}
		return groupInUseError("category "+uuid+", it is in use by", err)
	}
	return nil
}
