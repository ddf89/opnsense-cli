package cli

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	coreapi "opnsense-cli/opnsense/api"
	"opnsense-cli/opnsense/api/captiveportal"
)

// /captive-portal/template: the custom login pages of Services > Captive Portal > Templates
// (api/captiveportal/template). A template is a zip with the files that differ from the default template; download
// returns the complete page (the template over the default), download-default the default to start from. Items are
// selected by the # of print, the uuid or the name

const captivePortalTemplateItemHelp = "the #, uuid or name of the template"

func init() {
	var menu = Root.Menu("captive-portal/template")
	menu.Help = "custom login pages of the captive portal (Services > Captive Portal > Templates)"
	var item = Arg{Name: "item", Help: captivePortalTemplateItemHelp, Positional: true, Required: true, Complete: captivePortalTemplateItemNames}
	var fileArgs = func(what string) []Arg {
		return []Arg{
			{Name: "file", Help: "file to write, - for stdout (default: " + what + ")"},
			{Name: "overwrite", Type: Bool, Help: "overwrite an existing file"},
		}
	}
	menu.Add(
		&Command{Name: "print", Help: "list the templates and the zones using them", Args: []Arg{
			{Name: "detail", Type: Bool, Help: "show all fields of every template"},
			{Name: "json", Type: Bool, Help: "one JSON object per line, as the API returns them (with the base64 zip)"},
			{Name: "search", Help: "only templates where any field contains this text"},
		}, Run: captivePortalTemplatePrint},
		&Command{Name: "show", Help: "show one template", Args: []Arg{item}, Run: captivePortalTemplateShow},
		&Command{Name: "download", Help: "save the complete template as zip: its files over the default template",
			Args: append([]Arg{item}, fileArgs("template_<file-id>.zip as OPNsense names it")...), Check: captivePortalCheckFileArgs,
			Run: captivePortalTemplateDownload},
		&Command{Name: "download-default", Help: "save the default template as zip, the base of your own",
			Args: fileArgs("template_default.zip"), Check: captivePortalCheckFileArgs, Run: captivePortalTemplateDownloadDefault},
		&Command{Name: "upload", Help: "add a template from a zip file, prints its uuid",
			Long: `The zip holds the login page (index.html at the top) and the files it uses; files equal to those of the default
template are dropped by OPNsense. If a template with this name exists, upload fails unless replace is given, then its
content is replaced. Zones use a template with "/captive-portal/zone set <zone> template=<name>".
` + captivePortalApplyHint,
			Args: []Arg{
				{Name: "name", Required: true, Validate: captiveportal.TemplateValidateName,
					Help: "name of the template: letters, digits, spaces, . , _ (no dashes)"},
				{Name: "file", Required: true, Help: "the zip file to upload"},
				{Name: "replace", Type: Bool, Help: "replace the content of the template with the same name"},
			},
			Run: captivePortalTemplateUpload},
		&Command{Name: "set", Help: "rename a template or replace its content",
			Long: captivePortalApplyHint,
			Args: []Arg{item,
				{Name: "name", Validate: captiveportal.TemplateValidateName, Help: "the new name"},
				{Name: "file", Help: "a zip file with the new content"},
			},
			Check: func(args *Args) error {
				if !args.Has("name") && !args.Has("file") {
					return errors.New("set: nothing to change, give name= or file= (type \"set ?\" for help)")
				}
				return nil
			},
			Run: captivePortalTemplateSet},
		&Command{Name: "remove", Help: "remove a template, refused while zones use it", Args: []Arg{item}, Run: captivePortalTemplateRemove},
	)
}

// --- lookups

func captivePortalTemplateUuid(template captiveportal.Template) string { return template.Uuid }

func captivePortalTemplateSelect(c *Context, api *captiveportal.CaptivePortalApi, selector string) (captiveportal.Template, []captiveportal.Template, error) {
	var templates, err = api.TemplateList("")
	if err != nil {
		return captiveportal.Template{}, nil, err
	}
	var template, selectErr = Select(c, selector, templates, captivePortalTemplateUuid,
		func(template captiveportal.Template) []string { return []string{template.Name} })
	return template, templates, selectErr
}

// captivePortalTemplateResolve finds a template by uuid or name (exact, else case-insensitive)
func captivePortalTemplateResolve(templates []captiveportal.Template, value string) (captiveportal.Template, error) {
	var folded []captiveportal.Template
	for _, template := range templates {
		if template.Name == value || strings.EqualFold(template.Uuid, value) {
			return template, nil
		}
		if strings.EqualFold(template.Name, value) {
			folded = append(folded, template)
		}
	}
	switch len(folded) {
	case 1:
		return folded[0], nil
	case 0:
		var names []string
		for _, template := range templates {
			names = append(names, fmt.Sprintf("%q", template.Name))
		}
		if len(names) == 0 {
			return captiveportal.Template{}, &coreapi.NotFoundError{Name: fmt.Sprintf("template %q, there are no templates", value)}
		}
		return captiveportal.Template{}, &coreapi.NotFoundError{Name: fmt.Sprintf("template %q, valid are: %s", value, strings.Join(names, ", "))}
	default:
		return captiveportal.Template{}, &coreapi.TooManyFoundError{Name: fmt.Sprintf("template %q matches several templates, give the exact name or the uuid", value)}
	}
}

func captivePortalTemplateItemNames(c *Context) []string {
	var api, err = captivePortalApi(c)
	if err != nil {
		return nil
	}
	var templates, listErr = api.TemplateList("")
	if listErr != nil {
		return nil
	}
	var names []string
	for _, template := range templates {
		names = append(names, template.Name)
	}
	return names
}

// captivePortalTemplateUsers returns the descriptions of the zones using the template
func captivePortalTemplateUsers(zones []captiveportal.Zone, uuid string) []string {
	var users []string
	for _, zone := range zones {
		if zone.Template != "" && strings.EqualFold(zone.Template, uuid) {
			users = append(users, zone.Description)
		}
	}
	return users
}

// captivePortalTemplateSize is the size of the stored zip
func captivePortalTemplateSize(template captiveportal.Template) string {
	if template.Content == "" {
		return ""
	}
	return ifaceBytes(float64(base64.StdEncoding.DecodedLen(len(template.Content))))
}

// --- output

func captivePortalTemplatePrint(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	if args.Bool("json") {
		var endpoint = api.EndpointForPluginControllerMethod("captiveportal", "template", "search_templates")
		var rows, searchErr = coreapi.Search[map[string]any](api.OPNsense, endpoint, args.String("search"))
		if searchErr != nil {
			return searchErr
		}
		for _, row := range rows {
			if err := c.JSON(row); err != nil {
				return err
			}
		}
		return nil
	}
	templates, err := api.TemplateList(args.String("search"))
	if err != nil {
		return err
	}
	zones, err := api.ZoneList("")
	if err != nil {
		return err
	}
	var rows = make([][]string, len(templates))
	var details = make([][][2]string, len(templates))
	var uuids = make([]string, len(templates))
	for i, template := range templates {
		uuids[i] = template.Uuid
		rows[i] = []string{template.Name, template.FileId, captivePortalTemplateSize(template),
			strings.Join(captivePortalTemplateUsers(zones, template.Uuid), ",")}
		details[i] = captivePortalTemplateDetail(template, zones)
	}
	if args.Bool("detail") {
		c.Details(details, uuids)
		return nil
	}
	c.Items([]string{"NAME", "FILE-ID", "SIZE", "USED-BY"}, rows, uuids)
	return nil
}

// captivePortalTemplateDetail are the fields of show and print detail
func captivePortalTemplateDetail(template captiveportal.Template, zones []captiveportal.Zone) [][2]string {
	return [][2]string{
		{"uuid", template.Uuid},
		{"name", template.Name},
		{"file-id", template.FileId},
		{"size", captivePortalTemplateSize(template)},
		{"used-by", strings.Join(captivePortalTemplateUsers(zones, template.Uuid), ",")},
	}
}

func captivePortalTemplateShow(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var template, _, selectErr = captivePortalTemplateSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	zones, err := api.ZoneList("")
	if err != nil {
		return err
	}
	c.Fields(captivePortalTemplateDetail(template, zones))
	return nil
}

// --- files

func captivePortalTemplateDownload(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var template, _, selectErr = captivePortalTemplateSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	if template.FileId == "" {
		return fmt.Errorf("the template %q has no file id", template.Name)
	}
	var defaultName = "template_" + template.FileId + ".zip"
	if err := captivePortalCheckOutput(args.String("file"), defaultName, args.Bool("overwrite")); err != nil {
		return err
	}
	content, err := api.TemplateDownload(template.FileId)
	if err != nil {
		return err
	}
	return captivePortalWriteOutput(c, args.String("file"), defaultName, content, args.Bool("overwrite"))
}

func captivePortalTemplateDownloadDefault(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var defaultName = "template_default.zip"
	if err := captivePortalCheckOutput(args.String("file"), defaultName, args.Bool("overwrite")); err != nil {
		return err
	}
	content, err := api.TemplateDownload("")
	if err != nil {
		return err
	}
	return captivePortalWriteOutput(c, args.String("file"), defaultName, content, args.Bool("overwrite"))
}

// captivePortalTemplateReadZip reads and checks a zip file
func captivePortalTemplateReadZip(name string) ([]byte, error) {
	var content, err = os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	if err := captiveportal.TemplateValidateZip(content); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return content, nil
}

func captivePortalTemplateUpload(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	content, err := captivePortalTemplateReadZip(args.String("file"))
	if err != nil {
		return err
	}
	var name = args.String("name")
	existing, err := api.TemplateGetByName(name)
	switch {
	case err == nil && !args.Bool("replace"):
		return fmt.Errorf("a template named %q exists already (%s), replace its content with upload ... replace", existing.Name, existing.Uuid)
	case err == nil:
		if err := api.TemplateSave(existing.Uuid, name, content); err != nil {
			return err
		}
		c.Infof("replaced the content of the template %q", name)
		c.Println(existing.Uuid)
		return nil
	case !coreapi.IsNotFound(err):
		return err
	}
	if err := api.TemplateSave("", name, content); err != nil {
		return err
	}
	saved, err := api.TemplateGetByName(name)
	if err != nil {
		return fmt.Errorf("the template was saved, but can not be found: %w", err)
	}
	c.Println(saved.Uuid)
	return nil
}

func captivePortalTemplateSet(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var content []byte
	if args.Has("file") {
		if content, err = captivePortalTemplateReadZip(args.String("file")); err != nil {
			return err
		}
	}
	var template, templates, selectErr = captivePortalTemplateSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	var name = template.Name
	if args.Has("name") {
		name = args.String("name")
		for _, other := range templates {
			if other.Uuid != template.Uuid && other.Name == name {
				return fmt.Errorf("another template named %q exists already (%s)", name, other.Uuid)
			}
		}
	}
	return api.TemplateSave(template.Uuid, name, content)
}

func captivePortalTemplateRemove(c *Context, args *Args) error {
	var api, err = captivePortalApi(c)
	if err != nil {
		return err
	}
	var template, _, selectErr = captivePortalTemplateSelect(c, api, args.String("item"))
	if selectErr != nil {
		return selectErr
	}
	zones, err := api.ZoneList("")
	if err != nil {
		return err
	}
	if users := captivePortalTemplateUsers(zones, template.Uuid); len(users) > 0 {
		return fmt.Errorf("the template %q is used by the zones %s, change their template= first", template.Name, strings.Join(users, ", "))
	}
	return api.TemplateRemove(template.Uuid)
}
