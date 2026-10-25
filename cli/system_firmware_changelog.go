package cli

import (
	"html"
	"opnsense-cli/opnsense/api/system"
	"regexp"
	"strings"
)

// /system/firmware/changelog: the release notes of System > Firmware > Changelog. The list is downloaded by a check
// (/system/firmware check), items are selected by the # of print or the version

func init() {
	var menu = Root.Menu("system/firmware/changelog")
	menu.Help = "release notes (System > Firmware > Changelog)"
	menu.Add(
		&Command{Name: "print", Help: "list the releases with a changelog, newest first",
			Args: []Arg{
				{Name: "json", Type: Bool, Help: "one JSON object per line"},
				{Name: "search", Help: "only versions or series containing this text"},
			},
			Run: systemFirmwareChangelogPrint},
		&Command{Name: "show", Help: "print the changelog of one release as text",
			Args: []Arg{
				{Name: "item", Help: "the # or version (like 26.7.7) of the release", Positional: true, Required: true,
					Complete: systemFirmwareChangelogComplete},
				{Name: "html", Type: Bool, Help: "print the changelog as the API returns it (HTML)"},
			},
			Run: systemFirmwareChangelogShow},
	)
}

func systemFirmwareChangelogVersion(item system.FirmwareChangelogItem) string {
	return item.Version
}

func systemFirmwareChangelogNames(item system.FirmwareChangelogItem) []string {
	return []string{item.Version}
}

func systemFirmwareChangelogComplete(c *Context) []string {
	var api, err = systemServiceApi(c)
	if err != nil {
		return nil
	}
	var info, infoErr = api.FirmwareInfo()
	if infoErr != nil {
		return nil
	}
	var versions = make([]string, 0, len(info.Changelogs))
	for _, item := range info.Changelogs {
		versions = append(versions, item.Version)
	}
	return versions
}

func systemFirmwareChangelogPrint(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var info, infoErr = api.FirmwareInfo()
	if infoErr != nil {
		return infoErr
	}
	var items []system.FirmwareChangelogItem
	for _, item := range info.Changelogs {
		if !args.Has("search") || strings.Contains(item.Version, args.String("search")) || strings.Contains(item.Series, args.String("search")) {
			items = append(items, item)
		}
	}
	if len(info.Changelogs) == 0 {
		c.Infof(`no changelogs yet, "/system/firmware check" downloads them`)
	}
	if args.Bool("json") {
		for _, item := range items {
			if err := c.JSON(item); err != nil {
				return err
			}
		}
		return nil
	}
	var rows = make([][]string, len(items))
	var versions = make([]string, len(items))
	for i, item := range items {
		var installed = ""
		if item.Version == info.ProductVersion {
			installed = "yes"
		}
		rows[i] = []string{item.Version, item.Series, item.Date, installed}
		versions[i] = item.Version
	}
	c.Items([]string{"VERSION", "SERIES", "DATE", "INSTALLED"}, rows, versions)
	return nil
}

func systemFirmwareChangelogShow(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	var version = args.String("item")
	// a # needs the list, a version is asked for directly (also releases the list does not show)
	if systemFirmwareIsIndex(version) {
		var info, infoErr = api.FirmwareInfo()
		if infoErr != nil {
			return infoErr
		}
		var item, selectErr = Select(c, version, info.Changelogs, systemFirmwareChangelogVersion, systemFirmwareChangelogNames)
		if selectErr != nil {
			return selectErr
		}
		version = item.Version
	} else if err := system.FirmwareValidateVersion(version); err != nil {
		return err
	}
	var changelog, changelogErr = api.FirmwareChangelog(version)
	if changelogErr != nil {
		return changelogErr
	}
	if args.Bool("html") {
		c.Println(changelog.Html)
		return nil
	}
	c.Printf("%s (%s)\n\n", changelog.Version, changelog.Date)
	c.Println(systemFirmwareHtmlText(changelog.Html))
	return nil
}

var (
	systemFirmwareHtmlLink  = regexp.MustCompile(`(?is)<a\s[^>]*href="([^"]*)"[^>]*>(.*?)</a>`)
	systemFirmwareHtmlTag   = regexp.MustCompile(`(?s)<[^>]*>`)
	systemFirmwareHtmlBreak = regexp.MustCompile(`(?i)<br\s*/?>`)
	systemFirmwareHtmlBlank = regexp.MustCompile(`\n{3,}`)
)

// systemFirmwareHtmlText renders the changelog HTML (p, ul/li, br, a) as plain text: paragraphs separated by a
// blank line, list items as "- item", links as "text (url)"
func systemFirmwareHtmlText(source string) string {
	var text = strings.NewReplacer("\r", "", "\n", " ").Replace(source)
	text = systemFirmwareHtmlLink.ReplaceAllString(text, "$2 ($1)")
	text = systemFirmwareHtmlBreak.ReplaceAllString(text, "\n")
	text = strings.NewReplacer("<li>", "\n- ", "</li>", "", "<ul>", "\n", "</ul>", "\n\n", "<p>", "", "</p>", "\n\n").Replace(text)
	text = systemFirmwareHtmlTag.ReplaceAllString(text, "")
	text = html.UnescapeString(text)
	var lines = strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	text = systemFirmwareHtmlBlank.ReplaceAllString(strings.Join(lines, "\n"), "\n\n")
	return strings.TrimSpace(text)
}
