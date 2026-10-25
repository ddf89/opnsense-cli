package cli

import (
	"bytes"
	"encoding/json"
	"opnsense-cli/opnsense/api/system"
	"strings"
)

// /system/license: the product and copyright of Lobby > License, and the license of any package. The page's
// license text itself is static (the BSD 2-clause license) and has no API, the product details come from
// api/core/firmware/status, package licenses from api/core/firmware/license/<package>

func init() {
	var menu = Root.Menu("system/license")
	menu.Help = "product copyright and package licenses (Lobby > License)"
	menu.Add(&Command{Name: "print", Help: "show the product, its copyright and license information",
		Long: `With package= it prints the license of that package instead (installed or available, see
/system/firmware/package print).`,
		Args: []Arg{
			{Name: "package", Help: "print the license of this package", Validate: system.FirmwareValidatePackage,
				Complete: systemFirmwarePackageComplete(systemFirmwarePackageKindPackage)},
			{Name: "json", Type: Bool, Help: "print the product details as one JSON object"},
		},
		Run: systemLicensePrint})
}

func systemLicensePrint(c *Context, args *Args) error {
	var api, err = systemServiceApi(c)
	if err != nil {
		return err
	}
	if args.Has("package") {
		var license, licenseErr = api.FirmwarePackageLicense(args.String("package"))
		if licenseErr != nil {
			return licenseErr
		}
		c.Println(strings.TrimRight(license, "\n"))
		return nil
	}
	var status, statusErr = api.FirmwareStatus()
	if statusErr != nil {
		return statusErr
	}
	var product = status.Product
	var subscription = ""
	if trimmed := bytes.TrimSpace(product.License); len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("[]")) &&
		!bytes.Equal(trimmed, []byte("{}")) && !bytes.Equal(trimmed, []byte("null")) {
		subscription = string(trimmed)
	}
	if args.Bool("json") {
		var object = map[string]any{
			"product": product.Name, "version": product.Version, "nickname": product.Nickname,
			"copyright_years": product.CopyrightYears, "copyright_owner": product.CopyrightOwner,
			"copyright_url": product.CopyrightUrl, "website": product.Website, "email": product.Email,
		}
		if subscription != "" {
			object["license"] = json.RawMessage(subscription)
		}
		return c.JSON(object)
	}
	var fields = [][2]string{
		{"product", strings.TrimSpace(product.Name + " " + product.Version)},
		{"nickname", product.Nickname},
		{"copyright", strings.TrimSpace("(c) " + product.CopyrightYears + " " + product.CopyrightOwner)},
		{"copyright-url", product.CopyrightUrl},
		{"website", product.Website},
	}
	if subscription != "" {
		fields = append(fields, [2]string{"license", subscription})
	}
	c.Fields(fields)
	return nil
}
