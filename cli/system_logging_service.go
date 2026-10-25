package cli

// /system/logging/service: the syslog-ng service

func init() {
	var menu = Root.Menu("system/logging/service")
	menu.Help = "the logging service (syslog-ng)"
	menu.Add(
		&Command{Name: "status", Help: "show whether the logging service is running", Run: systemLoggingServiceStatus},
		&Command{Name: "restart", Help: "restart the logging service", Run: systemLoggingServiceRestart},
		&Command{
			Name: "reconfigure",
			Help: "apply the saved logging configuration (regenerate the syslog-ng config and reload it)",
			Run:  systemLoggingServiceReconfigure,
		},
	)
}

func systemLoggingServiceStatus(c *Context, _ *Args) error {
	var api, err = systemLoggingApi(c)
	if err != nil {
		return err
	}
	var status, statusErr = api.LoggingServiceStatus()
	if statusErr != nil {
		return statusErr
	}
	c.Fields([][2]string{{"status", status}})
	return nil
}

func systemLoggingServiceRestart(c *Context, _ *Args) error {
	var api, err = systemLoggingApi(c)
	if err != nil {
		return err
	}
	return api.LoggingServiceRestart()
}

func systemLoggingServiceReconfigure(c *Context, _ *Args) error {
	var api, err = systemLoggingApi(c)
	if err != nil {
		return err
	}
	return api.LoggingServiceReconfigure()
}
