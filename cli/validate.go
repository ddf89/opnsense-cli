package cli

import (
	"fmt"
	"net"
	"strconv"
)

// Validators for Arg.Validate. An empty value is accepted by all of them (it clears a field), use Required to
// demand a value

// ValidateIP accepts a single IPv4 or IPv6 address
func ValidateIP(value string) error {
	if value != "" && net.ParseIP(value) == nil {
		return fmt.Errorf("must be an IPv4 or IPv6 address, got %q", value)
	}
	return nil
}

// ValidateIPList accepts comma separated IPv4 or IPv6 addresses
func ValidateIPList(value string) error {
	for _, element := range splitList(value) {
		if err := ValidateIP(element); err != nil {
			return err
		}
	}
	return nil
}

// ValidateMACList accepts comma separated MAC addresses
func ValidateMACList(value string) error {
	for _, element := range splitList(value) {
		if _, err := net.ParseMAC(element); err != nil {
			return fmt.Errorf("must be a MAC address like aa:bb:cc:dd:ee:ff, got %q", element)
		}
	}
	return nil
}

// ValidatePort accepts a port number 1-65535
func ValidatePort(value string) error {
	return ValidateRange(1, 65535)(value)
}

// ValidateRange accepts whole numbers from min to max
func ValidateRange(min int, max int) func(string) error {
	return func(value string) error {
		if value == "" {
			return nil
		}
		var number, err = strconv.Atoi(value)
		if err != nil || number < min || number > max {
			return fmt.Errorf("must be a number from %d to %d, got %q", min, max, value)
		}
		return nil
	}
}
