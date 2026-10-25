package cli

import (
	"fmt"
	coreapi "opnsense-cli/opnsense/api"
	"strconv"
	"strings"
)

// Select finds the item a selector refers to, the way RouterOS refers to items:
//   - a number: the row with this "#" in the last print of this menu, or, when there was no print in this
//     session (one-shot commands), the item at this position of items, which must be in print order
//   - a uuid
//   - a name: exact, case-insensitive match against names(item), e.g. the FQDN of a host override
//
// Not found is a *NotFoundError, a name matching several items a *TooManyFoundError listing their uuids
func Select[T any](c *Context, selector string, items []T, uuid func(T) string, names func(T) []string) (T, error) {
	var zero T
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return zero, fmt.Errorf("no item given, use the # of print, the uuid or the name")
	}

	if index, err := strconv.Atoi(selector); err == nil {
		if printed, hasPrint := c.Session.lastPrint[c.Menu.Path()]; hasPrint {
			if index < 0 || index >= len(printed) {
				return zero, &coreapi.NotFoundError{Name: fmt.Sprintf("item #%d, the last print showed %s", index, itemCount(len(printed)))}
			}
			for _, item := range items {
				if uuid(item) == printed[index] {
					return item, nil
				}
			}
			return zero, &coreapi.NotFoundError{Name: fmt.Sprintf("item #%d (%s), it was removed since the last print", index, printed[index])}
		}
		if index < 0 || index >= len(items) {
			return zero, &coreapi.NotFoundError{Name: fmt.Sprintf("item #%d, the list has %s", index, itemCount(len(items)))}
		}
		return items[index], nil
	}

	for _, item := range items {
		if strings.EqualFold(uuid(item), selector) {
			return item, nil
		}
	}

	var matches []T
	for _, item := range items {
		for _, name := range names(item) {
			if name != "" && strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(selector, ".")) {
				matches = append(matches, item)
				break
			}
		}
	}
	switch len(matches) {
	case 0:
		return zero, &coreapi.NotFoundError{Name: fmt.Sprintf("%q, use the # of print, the uuid or the name", selector)}
	case 1:
		return matches[0], nil
	default:
		var uuids = make([]string, 0, len(matches))
		for _, match := range matches {
			uuids = append(uuids, uuid(match))
		}
		return zero, &coreapi.TooManyFoundError{Name: fmt.Sprintf("%q matches %d items (%s), select one by its # from print or its uuid",
			selector, len(matches), strings.Join(uuids, ", "))}
	}
}

// itemCount renders a number of items like "1 item" or "3 items"
func itemCount(n int) string {
	if n == 1 {
		return "1 item"
	}
	return fmt.Sprintf("%d items", n)
}
