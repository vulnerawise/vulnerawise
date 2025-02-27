package cvss

import (
	"strings"
)

// IsAutomatable determines if a CVSS vector string is automatable.
// It returns a boolean indicating automatable status and the CVSS version (or "Unknown").
func IsAutomatable(cvssVector string) (bool, string) {
	var version, av, ac, pr, ui string

	// Determine the CVSS version based on known prefixes.
	if strings.HasPrefix(cvssVector, "CVSS:2.0") || strings.HasPrefix(cvssVector, "AV:") {
		version = "2.0"
	} else if strings.HasPrefix(cvssVector, "CVSS:3.0") || strings.HasPrefix(cvssVector, "CVSS:3.1") {
		version = "3.x"
	} else if strings.HasPrefix(cvssVector, "CVSS:4.0") {
		version = "4.0"
	} else {
		return false, "Unknown"
	}

	// Split the vector into components.
	parts := strings.Split(cvssVector, "/")
	for _, part := range parts {
		// Split each component into key and value.
		keyValue := strings.SplitN(part, ":", 2)
		if len(keyValue) != 2 {
			continue
		}
		// Trim spaces from key and value.
		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])
		switch key {
		case "AV":
			av = value
		case "AC":
			ac = value
		case "PR":
			pr = value
		case "UI":
			ui = value
		case "Au":
			// For CVSS 2.0, derive PR from the Au value.
			if version == "2.0" {
				if value == "N" {
					pr = "N"
				} else if value == "S" {
					pr = "L"
				} else {
					pr = "H"
				}
			}
		}
	}

	// A vector is considered automatable if it meets these criteria.
	if av == "N" && ac == "L" && pr == "N" && ui == "N" {
		return true, version
	}

	return false, version
}
