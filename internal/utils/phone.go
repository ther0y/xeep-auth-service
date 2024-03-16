package utils

import "regexp"

var iranMobileRegex = regexp.MustCompile(`(\+98|0|98)?(9\d{9})`)

func NormalizePhone(phone string) string {
	return iranMobileRegex.ReplaceAllString(phone, "0098$2$3$4")
}
