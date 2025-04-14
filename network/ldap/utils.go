package ldap

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const UnixTimestampStart int64 = 116444736000000000 // Monday, January 1, 1601 12:00:00 AM

func GetDomainFromDistinguishedName(distinguishedName string) string {
	domainParts := strings.Split(distinguishedName, ",")

	domain := ""
	for _, part := range domainParts {
		if strings.HasPrefix(part, "DC=") {
			domain += strings.TrimPrefix(part, "DC=") + "."
		}
	}

	domain = strings.TrimSuffix(domain, ".")

	return domain
}

func ConvertLDAPTimeStampToUnixTimeStamp(value string) int64 {
	convertedValue := int64(0)

	if len(value) != 0 {
		valueInt, err := strconv.ParseInt(value, 10, 64)

		if err != nil {
			fmt.Printf("[!] Error converting value to int64: %s\n", err)
			return convertedValue
		}

		if valueInt < UnixTimestampStart {
			// Typically for dates on year 1601
			convertedValue = 0
		} else {
			delta := int64((valueInt - UnixTimestampStart) * 100)
			convertedValue = int64(time.Unix(0, delta).Unix())
		}
	}

	return convertedValue
}

func ConvertLDAPDurationToSeconds(value string) int64 {
	convertedValue := int64(0)

	if len(value) != 0 {
		valueInt, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			fmt.Printf("[!] Error converting value to int64: %s\n", err)
			return convertedValue
		}

		if valueInt < 0 {
			valueInt = valueInt * int64(-1)
		}

		// Convert intervals of 100-nanoseconds to Seconds
		convertedValue = valueInt / int64(1e7)
	}

	return convertedValue
}

func ConvertSecondsToLDAPDuration(value int64) string {
	convertedValue := fmt.Sprintf("%d", value*int64(1e7))
	return convertedValue
}

func ConvertUnixTimeStampToLDAPTimeStamp(value time.Time) int64 {
	ldapvalue := value.Unix() * (1e7)
	ldapvalue = ldapvalue + UnixTimestampStart
	return int64(ldapvalue)
}
