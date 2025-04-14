package ldap

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ParseSIDFromBytes parses raw bytes representing an SID and returns the SID string
func ParseSIDFromBytes(sidBytes []byte) string {
	debug := false

	// Ensure the SID has a valid format
	if len(sidBytes) < 8 || sidBytes[0] != 1 {
		return ""
	}

	// Extract revisionLevel
	revisionLevel := int(sidBytes[0])
	if debug {
		fmt.Printf("revisionLevel       = 0x%02x\n", revisionLevel)
		fmt.Println(sidBytes[1:])
	}
	// Extract subAuthorityCount
	subAuthorityCount := int(sidBytes[1])
	if debug {
		fmt.Printf("subAuthorityCount   = 0x%02x\n", subAuthorityCount)
		fmt.Println(sidBytes[2:])
	}

	// Extract identifierAuthority
	identifierAuthority := uint64(sidBytes[2+0]) << 40
	identifierAuthority |= uint64(sidBytes[2+1]) << 32
	identifierAuthority |= uint64(sidBytes[2+2]) << 24
	identifierAuthority |= uint64(sidBytes[2+3]) << 16
	identifierAuthority |= uint64(sidBytes[2+4]) << 8
	identifierAuthority |= uint64(sidBytes[2+5])
	if debug {
		fmt.Printf("identifierAuthority = 0x%08x\n", identifierAuthority)
		fmt.Println(sidBytes[8:])
	}

	// Extract subAuthorities
	subAuthorities := make([]string, 0)
	for k := 0; k < subAuthorityCount-1; k++ {
		subAuthority := binary.LittleEndian.Uint32(sidBytes[8+(4*k):])
		subAuthorities = append(subAuthorities, fmt.Sprintf("%d", subAuthority))
		if debug {
			fmt.Printf("subAuthority        = 0x%08x\n", subAuthority)
			fmt.Println(sidBytes[8+(4*k):])
		}
	}

	// Parse the relativeIdentifier
	relativeIdentifier := binary.LittleEndian.Uint32(sidBytes[8+((subAuthorityCount-1)*4):])
	if debug {
		fmt.Printf("relativeIdentifier  = 0x%08x\n", relativeIdentifier)
		fmt.Println(sidBytes[8+((subAuthorityCount-1)*4):])
	}

	// Construct the parsed SID
	parsedSID := fmt.Sprintf("S-%d-%d-%s-%d", revisionLevel, identifierAuthority, strings.Join(subAuthorities, "-"), relativeIdentifier)

	return parsedSID
}
