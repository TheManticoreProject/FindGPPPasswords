package windows

// sAMAccountType Values
// Src: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e742be45-665d-4576-b872-0bc99d1e1fbe
const (
	SAM_DOMAIN_OBJECT             = 0x00000000
	SAM_GROUP_OBJECT              = 0x10000000
	SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
	SAM_ALIAS_OBJECT              = 0x20000000
	SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
	SAM_USER_OBJECT               = 0x30000000
	SAM_MACHINE_ACCOUNT           = 0x30000001
	SAM_TRUST_ACCOUNT             = 0x30000002
	SAM_APP_BASIC_GROUP           = 0x40000000
	SAM_APP_QUERY_GROUP           = 0x40000001
)
