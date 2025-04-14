package windows

// UserAccountControl
// Src: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
const (
	UAF_SCRIPT                         = 0x00000001
	UAF_ACCOUNT_DISABLED               = 0x00000002
	UAF_HOMEDIR_REQUIRED               = 0x00000008
	UAF_LOCKOUT                        = 0x00000010
	UAF_PASSWD_NOTREQD                 = 0x00000020
	UAF_PASSWD_CANT_CHANGE             = 0x00000040
	UAF_ENCRYPTED_TEXT_PWD_ALLOWED     = 0x00000080
	UAF_TEMP_DUPLICATE_ACCOUNT         = 0x00000100
	UAF_NORMAL_ACCOUNT                 = 0x00000200
	UAF_INTERDOMAIN_TRUST_ACCOUNT      = 0x00000800
	UAF_WORKSTATION_TRUST_ACCOUNT      = 0x00001000
	UAF_SERVER_TRUST_ACCOUNT           = 0x00002000
	UAF_DONT_EXPIRE_PASSWORD           = 0x00010000
	UAF_MNS_LOGON_ACCOUNT              = 0x00020000
	UAF_SMARTCARD_REQUIRED             = 0x00040000
	UAF_TRUSTED_FOR_DELEGATION         = 0x00080000
	UAF_NOT_DELEGATED                  = 0x00100000
	UAF_USE_DES_KEY_ONLY               = 0x00200000
	UAF_DONT_REQ_PREAUTH               = 0x00400000
	UAF_PASSWORD_EXPIRED               = 0x00800000
	UAF_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000
	UAF_PARTIAL_SECRETS_ACCOUNT        = 0x04000000
)
