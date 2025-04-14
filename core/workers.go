package core

import (
	"FindGPPPasswords/core/config"
	"FindGPPPasswords/core/crypto"
	"FindGPPPasswords/core/logger"
	"FindGPPPasswords/network/dns"
	"fmt"
	"sync"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

// SMBListFilesRecursivelyAndCallback lists files recursively in a given directory on an SMB share and executes a callback function for each file found.
//
// Parameters:
// - session: an active SMB connection.
// - share: the name of the SMB share to connect to.
// - dir: the directory within the share to start listing files from.
// - callback: a function to be called for each file found. The callback function takes the SMB connection, the share name, and the file path as arguments and returns an error.
//
// Returns:
// - err: an error if any occurs during the process.
//
// The function performs the following steps:
// 1. Connects to the specified SMB share.
// 2. Lists files in the specified directory.
// 3. Recursively explores subdirectories and applies the callback function to each file found.
//
// If the function encounters an error while connecting to the share or listing files, it logs the error and returns it. If access to a directory is denied, it logs the error and continues processing other directories.
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

// FindCPasswords searches for Group Policy Preference Passwords (GPP Passwords) in the SYSVOL share of a given domain controller.
// It performs the following steps:
// 1. Resolves the DNS hostname to an IP address.
// 2. Establishes an SMB connection to the target IP address.
// 3. Recursively searches for XML files in the SYSVOL share.
// 4. Processes the found XML files to extract GPP Passwords.
//
// Parameters:
// - dnsHostname: A slice of strings containing the DNS hostnames of the domain controller.
// - config: The configuration settings for the connection and search.
// - testResults: A pointer to the structure that holds the found Group Policy Preference Passwords.
//
// Returns:
// - An error if any step of the process fails, otherwise nil.
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

// RunWorkers starts a specified number of worker goroutines to process tasks from the channel.
// It takes a slice of LDAP entries, a configuration, and a pointer to the found Group Policy Preference Passwords.
func RunWorkers(maxThreads int, domainControllersResults []*ldapv3.Entry, config config.Config, gpppfound *crypto.GroupPolicyPreferencePasswordsFound) {
	sem := make(chan struct{}, config.Threads)

	maxLenOfAdvancementString := len(fmt.Sprintf("%d", len(domainControllersResults)))
	advancementFormatString := fmt.Sprintf("(%%0%dd/%%0%dd)", maxLenOfAdvancementString, maxLenOfAdvancementString)

	var wg sync.WaitGroup

	for k, entry := range domainControllersResults {
		wg.Add(1)

		// acquire semaphore
		sem <- struct{}{}

		// start long running go routine
		go func(id int, entry *ldapv3.Entry) {
			defer wg.Done()

			advancementString := fmt.Sprintf(advancementFormatString, k+1, len(domainControllersResults))

			logger.Info(fmt.Sprintf("%s Searching for GPPPasswords in '\\\\%s\\SYSVOL\\' ... ", advancementString, entry.GetEqualFoldAttributeValues("dnsHostname")[0]))

			err := FindCPasswords(
				entry.GetEqualFoldAttributeValues("dnsHostname"),
				config,
				gpppfound,
			)

			if err != nil {
				logger.Warn(fmt.Sprintf("%s Error: %s", advancementString, err))
			} else {
				if config.Debug {
					logger.Info(fmt.Sprintf("%s Search in '\\\\%s\\SYSVOL\\' has finished successfully. ", advancementString, entry.GetEqualFoldAttributeValues("dnsHostname")[0]))
				}
			}

			// release semaphore
			<-sem
		}(k, entry)
	}

	wg.Wait()
}
