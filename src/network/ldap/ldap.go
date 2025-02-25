package ldap

import (
	"FindGPPPasswords/core/logger"

	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type Entry ldap.Entry

const (
	ScopeBaseObject   = ldap.ScopeBaseObject
	ScopeSingleLevel  = ldap.ScopeSingleLevel
	ScopeChildren     = ldap.ScopeChildren
	ScopeWholeSubtree = ldap.ScopeWholeSubtree
)

type Session struct {
	// Network
	host       string
	port       int
	connection *ldap.Conn
	// Credentials
	domain   string
	username string
	password string
	// Config
	debug    bool
	useldaps bool
}

type Domain struct {
	NetBIOSName       string `json:"netbiosName"`
	DNSName           string `json:"dnsName"`
	DistinguishedName string `json:"distinguishedName"`
	SID               string `json:"sid"`
}

func (s *Session) InitSession(host string, port int, useldaps bool, domain string, username string, password string, debug bool) error {
	// Check if TCP port is valid
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number. Port must be in the range 1-65535")
	}

	// Network
	s.host = host
	s.port = port
	// Credentials
	s.domain = domain
	s.username = username
	s.password = password
	// Config
	s.useldaps = useldaps
	s.debug = debug

	return nil
}

func (s *Session) Connect() error {
	// Set up LDAP connection
	var ldapConnection *ldap.Conn
	var err error

	// Check if LDAPS is available
	if s.useldaps {
		// LDAPS connection
		ldapConnection, err = ldap.DialURL(
			fmt.Sprintf("ldaps://%s:%d", s.host, s.port),
			ldap.DialWithTLSConfig(
				&tls.Config{
					InsecureSkipVerify: true,
				},
			),
		)
		if err != nil {
			return fmt.Errorf("error connecting to LDAPS server: %w", err)
		}
	} else {
		// Regular LDAP connection
		ldapConnection, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", s.host, s.port))
		if err != nil {
			return fmt.Errorf("error connecting to LDAP server: %w", err)
		}
	}

	// Bind with credentials if provided
	if len(s.password) > 0 {
		// Binding with credentials
		err = ldapConnection.Bind(fmt.Sprintf("%s@%s", s.username, s.domain), s.password)
		if err != nil {
			return fmt.Errorf("error binding with credentials: %w", err)
		}
	} else {
		// Unauthenticated Bind
		bindDN := ""
		if s.username != "" {
			bindDN = fmt.Sprintf("%s@%s", s.username, s.domain)
		}

		err = ldapConnection.UnauthenticatedBind(bindDN)
		if err != nil {
			return fmt.Errorf("error performing unauthenticated bind: %w", err)
		}
	}

	s.connection = ldapConnection

	return nil
}

func (s *Session) ReConnect() error {
	s.connection.Close()
	return s.Connect()
}

func GetRootDSE(ldapSession *Session) *ldap.Entry {
	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN blank
		"",
		// Scope Base
		ldap.ScopeBaseObject,
		// DerefAliases
		ldap.NeverDerefAliases,
		// SizeLimit
		1,
		// TimeLimit
		0,
		// TypesOnly
		false,
		// Search filter
		"(objectClass=*)",
		// Attributes to retrieve
		[]string{"*"},
		// Controls
		nil,
	)

	// Perform LDAP search
	searchResult, err := ldapSession.connection.Search(searchRequest)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error searching LDAP: %s", err))
		return nil
	}

	return searchResult.Entries[0]
}

func RawQuery(ldapSession *Session, baseDN string, query string, attributes []string, scope int) []*ldap.Entry {
	debug := false

	// Parsing parameters
	if len(baseDN) == 0 {
		baseDN = "defaultNamingContext"
	}
	if strings.ToLower(baseDN) == "defaultnamingcontext" {
		rootDSE := GetRootDSE(ldapSession)
		if debug {
			logger.Debug(fmt.Sprintf("Using defaultNamingContext %s ...\n", rootDSE.GetAttributeValue("defaultNamingContext")))
		}
		baseDN = rootDSE.GetAttributeValue("defaultNamingContext")
	} else if strings.ToLower(baseDN) == "configurationnamingcontext" {
		rootDSE := GetRootDSE(ldapSession)
		if debug {
			logger.Debug(fmt.Sprintf("Using configurationNamingContext %s ...\n", rootDSE.GetAttributeValue("configurationNamingContext")))
		}
		baseDN = rootDSE.GetAttributeValue("configurationNamingContext")
	} else if strings.ToLower(baseDN) == "schemanamingcontext" {
		rootDSE := GetRootDSE(ldapSession)
		if debug {
			logger.Debug(fmt.Sprintf("Using schemaNamingContext CN=Schema,%s ...\n", rootDSE.GetAttributeValue("configurationNamingContext")))
		}
		baseDN = fmt.Sprintf("CN=Schema,%s", rootDSE.GetAttributeValue("configurationNamingContext"))

	}

	if (scope != ldap.ScopeBaseObject) && (scope != ldap.ScopeSingleLevel) && (scope != ldap.ScopeWholeSubtree) {
		scope = ldap.ScopeWholeSubtree
	}

	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN
		baseDN,
		// Scope
		scope,
		// DerefAliases
		ldap.NeverDerefAliases,
		// SizeLimit
		0,
		// TimeLimit
		0,
		// TypesOnly
		false,
		// Search filter
		query,
		// Attributes to retrieve
		attributes,
		// Controls
		nil,
	)

	// Perform LDAP search
	searchResult, err := ldapSession.connection.SearchWithPaging(searchRequest, 1000)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error searching LDAP: %s", err))
		return nil
	}

	return searchResult.Entries
}

func QueryBaseObject(ldapSession *Session, baseDN string, query string, attributes []string) []*ldap.Entry {
	entries := RawQuery(ldapSession, baseDN, query, attributes, ldap.ScopeBaseObject)
	return entries
}

func QuerySingleLevel(ldapSession *Session, baseDN string, query string, attributes []string) []*ldap.Entry {
	entries := RawQuery(ldapSession, baseDN, query, attributes, ldap.ScopeSingleLevel)
	return entries
}

func QueryWholeSubtree(ldapSession *Session, baseDN string, query string, attributes []string) []*ldap.Entry {
	entries := RawQuery(ldapSession, baseDN, query, attributes, ldap.ScopeWholeSubtree)
	return entries
}

func QueryAllNamingContexts(ldapSession *Session, query string, attributes []string, scope int) []*ldap.Entry {
	// Fetch the RootDSE entry to get the naming contexts
	rootDSE := GetRootDSE(ldapSession)
	if rootDSE == nil {
		// logger.Warn("Could not retrieve RootDSE.")
		return nil
	}

	// Retrieve the namingContexts attribute
	namingContexts := rootDSE.GetAttributeValues("namingContexts")
	if len(namingContexts) == 0 {
		//logger.Warn("No naming contexts found.")
		return nil
	}

	// Store all entries from all naming contexts
	var allEntries []*ldap.Entry

	// Iterate over each naming context and perform the query
	for _, context := range namingContexts {
		entries := RawQuery(ldapSession, context, query, attributes, scope)
		if entries != nil {
			allEntries = append(allEntries, entries...)
		}
	}

	return allEntries
}

func CanLogin(ldapSession *Session) (bool, error) {
	// Set up LDAP connection
	var ldapConnection *ldap.Conn
	var err error

	if ldapSession.useldaps {
		ldapConnection, err = ldap.DialURL(
			fmt.Sprintf("ldaps://%s:%d", ldapSession.host, ldapSession.port),
			ldap.DialWithTLSConfig(
				&tls.Config{
					InsecureSkipVerify: true,
				},
			),
		)
	} else {
		ldapConnection, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", ldapSession.host, ldapSession.port))
	}

	if err != nil {
		return false, err
	}
	defer ldapConnection.Close()

	// Bind with provided credentials
	err = ldapConnection.Bind(fmt.Sprintf("%s\\%s", ldapSession.domain, ldapSession.username), ldapSession.password)
	if err != nil {
		return false, err
	}

	return true, nil
}
