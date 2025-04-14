package dns

import (
	"context"
	"net"
	"strings"
	"time"
)

// DNSLookup performs a DNS lookup of a hostname (FQDN or hostname) to a specified DNS server.
func DNSLookup(hostname string, dnsServer string) []string {
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(5000),
			}
			return d.DialContext(ctx, network, dnsServer)
		},
	}
	ip, _ := r.LookupHost(context.Background(), hostname)

	return ip
}

// // Search for DNS servers in the domain
// dnsServers := ldap.GetDomainDNSServers(ldapSession)
// if len(dnsServers) != 0 {
// 	if config.Debug {
// 		if config.Debug {
// 			logger.Debug(fmt.Sprintf("Found DNS servers (%d):", len(dnsServers)))
// 		}
// 		for _, distinguishedName := range dnsServers {
// 			if config.Debug {
// 				logger.Debug(fmt.Sprintf("| %s", distinguishedName))
// 			}
// 		}
// 	}
// } else {
// 	dnsServers = []string{}
// 	dnsServers = append(dnsServers, ldap.GetPrincipalDomainController(ldapSession, config.Credentials.Domain))
// }
