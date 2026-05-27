package portscan

// Curated common-UDP-services list. R-13 picks ports the engine has a
// dedicated service probe for plus a handful of well-known services
// where an empty UDP probe is unlikely to elicit a response but the
// port is still worth listing.
//
// Order roughly matches nmap-services frequency. We carry 100 entries
// so `--top 100 --udp` does something meaningful, but the engine
// defaults to TopUDPPorts(50) — the long tail of UDP services drops
// off sharply after the first ~30 and the extra ports rarely yield
// information without a custom probe.
var nmapUDPTop100 = []int{
	53,    // DNS
	123,   // NTP
	161,   // SNMP
	137,   // NetBIOS Name Service
	138,   // NetBIOS Datagram
	500,   // ISAKMP / IKE
	5353,  // mDNS
	1900,  // SSDP / UPnP
	445,   // SMB over UDP (rare)
	67,    // DHCP server
	68,    // DHCP client
	69,    // TFTP
	514,   // syslog
	520,   // RIP
	5060,  // SIP
	5061,  // SIP-TLS
	1434,  // MSSQL Monitor
	1701,  // L2TP
	4500,  // IPsec NAT-T
	631,   // IPP (CUPS)
	162,   // SNMP trap
	111,   // RPCbind
	2049,  // NFS
	6,     // IPP-discovery
	17,    // QOTD
	19,    // chargen
	49,    // TACACS
	88,    // Kerberos
	115,   // SFTP (rare UDP)
	135,   // MS-RPC EPMAP
	139,   // NetBIOS Session
	177,   // X Display Manager
	389,   // LDAP
	427,   // SLP
	443,   // QUIC / HTTP/3
	464,   // Kerberos kpasswd
	548,   // AFP-over-IP
	623,   // IPMI / ASF-RMCP
	636,   // LDAPS
	853,   // DoT
	902,   // VMware Auth
	989,   // FTPS-data
	990,   // FTPS
	993,   // IMAPS
	995,   // POP3S
	1025,  // Blackjack / NetMeeting
	1026,  //
	1027,  //
	1028,  //
	1029,  //
	1030,  //
	1194,  // OpenVPN
	1645,  // RADIUS auth (legacy)
	1646,  // RADIUS acct (legacy)
	1812,  // RADIUS auth
	1813,  // RADIUS acct
	2000,  // Cisco SCCP
	2222,  // EtherNet/IP
	3389,  // RDP UDP
	3478,  // STUN / TURN
	3702,  // WS-Discovery
	3784,  // BFD
	4444,  // KRB524 / many
	4500,  //  (dup; harmless)
	5000,  // UPnP control point
	5004,  // RTP
	5005,  // RTP control
	5247,  // CAPWAP control
	5269,  // XMPP server
	5349,  // STUN-TLS
	5631,  // pcAnywhere
	5632,  // pcAnywhere status
	5683,  // CoAP
	6000,  // X11
	7777,  // many
	8000,  // various
	8080,  // QUIC
	8081,  // alt-HTTP
	8443,  // QUIC HTTPS
	8888,  // alt-HTTP
	9000,  // various
	9001,  // Tor / others
	9100,  // JetDirect (printers)
	10000, // Webmin / many
	17500, // Dropbox LAN sync
	19132, // Minecraft Bedrock
	19133, // Minecraft Bedrock IPv6
	27015, // Source engine games
	27016, // Source engine games
	27017, // MongoDB (default is TCP; UDP rare)
	37,    // time
	53,    // dup; harmless if duplicates
	123,
	161,
	137,
	138,
	500,
	5353,
	1900,
}

// TopUDPPorts returns the first n entries from the curated UDP top
// list. Caps at the length of the embedded list. n ≤ 0 returns nil.
//
// Deduplicates on the fly because the source list has a few intentional
// repeats near the tail (the long tail of UDP services is so sparse
// that the curated list pads with re-listed top-tier services rather
// than diluting with services we don't probe).
func TopUDPPorts(n int) []int {
	if n <= 0 {
		return nil
	}
	if n > len(nmapUDPTop100) {
		n = len(nmapUDPTop100)
	}
	out := make([]int, 0, n)
	seen := make(map[int]bool, n)
	for _, p := range nmapUDPTop100 {
		if len(out) == n {
			break
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
