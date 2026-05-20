package main

import "strings"

type CDNMatch struct {
	Provider   string
	Confidence string
	Reason     string
}

var cdnByASN = map[string]string{
	"13335":  "Cloudflare",
	"15169":  "Google",
	"54113":  "Fastly",
	"20940":  "Akamai",
	"16625":  "Akamai",
	"21342":  "Akamai",
	"32934":  "Meta",
	"16509":  "AWS",
	"14618":  "AWS",
	"8075":   "Microsoft",
	"714":    "Apple",
	"2906":   "Netflix",
	"19551":  "Imperva",
	"200325": "Bunny",
	"60068":  "Datacamp",
}

type ptrCDNPattern struct {
	Suffix   string
	Provider string
	Label    string
}

var cdnByPTR = []ptrCDNPattern{
	{Suffix: ".cloudflare.com", Provider: "Cloudflare", Label: "cloudflare.com PTR"},
	{Suffix: ".cloudflare.net", Provider: "Cloudflare", Label: "cloudflare.net PTR"},
	{Suffix: ".cloudfront.net", Provider: "AWS", Label: "cloudfront.net PTR"},
	{Suffix: ".1e100.net", Provider: "Google", Label: "1e100.net PTR"},
	{Suffix: ".googleusercontent.com", Provider: "Google", Label: "googleusercontent.com PTR"},
	{Suffix: ".akamaiedge.net", Provider: "Akamai", Label: "akamaiedge.net PTR"},
	{Suffix: ".akamai-edge.com", Provider: "Akamai", Label: "akamai-edge.com PTR"},
	{Suffix: ".akamaihd.net", Provider: "Akamai", Label: "akamaihd.net PTR"},
	{Suffix: ".akamai.net", Provider: "Akamai", Label: "akamai.net PTR"},
	{Suffix: ".edgekey.net", Provider: "Akamai", Label: "edgekey.net PTR"},
	{Suffix: ".edgesuite.net", Provider: "Akamai", Label: "edgesuite.net PTR"},
	{Suffix: ".fastly.net", Provider: "Fastly", Label: "fastly.net PTR"},
	{Suffix: ".fastlylb.net", Provider: "Fastly", Label: "fastlylb.net PTR"},
	{Suffix: ".fbcdn.net", Provider: "Meta", Label: "fbcdn.net PTR"},
	{Suffix: ".facebook.com", Provider: "Meta", Label: "facebook.com PTR"},
	{Suffix: ".tfbnw.net", Provider: "Meta", Label: "tfbnw.net PTR"},
	{Suffix: ".azureedge.net", Provider: "Microsoft", Label: "azureedge.net PTR"},
	{Suffix: ".trafficmanager.net", Provider: "Microsoft", Label: "trafficmanager.net PTR"},
	{Suffix: ".hwcdn.net", Provider: "StackPath", Label: "hwcdn.net PTR"},
	{Suffix: ".cdn77.org", Provider: "CDN77", Label: "cdn77.org PTR"},
}

func classifyCDN(asn *ASNInfo, ptrs []string) CDNMatch {
	asnProvider := ""
	if asn != nil {
		asnProvider = cdnByASN[normalizeASN(asn.ASN)]
	}
	ptrProvider, ptrReason := cdnProviderFromPTR(ptrs)

	switch {
	case asnProvider != "" && ptrProvider != "" && asnProvider == ptrProvider:
		return CDNMatch{
			Provider:   asnProvider,
			Confidence: "high",
			Reason:     "ASN match + " + ptrReason,
		}
	case asnProvider != "" && ptrProvider != "":
		return CDNMatch{
			Provider:   asnProvider,
			Confidence: "medium",
			Reason:     "ASN match; PTR suggests " + ptrProvider,
		}
	case asnProvider != "":
		return CDNMatch{
			Provider:   asnProvider,
			Confidence: "medium",
			Reason:     "ASN match",
		}
	case ptrProvider != "":
		return CDNMatch{
			Provider:   ptrProvider,
			Confidence: "medium",
			Reason:     ptrReason,
		}
	default:
		return CDNMatch{}
	}
}

func normalizeASN(asn string) string {
	asn = strings.TrimSpace(strings.ToUpper(asn))
	asn = strings.TrimPrefix(asn, "AS")
	return asn
}

func cdnProviderFromPTR(ptrs []string) (string, string) {
	for _, ptr := range ptrs {
		host := "." + strings.Trim(strings.ToLower(strings.TrimSpace(ptr)), ".")
		for _, pattern := range cdnByPTR {
			if strings.HasSuffix(host, pattern.Suffix) {
				return pattern.Provider, pattern.Label
			}
		}
	}
	return "", ""
}
