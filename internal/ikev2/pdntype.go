// Added by itskimffs (2026-10), see NOTICE: subscribed PDN type from SWm limits the PDN type on S2b.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import "fmt"

// Subscribed PDN types in the APN-Configuration (TS 29.272 §7.3.62).
const (
	subPDNIPv4       uint8 = 0
	subPDNIPv6       uint8 = 1
	subPDNIPv4v6     uint8 = 2
	subPDNIPv4OrIPv6 uint8 = 3

	// notifyPDNConnectionRejection is the Private Notify Message - Error Type
	// for a PDN connection the network does not accept (TS 24.302 §8.1.2.2,
	// §7.4.1.2).
	notifyPDNConnectionRejection uint16 = 8192
)

// pdnFamilies returns the IP families of the PDN connection: those the UE asked
// for in CFG_REQUEST (IPv4 when it asked for neither), restricted by the
// subscribed PDN type when the AAA sent one (TS 23.401 §5.3.1.1, TS 24.302
// §7.4.1.1). ok is false when nothing the UE asked for is allowed.
//
//   - IPv4 / IPv6: only that family.
//   - IPv4v6: what the UE asked for.
//   - IPv4_OR_IPv6: one family; IPv4 when the UE asked for both.
//
// An unknown subscribed value is not enforced.
func (sa *ikeSA) pdnFamilies() (v4, v6, ok bool) {
	v4, v6 = sa.cpWantsIP, sa.cpWantsIP6
	if !v4 && !v6 {
		v4 = true
	}
	if !sa.subPDNTypePresent {
		return v4, v6, true
	}
	switch sa.subPDNType {
	case subPDNIPv4:
		v6 = false
	case subPDNIPv6:
		v4 = false
	case subPDNIPv4OrIPv6:
		if v4 {
			v6 = false
		}
	}
	return v4, v6, v4 || v6
}

func subscribedPDNTypeName(t uint8) string {
	switch t {
	case subPDNIPv4:
		return "IPv4"
	case subPDNIPv6:
		return "IPv6"
	case subPDNIPv4v6:
		return "IPv4v6"
	case subPDNIPv4OrIPv6:
		return "IPv4_OR_IPv6"
	}
	return fmt.Sprintf("unknown(%d)", t)
}
