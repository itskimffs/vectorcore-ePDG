// Added by itskimffs (2026-10), see NOTICE: IPv6 PDN connections over SWu/S2b; IPv4v6 PDN connections;
// PDN type limited by the subscription.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package ikev2

import (
	"net"

	"vectorcore-epdg/internal/pco"
	"vectorcore-epdg/internal/xfrm"

	"github.com/free5gc/ike/message"
)

const (
	// paaPrefixLen6 is the IPv6 prefix length of a PDN connection: the PGW
	// assigns a /64 prefix (TS 23.401 §5.3.1.2.2), and the UE only uses the
	// prefix from INTERNAL_IP6_ADDRESS (TS 24.302 §7.2.2 NOTE 3, §7.4.1 NOTE).
	paaPrefixLen6 = 64

	// attrPCSCF6Private is a private-use configuration attribute (RFC 7296
	// §3.15.1: 16384-32767) requested with length 0 by a Samsung A33 (Android 13)
	// together with INTERNAL_IP6_ADDRESS and INTERNAL_IP6_DNS, and without
	// P_CSCF_IP6_ADDRESS (21). It is not defined in TS 24.302 or RFC 7651; it is
	// treated as a pre-RFC 7651 P-CSCF IPv6 attribute and answered with the same
	// value format as P_CSCF_IP6_ADDRESS (16-octet address). Unverified.
	attrPCSCF6Private = uint16(16390)
)

// wantsIPv6PDN reports whether the PDN connection is set up as IPv6: the UE
// asked only for INTERNAL_IP6_ADDRESS, or for both and the subscription allows
// only IPv6.
func (sa *ikeSA) wantsIPv6PDN() bool {
	v4, v6, _ := sa.pdnFamilies()
	return v6 && !v4
}

// wantsIPv4v6PDN reports whether the PDN connection is set up as IPv4v6: the
// UE asked for INTERNAL_IP4_ADDRESS and INTERNAL_IP6_ADDRESS (TS 24.302 §7.2.2,
// §7.4.1) and ikev2.ipv4v6 is enabled. Otherwise such a request is answered
// with IPv4 and PDN_TYPE_IPv4_ONLY_ALLOWED.
func (s *Server) wantsIPv4v6PDN(sa *ikeSA) bool {
	v4, v6, _ := sa.pdnFamilies()
	return v4 && v6 && s.fullCfg != nil && s.fullCfg.IKEv2.IPv4v6
}

// sessionPAAs returns the PAA of the session's PDN connection and, for an
// IPv4v6 PDN connection, its IPv6 address (nil otherwise).
func (s *Server) sessionPAAs(sessionID string) (paa, paa6 net.IP) {
	if s.sessions == nil || sessionID == "" {
		return nil, nil
	}
	sess := s.sessions.Get(sessionID)
	if sess == nil {
		return nil, nil
	}
	sess.RLock()
	defer sess.RUnlock()
	if sess.S2B == nil {
		return nil, nil
	}
	paa = net.ParseIP(sess.S2B.PAA)
	if sess.S2B.PAA6 != "" {
		paa6 = net.ParseIP(sess.S2B.PAA6)
	}
	return paa, paa6
}

// setChildTrafficSelectors fills the inner XFRM selectors for the PAA and, for
// an IPv4v6 PDN connection, the IPv6 selectors for paa6.
func setChildTrafficSelectors(p *xfrm.ChildSAParams, paa, paa6 net.IP) {
	p.LocalTS, p.RemoteTS = paaTrafficSelectors(paa)
	p.LocalTS6, p.RemoteTS6 = nil, nil
	if paa6 != nil && paa.To4() != nil {
		p.LocalTS6, p.RemoteTS6 = paaTrafficSelectors(paa6)
	}
}

// paaTrafficSelectors returns the inner XFRM selectors for a PAA:
// IPv4 PAA/32 with 0.0.0.0/0 on the ePDG side, IPv6 prefix/64 with ::/0, and
// 0.0.0.0/0 on both sides when no PAA is known.
func paaTrafficSelectors(paa net.IP) (local, remote *net.IPNet) {
	if paa4 := paa.To4(); paa4 != nil {
		return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			&net.IPNet{IP: paa4, Mask: net.CIDRMask(32, 32)}
	}
	if paa6 := paa.To16(); paa6 != nil {
		mask := net.CIDRMask(paaPrefixLen6, 128)
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			&net.IPNet{IP: paa6.Mask(mask), Mask: mask}
	}
	return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
		&net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}
}

// internalIP6AddressValue encodes INTERNAL_IP6_ADDRESS: 16-octet address and a
// 1-octet prefix length (RFC 7296 §3.15.1).
func internalIP6AddressValue(paa net.IP) []byte {
	v := make([]byte, 0, net.IPv6len+1)
	v = append(v, paa.To16()...)
	return append(v, paaPrefixLen6)
}

// appendIPv6FromPCO adds the IPv6 DNS and P-CSCF addresses from the PGW's
// (A)PCO, only for the attributes the UE requested (TS 24.302 §7.4.1, RFC 7651).
func appendIPv6FromPCO(cp *message.Configuration, decoded *pco.Decoded, sa *ikeSA) {
	if decoded == nil {
		return
	}
	if sa.cpWantsDNS6 {
		for _, ip := range decoded.DNSv6 {
			if ip.To4() == nil && ip.To16() != nil {
				cp.ConfigurationAttribute.BuildConfigurationAttribute(message.INTERNAL_IP6_DNS, ip.To16())
			}
		}
	}
	for _, ip := range decoded.PCSCFv6 {
		if ip.To4() != nil || ip.To16() == nil {
			continue
		}
		if sa.cpWantsPCSCF6 {
			cp.ConfigurationAttribute.BuildConfigurationAttribute(internalIP6PCSCF, ip.To16())
		}
		if sa.cpWantsPCSCF6Private {
			cp.ConfigurationAttribute.BuildConfigurationAttribute(attrPCSCF6Private, ip.To16())
		}
	}
}

// buildTSResponse6 adds TSi (the UE's /64 prefix) and TSr (all IPv6) for an
// IPv6 PDN connection.
func buildTSResponse6(container *message.IKEPayloadContainer, paa net.IP) {
	tsi := container.BuildTrafficSelectorInitiator()
	addTS6(&tsi.TrafficSelectors, paa)
	tsr := container.BuildTrafficSelectorResponder()
	addTSAll6(&tsr.TrafficSelectors)
}

// buildTSResponseIPv4v6 adds TSi (the UE's IPv4 address and /64 prefix) and
// TSr (all IPv4 and all IPv6) for an IPv4v6 PDN connection: one CHILD SA for
// both families (RFC 7296 §2.9, TS 24.302 §7.2.2).
func buildTSResponseIPv4v6(container *message.IKEPayloadContainer, paa4, paa6 net.IP) {
	tsi := container.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(
		message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535, []byte(paa4.To4()), []byte(paa4.To4()))
	addTS6(&tsi.TrafficSelectors, paa6)
	tsr := container.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(
		message.TS_IPV4_ADDR_RANGE, message.IPProtocolAll, 0, 65535,
		[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	addTSAll6(&tsr.TrafficSelectors)
}

// addTS6 adds the /64 prefix of paa as an IPv6 address range.
func addTS6(ts *message.IndividualTrafficSelectorContainer, paa net.IP) {
	mask := net.CIDRMask(paaPrefixLen6, 128)
	start := paa.To16().Mask(mask)
	end := make(net.IP, net.IPv6len)
	for i := range end {
		end[i] = start[i] | ^mask[i]
	}
	ts.BuildIndividualTrafficSelector(
		message.TS_IPV6_ADDR_RANGE, message.IPProtocolAll, 0, 65535, []byte(start), []byte(end))
}

// addTSAll6 adds the whole IPv6 address range.
func addTSAll6(ts *message.IndividualTrafficSelectorContainer) {
	allOnes := make([]byte, net.IPv6len)
	for i := range allOnes {
		allOnes[i] = 0xff
	}
	ts.BuildIndividualTrafficSelector(
		message.TS_IPV6_ADDR_RANGE, message.IPProtocolAll, 0, 65535, make([]byte, net.IPv6len), allOnes)
}

// ipString renders an optional address ("" when nil).
func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
