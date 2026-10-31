// Added by itskimffs (2026-10), see NOTICE: IPv4v6 CHILD SAs (XFRM_STATE_AF_UNSPEC).
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package xfrm

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// addState installs an XFRM SA. For an IPv4v6 CHILD SA (afUnspec) the SA is
// sent with XFRM_STATE_AF_UNSPEC and an all-zero selector, so the kernel does
// not bind it to one inner family. netlink v1.3.1 cannot set that flag, so the
// XFRM_MSG_NEWSA request is built here with the same attributes that
// netlink.XfrmStateAdd would send for the fields this package uses.
func addState(st *netlink.XfrmState, afUnspec bool) error {
	if !afUnspec {
		return netlink.XfrmStateAdd(st)
	}
	req, err := newSARequestAFUnspec(st)
	if err != nil {
		return err
	}
	_, err = req.Execute(unix.NETLINK_XFRM, 0)
	return err
}

func newSARequestAFUnspec(st *netlink.XfrmState) (*nl.NetlinkRequest, error) {
	if st.Spi == 0 {
		return nil, fmt.Errorf("Spi must be set when adding xfrm state")
	}
	if st.Selector != nil || st.ESN || st.Mark != nil || st.OutputMark != nil || st.Replay != nil || st.SADir != 0 || st.Pcpunum != nil {
		return nil, fmt.Errorf("xfrm: AF_UNSPEC state with unsupported fields")
	}
	req := nl.NewNetlinkRequest(nl.XFRM_MSG_NEWSA, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)

	msg := &nl.XfrmUsersaInfo{}
	msg.Family = uint16(nl.GetIPFamily(st.Dst))
	msg.Id.Daddr.FromIP(st.Dst)
	msg.Saddr.FromIP(st.Src)
	msg.Id.Proto = uint8(st.Proto)
	msg.Mode = uint8(st.Mode)
	msg.Id.Spi = nl.Swap32(uint32(st.Spi))
	msg.Reqid = uint32(st.Reqid)
	msg.ReplayWindow = uint8(st.ReplayWindow)
	msg.Sel = nl.XfrmSelector{} // family 0: any inner family
	msg.Flags |= nl.XFRM_STATE_AF_UNSPEC
	msg.Lft.SoftByteLimit = nl.XFRM_INF
	msg.Lft.HardByteLimit = nl.XFRM_INF
	msg.Lft.SoftPacketLimit = nl.XFRM_INF
	msg.Lft.HardPacketLimit = nl.XFRM_INF
	req.AddData(msg)

	if a := st.Auth; a != nil {
		algo := nl.XfrmAlgoAuth{AlgKeyLen: uint32(len(a.Key) * 8), AlgTruncLen: uint32(a.TruncateLen), AlgKey: a.Key}
		copy(algo.AlgName[:], truncName(a.Name))
		req.AddData(nl.NewRtAttr(nl.XFRMA_ALG_AUTH_TRUNC, algo.Serialize()))
	}
	if a := st.Crypt; a != nil {
		algo := nl.XfrmAlgo{AlgKeyLen: uint32(len(a.Key) * 8), AlgKey: a.Key}
		copy(algo.AlgName[:], truncName(a.Name))
		req.AddData(nl.NewRtAttr(nl.XFRMA_ALG_CRYPT, algo.Serialize()))
	}
	if a := st.Aead; a != nil {
		algo := nl.XfrmAlgoAEAD{AlgKeyLen: uint32(len(a.Key) * 8), AlgICVLen: uint32(a.ICVLen), AlgKey: a.Key}
		copy(algo.AlgName[:], truncName(a.Name))
		req.AddData(nl.NewRtAttr(nl.XFRMA_ALG_AEAD, algo.Serialize()))
	}
	if e := st.Encap; e != nil {
		data := make([]byte, nl.SizeofXfrmEncapTmpl)
		encap := nl.DeserializeXfrmEncapTmpl(data)
		encap.EncapType = uint16(e.Type)
		encap.EncapSport = nl.Swap16(uint16(e.SrcPort))
		encap.EncapDport = nl.Swap16(uint16(e.DstPort))
		encap.EncapOa.FromIP(e.OriginalAddress)
		req.AddData(nl.NewRtAttr(nl.XFRMA_ENCAP, data))
	}
	if st.Ifid != 0 {
		req.AddData(nl.NewRtAttr(nl.XFRMA_IF_ID, nl.Uint32Attr(uint32(st.Ifid))))
	}
	return req, nil
}

func truncName(name string) string {
	if len(name) > 64 {
		return name[:64]
	}
	return name
}
