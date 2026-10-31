// Modified by itskimffs (2026-10), see NOTICE: ue_ip6 for IPv4v6 PDN connections.
// This file is part of vectorcore-ePDG, licensed under the Apache License,
// Version 2.0 (see LICENSE).

package api

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-epdg/internal/session"
)

func (s *Server) registerSessions(api huma.API) {
	huma.Get(api, basePath+"/sessions", func(ctx context.Context, _ *struct{}) (*struct{ Body []SessionDetail }, error) {
		var out []SessionDetail
		for _, sess := range s.sessions.Snapshot() {
			out = append(out, sessionDetail(sess))
		}
		return &struct{ Body []SessionDetail }{out}, nil
	})

	huma.Get(api, basePath+"/sessions/{imsi}", func(ctx context.Context, in *imsiInput) (*struct{ Body SessionDetail }, error) {
		sess := s.sessions.FindByIMSIAPN(in.IMSI, "")
		if sess == nil {
			return nil, huma.Error404NotFound(fmt.Sprintf("no session found for IMSI %s", in.IMSI))
		}
		return &struct{ Body SessionDetail }{sessionDetail(sess)}, nil
	})
}

func sessionDetail(sess *session.Session) SessionDetail {
	sess.RLock()
	defer sess.RUnlock()
	ueIP, ueIP6 := "", ""
	if sess.S2B != nil {
		ueIP, ueIP6 = sess.S2B.PAA, sess.S2B.PAA6
	}
	out := SessionDetail{
		IMSI:    sess.IMSI,
		UEIP:    ueIP,
		UEIP6:   ueIP6,
		OuterIP: sess.OuterIP,
		APN:     sess.APN,
		State:   string(sess.State),
		IKESA: IKESADetail{
			SPII: fmt.Sprintf("0x%x", sess.IkeSPII),
			SPIR: fmt.Sprintf("0x%x", sess.IkeSPIR),
		},
		ChildSA: ChildSADetail{
			ESPSPIIn:  fmt.Sprintf("0x%x", sess.ESPInboundSPI),
			ESPSPIOut: fmt.Sprintf("0x%x", sess.ESPOutboundSPI),
		},
	}
	if sess.S2B != nil {
		pgw := ""
		if sess.S2B.PGWControlIP != nil {
			pgw = sess.S2B.PGWControlIP.String()
		}
		out.S2B = &S2BDetail{
			PGW:         pgw,
			ControlTEID: sess.S2B.PGWControlTEID,
			DataTEID:    sess.S2B.PGWUserTEID,
		}
	}
	return out
}
