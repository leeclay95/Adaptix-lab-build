package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	adaptix "github.com/Adaptix-Framework/axc2"
)

// ---------------------------------------------------------------------------
// Teamserver interface — matches the axc2 v1.2.0 surface exactly.
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
// Plugin globals and entry point
// ---------------------------------------------------------------------------

type PluginListener struct{}

var (
	ModuleDir       string
	ListenerDataDir string
	Ts              Teamserver
)

func InitPlugin(ts any, moduleDir string, listenerDir string) adaptix.PluginListener {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir
	Ts = ts.(Teamserver)
	return &PluginListener{}
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type ListenerConfig struct {
	Host   string `json:"host"`
	Port   string `json:"port"`
	Domain string `json:"domain"`
}

// ---------------------------------------------------------------------------
// Listener — implements adaptix.ExtenderListener
// ---------------------------------------------------------------------------

type Listener struct {
	name   string
	config ListenerConfig
	server *DNSServer
}

func (p *PluginListener) Create(name, config string, customData []byte) (adaptix.ExtenderListener, adaptix.ListenerData, []byte, error) {
	var cfg ListenerConfig
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, adaptix.ListenerData{}, nil, fmt.Errorf("DNSC2 Create: bad config: %w", err)
	}
	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.Port == "" {
		cfg.Port = "5300"
	}
	if cfg.Domain == "" {
		cfg.Domain = "c2.lab"
	}

	l := &Listener{name: name, config: cfg}

	profileBytes, _ := json.Marshal(cfg)

	ld := adaptix.ListenerData{
		Name:     name,
		RegName:  "DNSC2",
		Protocol: "DNS",
		Type:     "DNSC2",
		BindHost: cfg.Host,
		BindPort: cfg.Port,
		Data:     string(profileBytes),
	}

	return l, ld, profileBytes, nil
}

func (l *Listener) Start() error {
	port, err := strconv.Atoi(l.config.Port)
	if err != nil {
		return fmt.Errorf("DNSC2 Start: invalid port %q: %w", l.config.Port, err)
	}
	l.server = NewDNSServer(l.config.Host, port, l.config.Domain, l.name)
	return l.server.Start()
}

func (l *Listener) Edit(config string) (adaptix.ListenerData, []byte, error) {
	var cfg ListenerConfig
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return adaptix.ListenerData{}, nil, fmt.Errorf("DNSC2 Edit: bad config: %w", err)
	}
	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.Port == "" {
		cfg.Port = "5300"
	}
	if cfg.Domain == "" {
		cfg.Domain = "c2.lab"
	}
	l.config = cfg

	profileBytes, _ := json.Marshal(cfg)
	ld := adaptix.ListenerData{
		Name:     l.name,
		RegName:  "DNSC2",
		Protocol: "DNS",
		Type:     "DNSC2",
		BindHost: cfg.Host,
		BindPort: cfg.Port,
		Data:     string(profileBytes),
	}
	return ld, profileBytes, nil
}

func (l *Listener) Stop() error {
	if l.server != nil {
		return l.server.Stop()
	}
	return nil
}

func (l *Listener) GetProfile() ([]byte, error) {
	return json.Marshal(l.config)
}

func (l *Listener) InternalHandler(data []byte) (string, error) {
	return "", nil
}
