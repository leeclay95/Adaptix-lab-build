/// dns_agent

function RegisterCommands(listener_type)
{
    if (listener_type == "DNSC2") {

        let cmd_shell = ax.create_command(
            "shell",
            "Execute shell command",
            [
                ax.create_arg("cmd", "string", true, "", "Command to execute")
            ]
        );

        let cmd_execute_bof = ax.create_command(
            "execute-bof",
            "Execute BOF in-process",
            [
                ax.create_arg("file",  "string", true,  "",  "BOF file upload ID"),
                ax.create_arg("args",  "string", false, "",  "Arguments to pass to the BOF")
            ]
        );

        let cmd_sleep = ax.create_command(
            "sleep",
            "Set beacon interval",
            [
                ax.create_arg("interval", "int", true,  0,  "Sleep interval in milliseconds"),
                ax.create_arg("jitter",   "int", false, 0,  "Jitter percentage (0-100)")
            ]
        );

        let cmd_terminate = ax.create_command(
            "terminate",
            "Terminate agent",
            []
        );

        let commands_external = ax.create_commands_group(
            "dns_agent",
            [cmd_shell, cmd_execute_bof, cmd_sleep, cmd_terminate]
        );

        return { commands_windows: commands_external }
    }

    return ax.create_commands_group("none", []);
}

function GenerateUI(listeners_type)
{
    let arch_combo = form.create_combobox("arch", ["x64", "x86"]);
    let format_combo = form.create_combobox("format", ["EXE", "DLL"]);
    let sleep_input = form.create_lineedit("sleep", "5000");
    let jitter_input = form.create_lineedit("jitter", "20");

    let container = form.create_container();
    form.add_row(container, [form.create_label("Architecture:"), arch_combo]);
    form.add_row(container, [form.create_label("Format:"),       format_combo]);
    form.add_row(container, [form.create_label("Sleep (ms):"),   sleep_input]);
    form.add_row(container, [form.create_label("Jitter (%):"),   jitter_input]);

    let panel = form.create_panel();

    return {
        ui_panel:     panel,
        ui_container: container,
        ui_height:    450,
        ui_width:     550
    }
}
