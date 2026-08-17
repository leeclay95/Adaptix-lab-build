/// DNSC2

function ListenerUI(mode_create)
{
    let labelHost = form.create_label("Bind Host:");
    let inputHost = form.create_lineedit();
    inputHost.setText("0.0.0.0");

    let labelPort = form.create_label("Port:");
    let inputPort = form.create_lineedit();
    inputPort.setText("5300");

    let labelDomain = form.create_label("C2 Domain:");
    let inputDomain = form.create_lineedit();
    inputDomain.setText("c2.lab");

    let layout = form.create_gridlayout();
    layout.addWidget(labelHost, 0, 0);
    layout.addWidget(inputHost, 0, 1);
    layout.addWidget(labelPort, 1, 0);
    layout.addWidget(inputPort, 1, 1);
    layout.addWidget(labelDomain, 2, 0);
    layout.addWidget(inputDomain, 2, 1);

    let container = form.create_container();
    container.put("host", inputHost);
    container.put("port", inputPort);
    container.put("domain", inputDomain);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 300,
        ui_width: 450
    }
}
