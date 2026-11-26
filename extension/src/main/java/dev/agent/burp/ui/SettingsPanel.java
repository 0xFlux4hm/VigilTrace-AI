package dev.agent.burp.ui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import dev.agent.burp.BridgeConfig;

/**
 * The "AI Agent Bridge" tab in Burp: token, bind address, port and rate, plus the live status. It holds no Burp
 * types, so it can be built and exercised on a headless JVM; {@code AgentExtension} supplies the listener that
 * persists and applies the settings.
 */
public final class SettingsPanel {
    /** What the panel needs from its host. */
    public interface Listener {
        /** Applies edited settings. Returns {@code null} when the bridge restarted, else the problem text. */
        String apply(String token, String bind, String port, String rate);

        /** A fresh token to put into the token field. */
        String newToken();
    }

    private final Listener listener;
    private final JPanel root = new JPanel(new GridBagLayout());
    private final JPasswordField tokenField = new JPasswordField(32);
    private final JCheckBox showToken = new JCheckBox("Show token");
    private final JTextField bindField = new JTextField(12);
    private final JTextField portField = new JTextField(8);
    private final JTextField rateField = new JTextField(8);
    private final JButton applyButton = new JButton("Apply and restart bridge");
    private final JButton generateButton = new JButton("Generate token");
    private final JLabel stateLabel = new JLabel(" ");
    private final JTextArea status = new JTextArea(9, 58);

    public SettingsPanel(Listener listener) {
        this.listener = listener;
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        addRow(0, "Bridge token", tokenField,
                "At least 16 characters. The MCP server needs the same value in BURP_BRIDGE_TOKEN. Empty = no saved token.");
        addRow(1, "", showToken, "");
        addRow(2, "Bind address", bindField, "127.0.0.1 keeps the bridge on this machine.");
        addRow(3, "Port", portField, "Default 8787.");
        addRow(4, "Rate limit (req/s)", rateField, "Applies to every request the bridge sends. Default 2.");
        addRow(5, "", buttons(), "");
        addRow(6, "Status", stateLabel, "");
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 7;
        c.gridwidth = 3;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1.0;
        c.weighty = 1.0;
        c.insets = new Insets(6, 0, 0, 0);
        status.setLineWrap(true);
        status.setWrapStyleWord(true);
        status.setEditable(false);
        root.add(new JScrollPane(status), c);

        showToken.addActionListener(e -> tokenField.setEchoChar(showToken.isSelected() ? (char) 0 : '*'));
        generateButton.addActionListener(e -> tokenField.setText(listener.newToken()));
        applyButton.addActionListener(e -> apply());
        stopped("Not started.");
    }

    private JPanel buttons() {
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        row.add(generateButton);
        row.add(Box.createHorizontalStrut(8));
        row.add(applyButton);
        return row;
    }

    private void addRow(int y, String label, JComponent field, String hint) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = y;
        c.anchor = GridBagConstraints.LINE_END;
        c.insets = new Insets(3, 0, 3, 8);
        root.add(new JLabel(label), c);
        c.gridx = 1;
        c.anchor = GridBagConstraints.LINE_START;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        root.add(field, c);
        c.gridx = 2;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0.0;
        JLabel hintLabel = new JLabel("<html><body style='width: 260px'>" + hint + "</body></html>");
        hintLabel.setForeground(hintLabel.getForeground().darker());
        root.add(hintLabel, c);
    }

    public JComponent component() {
        return root;
    }

    /** Fills the fields from the active configuration; a token that came from the environment is not shown. */
    public void load(BridgeConfig config) {
        tokenField.setText("settings".equals(config.tokenSource) && config.token != null ? config.token : "");
        bindField.setText(config.bindAddress == null ? "" : config.bindAddress);
        portField.setText(String.valueOf(config.port));
        rateField.setText(config.permitsPerSecond == Math.rint(config.permitsPerSecond)
                ? String.valueOf((long) config.permitsPerSecond) : String.valueOf(config.permitsPerSecond));
    }

    public void running(String uri, int toolCount, String instance, boolean loopbackOnly) {
        stateLabel.setText("RUNNING");
        setStatus("The bridge is listening on " + uri + " (" + toolCount + " tools).\n"
                + "Instance " + instance + " — its traffic counters live until Burp or the extension is restarted.\n"
                + "MCP server: set BURP_BRIDGE_URL=" + uri + " and BURP_BRIDGE_TOKEN to this token.\n"
                + (loopbackOnly ? ""
                        : "WARNING: the bridge can be reached from other machines. Anyone holding the token can send requests through Burp.\n")
                + "Check: curl -s -H \"Authorization: Bearer <token>\" " + uri + "/health", false);
    }

    public void stopped(String reason) {
        stateLabel.setText("NOT RUNNING");
        setStatus(reason + "\nNo socket is open and no request can be sent until a valid token is configured.", true);
    }

    public void failed(String message) {
        stateLabel.setText("FAILED");
        setStatus(message, true);
    }

    private void setStatus(String text, boolean problem) {
        status.setText(text);
        status.setBackground(problem ? new java.awt.Color(255, 236, 236) : root.getBackground());
        status.setCaretPosition(0);
    }

    private void apply() {
        String problem = listener.apply(new String(tokenField.getPassword()), bindField.getText(), portField.getText(), rateField.getText());
        if (problem != null) {
            setStatus(problem, true);
        }
    }

    // ---------------------------------------------------------------- headless access (self-test)

    public void setFields(String token, String bind, String port, String rate) {
        tokenField.setText(token);
        bindField.setText(bind);
        portField.setText(port);
        rateField.setText(rate);
    }

    public String tokenText() {
        return new String(tokenField.getPassword());
    }

    public void clickApply() {
        applyButton.doClick(0);
    }

    public void clickGenerate() {
        generateButton.doClick(0);
    }

    public String statusText() {
        return status.getText();
    }
}
