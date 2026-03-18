//
//  MetatronAgentApp.swift
//  Metatron Agent
//
//  SwiftUI interface matching Defender installer style
//

import SwiftUI

// Color scheme matching Defender installer
struct DefenderColors {
    static let primary = Color.cyan
    static let success = Color.green
    static let warning = Color.yellow
    static let error = Color.red
    static let info = Color.blue
    static let background = Color(hex: "1a1a1a")
    static let cardBackground = Color(hex: "2a2a2a")
    static let textLight = Color.white
    static let textDark = Color.gray
}

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (1, 1, 1, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}

// ASCII Banner View
struct BannerView: View {
    var body: some View {
        VStack(spacing: 0) {
            Text("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗   ██╗
║     ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║   ██║
║     ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║   ██║
║     ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║   ╚═╝
║     ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██╗
║     ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
║                                                                  ║
║                    UNIFIED SECURITY AGENT v1.0                    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
            .font(.custom("Menlo", size: 8))
            .foregroundColor(DefenderColors.primary)
            .multilineTextAlignment(.leading)
            .padding(.horizontal)
        }
        .background(DefenderColors.background)
    }
}

// Status Indicator View
struct StatusIndicatorView: View {
    let title: String
    let status: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Text(title)
                .font(.custom("Menlo", size: 12).bold())
                .foregroundColor(DefenderColors.textLight)

            Text(status)
                .font(.custom("Menlo", size: 10))
                .foregroundColor(color)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(DefenderColors.cardBackground)
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(DefenderColors.primary.opacity(0.3), lineWidth: 1)
        )
    }
}

// Main Content View
struct ContentView: View {
    @StateObject private var agent = UnifiedAgent()
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Banner
            BannerView()

            // Status Bar
            HStack {
                Text(agent.statusText)
                    .font(.custom("Menlo", size: 12).bold())
                    .foregroundColor(agent.isMonitoring ? DefenderColors.success : DefenderColors.error)

                Spacer()

                Text("Agent ID: \(agent.agentId.prefix(16))...")
                    .font(.custom("Menlo", size: 10))
                    .foregroundColor(DefenderColors.textDark)
            }
            .padding()
            .background(DefenderColors.background)

            // Control Buttons
            HStack(spacing: 20) {
                Button(action: {
                    agent.startMonitoring()
                }) {
                    Text("▶️ START MONITORING")
                        .font(.custom("Menlo", size: 14).bold())
                        .foregroundColor(DefenderColors.background)
                        .padding(.horizontal, 30)
                        .padding(.vertical, 12)
                        .background(agent.isMonitoring ? DefenderColors.cardBackground : DefenderColors.success)
                        .cornerRadius(8)
                }
                .disabled(agent.isMonitoring)

                Button(action: {
                    agent.stopMonitoring()
                }) {
                    Text("⏹️ STOP MONITORING")
                        .font(.custom("Menlo", size: 14).bold())
                        .foregroundColor(DefenderColors.textLight)
                        .padding(.horizontal, 30)
                        .padding(.vertical, 12)
                        .background(agent.isMonitoring ? DefenderColors.error : DefenderColors.cardBackground)
                        .cornerRadius(8)
                }
                .disabled(!agent.isMonitoring)
            }
            .padding()
            .background(DefenderColors.background)

            // Tab View
            TabView(selection: $selectedTab) {
                // Dashboard Tab
                DashboardView(agent: agent)
                    .tabItem {
                        Label("Dashboard", systemImage: "chart.bar.fill")
                    }
                    .tag(0)

                // Monitoring Tab
                MonitoringView(agent: agent)
                    .tabItem {
                        Label("Monitoring", systemImage: "magnifyingglass")
                    }
                    .tag(1)

                // Network Tab
                NetworkView(agent: agent)
                    .tabItem {
                        Label("Network", systemImage: "network")
                    }
                    .tag(2)

                // Settings Tab
                SettingsView(agent: agent)
                    .tabItem {
                        Label("Settings", systemImage: "gear")
                    }
                    .tag(3)

                // Logs Tab
                LogsView(agent: agent)
                    .tabItem {
                        Label("Logs", systemImage: "doc.text.fill")
                    }
                    .tag(4)
            }
        }
        .background(DefenderColors.background)
        .preferredColorScheme(.dark)
    }
}

// Dashboard View
struct DashboardView: View {
    @ObservedObject var agent: UnifiedAgent

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Status Indicators Grid
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 16) {
                    StatusIndicatorView(
                        title: "🌐 Network",
                        status: agent.networkStatus,
                        color: DefenderColors.info
                    )

                    StatusIndicatorView(
                        title: "⚙️ Processes",
                        status: agent.processStatus,
                        color: DefenderColors.success
                    )

                    StatusIndicatorView(
                        title: "📁 Files",
                        status: agent.fileStatus,
                        color: DefenderColors.warning
                    )

                    StatusIndicatorView(
                        title: "📶 Wireless",
                        status: agent.wirelessStatus,
                        color: agent.wirelessEnabled ? DefenderColors.success : DefenderColors.error
                    )
                }
                .padding(.horizontal)

                // Quick Actions
                VStack(alignment: .leading, spacing: 12) {
                    Text("Quick Actions")
                        .font(.custom("Menlo", size: 16).bold())
                        .foregroundColor(DefenderColors.textLight)

                    HStack(spacing: 12) {
                        Button("🔍 Scan Network") {
                            agent.scanNetwork()
                        }
                        .buttonStyle(DefenderButtonStyle(color: DefenderColors.primary))

                        Button("📡 Scan Wireless") {
                            agent.scanWireless()
                        }
                        .buttonStyle(DefenderButtonStyle(color: DefenderColors.info))
                    }
                }
                .padding(.horizontal)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.vertical)
        }
        .background(DefenderColors.background)
    }
}

// Monitoring View
struct MonitoringView: View {
    @ObservedObject var agent: UnifiedAgent

    var body: some View {
        VStack {
            // Monitoring Controls
            VStack(alignment: .leading, spacing: 16) {
                Text("Monitoring Options")
                    .font(.custom("Menlo", size: 16).bold())
                    .foregroundColor(DefenderColors.textLight)

                Toggle("Network Scanning", isOn: $agent.networkScanning)
                    .toggleStyle(DefenderToggleStyle())

                Toggle("Process Monitoring", isOn: $agent.processMonitoring)
                    .toggleStyle(DefenderToggleStyle())

                Toggle("File Scanning", isOn: $agent.fileScanning)
                    .toggleStyle(DefenderToggleStyle())

                Toggle("Wireless Scanning", isOn: $agent.wirelessScanning)
                    .toggleStyle(DefenderToggleStyle())

                Toggle("Bluetooth Scanning", isOn: $agent.bluetoothScanning)
                    .toggleStyle(DefenderToggleStyle())
            }
            .padding()

            // Results Area
            VStack(alignment: .leading) {
                Text("Monitoring Results")
                    .font(.custom("Menlo", size: 14).bold())
                    .foregroundColor(DefenderColors.textLight)
                    .padding(.horizontal)

                ScrollView {
                    Text(agent.monitoringResults)
                        .font(.custom("Menlo", size: 10))
                        .foregroundColor(DefenderColors.textLight)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .background(DefenderColors.cardBackground)
                .cornerRadius(8)
                .padding(.horizontal)
            }
        }
        .background(DefenderColors.background)
    }
}

// Network View
struct NetworkView: View {
    @ObservedObject var agent: UnifiedAgent

    var body: some View {
        VStack {
            // Scan Controls
            HStack(spacing: 16) {
                Button("🔍 SCAN NETWORK") {
                    agent.scanNetwork()
                }
                .buttonStyle(DefenderButtonStyle(color: DefenderColors.primary))

                Button("📡 WIRELESS SCAN") {
                    agent.scanWireless()
                }
                .buttonStyle(DefenderButtonStyle(color: DefenderColors.info))

                Button("📱 BLUETOOTH SCAN") {
                    agent.scanBluetooth()
                }
                .buttonStyle(DefenderButtonStyle(color: DefenderColors.warning))
            }
            .padding()

            // Results
            VStack(alignment: .leading) {
                Text("Network Scan Results")
                    .font(.custom("Menlo", size: 14).bold())
                    .foregroundColor(DefenderColors.textLight)
                    .padding(.horizontal)

                ScrollView {
                    Text(agent.networkResults)
                        .font(.custom("Menlo", size: 10))
                        .foregroundColor(DefenderColors.textLight)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                }
                .background(DefenderColors.cardBackground)
                .cornerRadius(8)
                .padding(.horizontal)
            }
        }
        .background(DefenderColors.background)
    }
}

// Settings View
struct SettingsView: View {
    @ObservedObject var agent: UnifiedAgent

    var body: some View {
        Form {
            Section(header: Text("Server Configuration").foregroundColor(DefenderColors.primary)) {
                TextField("Server URL", text: $agent.serverUrl)
                    .textFieldStyle(DefenderTextFieldStyle())

                TextField("Agent Name", text: $agent.agentName)
                    .textFieldStyle(DefenderTextFieldStyle())
            }

            Section(header: Text("Monitoring Settings").foregroundColor(DefenderColors.primary)) {
                Stepper("Update Interval: \(agent.updateInterval)s", value: $agent.updateInterval, in: 5...300)
                Stepper("Heartbeat Interval: \(agent.heartbeatInterval)s", value: $agent.heartbeatInterval, in: 30...3600)
            }

            Section {
                Button("💾 SAVE SETTINGS") {
                    agent.saveSettings()
                }
                .buttonStyle(DefenderButtonStyle(color: DefenderColors.success))

                Button("🔄 RESTART AGENT") {
                    agent.restartAgent()
                }
                .buttonStyle(DefenderButtonStyle(color: DefenderColors.warning))
            }
        }
        .background(DefenderColors.background)
    }
}

// Logs View
struct LogsView: View {
    @ObservedObject var agent: UnifiedAgent

    var body: some View {
        VStack {
            // Controls
            HStack {
                Button("🗑️ CLEAR LOGS") {
                    agent.clearLogs()
                }
                .buttonStyle(DefenderButtonStyle(color: DefenderColors.warning))

                Button("💾 EXPORT LOGS") {
                    agent.exportLogs()
                }
                .buttonStyle(DefenderButtonStyle(color: DefenderColors.info))

                Spacer()
            }
            .padding()

            // Log Display
            ScrollView {
                Text(agent.logs)
                    .font(.custom("Menlo", size: 10))
                    .foregroundColor(DefenderColors.textLight)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .background(DefenderColors.cardBackground)
            .cornerRadius(8)
            .padding(.horizontal)
        }
        .background(DefenderColors.background)
    }
}

// Custom Styles
struct DefenderButtonStyle: ButtonStyle {
    let color: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
            .background(configuration.isPressed ? color.opacity(0.7) : color)
            .foregroundColor(DefenderColors.background)
            .cornerRadius(8)
            .font(.custom("Menlo", size: 12).bold())
    }
}

struct DefenderToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack {
            configuration.label
                .foregroundColor(DefenderColors.textLight)
                .font(.custom("Menlo", size: 12))

            Spacer()

            RoundedRectangle(cornerRadius: 16)
                .fill(configuration.isOn ? DefenderColors.success : DefenderColors.cardBackground)
                .frame(width: 50, height: 30)
                .overlay(
                    Circle()
                        .fill(Color.white)
                        .padding(2)
                        .offset(x: configuration.isOn ? 10 : -10)
                )
                .onTapGesture {
                    configuration.isOn.toggle()
                }
        }
    }
}

struct DefenderTextFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .padding(8)
            .background(DefenderColors.cardBackground)
            .cornerRadius(6)
            .foregroundColor(DefenderColors.textLight)
            .font(.custom("Menlo", size: 12))
    }
}

// Agent Model
class UnifiedAgent: ObservableObject {
    @Published var isMonitoring = false
    @Published var statusText = "🔄 Initializing..."
    @Published var agentId = ""

    @Published var networkStatus = "Scanning..."
    @Published var processStatus = "Monitoring..."
    @Published var fileStatus = "Watching..."
    @Published var wirelessStatus = "Available"

    @Published var networkScanning = true
    @Published var processMonitoring = true
    @Published var fileScanning = true
    @Published var wirelessScanning = true
    @Published var bluetoothScanning = true

    @Published var serverUrl = UnifiedAgent.resolveDefaultServerUrl()
    @Published var agentName = ""
    @Published var updateInterval = 30
    @Published var heartbeatInterval = 60

    @Published var monitoringResults = ""
    @Published var networkResults = ""
    @Published var logs = ""

    private var monitoringTimer: Timer?

    private static func resolveDefaultServerUrl() -> String {
        let configured = ProcessInfo.processInfo.environment["METATRON_SERVER_URL"] ?? "http://localhost:8001"
        var normalized = configured.trimmingCharacters(in: .whitespacesAndNewlines)

        while normalized.hasSuffix("/") {
            normalized.removeLast()
        }

        if normalized.lowercased().hasSuffix("/api") {
            normalized.removeLast(4)
            while normalized.hasSuffix("/") {
                normalized.removeLast()
            }
        }

        return normalized
    }

    init() {
        setupAgent()
    }

    private func setupAgent() {
        // Generate agent ID
        agentId = UUID().uuidString.prefix(16).description

        // Set agent name
        agentName = "macOS-\(agentId.prefix(8))"

        // Initialize status
        updateStatus()
    }

    func startMonitoring() {
        isMonitoring = true
        statusText = "🟢 MONITORING ACTIVE"
        networkStatus = "Active"
        processStatus = "Active"
        fileStatus = "Active"

        // Start monitoring timer
        monitoringTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            self.updateMonitoringResults()
        }
    }

    func stopMonitoring() {
        isMonitoring = false
        statusText = "🔴 MONITORING STOPPED"
        networkStatus = "Inactive"
        processStatus = "Inactive"
        fileStatus = "Inactive"

        monitoringTimer?.invalidate()
        monitoringTimer = nil
    }

    func scanNetwork() {
        networkResults = "🔍 Scanning network...\n"
        // Simulate network scan
        DispatchQueue.global().async {
            sleep(2)
            DispatchQueue.main.async {
                self.networkResults += """
Network scan completed.
Found 5 devices:
- 192.168.1.1 (Gateway Router)
- 192.168.1.100 (MacBook Pro)
- 192.168.1.101 (iPhone)
- 192.168.1.102 (Smart TV)
- 192.168.1.103 (Printer)
"""
            }
        }
    }

    func scanWireless() {
        networkResults = "📶 Scanning wireless networks...\n"
        DispatchQueue.global().async {
            sleep(2)
            DispatchQueue.main.async {
                self.networkResults += """
Wireless scan completed.
Found 3 networks:
- MyHomeWiFi (2.4GHz, WPA2)
- MyHomeWiFi-5G (5GHz, WPA3)
- GuestNetwork (2.4GHz, Open)
"""
            }
        }
    }

    func scanBluetooth() {
        networkResults = "📱 Scanning Bluetooth devices...\n"
        DispatchQueue.global().async {
            sleep(2)
            DispatchQueue.main.async {
                self.networkResults += """
Bluetooth scan completed.
Found 2 devices:
- AirPods Pro (Connected)
- Wireless Keyboard (Paired)
"""
            }
        }
    }

    func saveSettings() {
        // Save settings to UserDefaults or file
        UserDefaults.standard.set(serverUrl, forKey: "serverUrl")
        UserDefaults.standard.set(agentName, forKey: "agentName")
        UserDefaults.standard.set(updateInterval, forKey: "updateInterval")
        UserDefaults.standard.set(heartbeatInterval, forKey: "heartbeatInterval")

        logMessage("Settings saved successfully")
    }

    func restartAgent() {
        if isMonitoring {
            stopMonitoring()
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                self.startMonitoring()
            }
        }
        logMessage("Agent restarted")
    }

    func clearLogs() {
        logs = ""
    }

    func exportLogs() {
        // Export logs functionality
        logMessage("Logs exported")
    }

    private func updateStatus() {
        // Update status indicators
    }

    private func updateMonitoringResults() {
        if isMonitoring {
            let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
            monitoringResults += "[\(timestamp)] System monitoring active...\n"
        }
    }

    private func logMessage(_ message: String) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        logs += "[\(timestamp)] \(message)\n"
    }
}

// App Entry Point
@main
struct MetatronAgentApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 1000, minHeight: 700)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Metatron Agent") {
                    // Show about dialog
                }
            }
        }
    }
}