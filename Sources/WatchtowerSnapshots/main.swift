// Renders the dashboard scenarios to PNG files, offscreen, in light and dark.
// Usage: WatchtowerSnapshots <out-dir>. No window is shown and no engine runs.
import AppKit
import SwiftUI
import WatchtowerCore
import WatchtowerUI

@MainActor
func render(_ view: some View, size: CGSize, dark: Bool, chrome: Bool = true, to url: URL) throws {
    let appearance = NSAppearance(named: dark ? .darkAqua : .aqua)!
    var size = size
    let fitHeight = size.height == 0
    if fitHeight {
        // Fit the height to the content, for example the menu bar popover.
        let probe = NSHostingController(rootView: view.environment(\.colorScheme, dark ? .dark : .light))
        size.height = probe.sizeThatFits(in: CGSize(width: size.width, height: 4000)).height
    }
    let window = NSWindow(contentRect: CGRect(origin: .zero, size: size),
                          styleMask: chrome ? [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
                                            : [.borderless],
                          backing: .buffered, defer: false)
    window.appearance = appearance
    window.title = "Watchtower"
    window.isReleasedWhenClosed = false
    window.contentViewController = NSHostingController(rootView: view.frame(width: size.width, height: size.height))
    window.setContentSize(size)
    // Let SwiftUI lay out the view and build the toolbar.
    for _ in 0..<5 {
        RunLoop.main.run(until: Date().addingTimeInterval(0.15))
        window.contentView?.layoutSubtreeIfNeeded()
    }
    if fitHeight {
        // State set in onAppear (for example an open list) can change the height. Measure again.
        let host = NSHostingController(rootView: view.environment(\.colorScheme, dark ? .dark : .light))
        host.view.frame = CGRect(origin: .zero, size: size)
        for _ in 0..<3 { RunLoop.main.run(until: Date().addingTimeInterval(0.1)); host.view.layoutSubtreeIfNeeded() }
        let height = max(size.height, host.sizeThatFits(in: CGSize(width: size.width, height: 4000)).height)
        if height > size.height {
            size.height = height
            window.contentViewController = NSHostingController(rootView: view.frame(width: size.width, height: height))
            window.setContentSize(size)
            for _ in 0..<5 {
                RunLoop.main.run(until: Date().addingTimeInterval(0.15))
                window.contentView?.layoutSubtreeIfNeeded()
            }
        }
    }
    let frameView = chrome ? (window.contentView?.superview ?? window.contentView!) : window.contentView!
    let bounds = frameView.bounds
    guard let rep = frameView.bitmapImageRepForCachingDisplay(in: bounds) else {
        throw CocoaError(.fileWriteUnknown)
    }
    appearance.performAsCurrentDrawingAppearance {
        frameView.cacheDisplay(in: bounds, to: rep)
    }
    guard let png = rep.representation(using: .png, properties: [:]) else { throw CocoaError(.fileWriteUnknown) }
    try png.write(to: url)
    window.close()
}

@MainActor
func renderAlert(title: String, text: String, buttons: [String], dark: Bool, to url: URL) throws {
    let appearance = NSAppearance(named: dark ? .darkAqua : .aqua)!
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = text
    buttons.forEach { alert.addButton(withTitle: $0) }
    // The snapshot tool has no app icon. The app shows its own icon here.
    alert.icon = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: nil)
    alert.window.appearance = appearance
    alert.layout()
    RunLoop.main.run(until: Date().addingTimeInterval(0.15))
    let view = alert.window.contentView?.superview ?? alert.window.contentView!
    guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw CocoaError(.fileWriteUnknown) }
    appearance.performAsCurrentDrawingAppearance { view.cacheDisplay(in: view.bounds, to: rep) }
    guard let png = rep.representation(using: .png, properties: [:]) else { throw CocoaError(.fileWriteUnknown) }
    try png.write(to: url)
}

MainActor.assumeIsolated {
    let args = CommandLine.arguments
    guard args.count == 2 else {
        FileHandle.standardError.write(Data("usage: WatchtowerSnapshots <out-dir>\n".utf8))
        exit(2)
    }
    let out = URL(fileURLWithPath: args[1], isDirectory: true)
    try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
    let app = NSApplication.shared
    app.setActivationPolicy(.prohibited)

    var written = 0
    for scenario in SampleData.Scenario.allCases {
        for dark in [false, true] {
            let model = SampleData.model(scenario)
            let name = "\(scenario.rawValue)-\(dark ? "dark" : "light").png"
            do {
                if scenario.isMenuBar {
                    // The system gives the real popover its material. Here a window color stands in.
                    try render(MenuBarPopover(model: model, openWindow: {})
                                   .background(Color(nsColor: .windowBackgroundColor)),
                               size: CGSize(width: DesignTokens.popoverWidth, height: 0), dark: dark, chrome: false,
                               to: out.appendingPathComponent(name))
                } else if scenario == .settingsInactive {
                    try render(SettingsView(model: model), size: CGSize(width: 560, height: 380), dark: dark,
                               to: out.appendingPathComponent(name))
                } else if scenario.isDependencies {
                    // The Update… buttons need an update model and the table needs a dependency model.
                    try render(DashboardView(model: model).environment(UpdateModel(client: PreviewEngine()))
                                   .environment(SampleData.dependencyModel(scenario)),
                               size: CGSize(width: 1280, height: 720), dark: dark, to: out.appendingPathComponent(name))
                } else if [.findingUv, .findingRequirements, .findingRequirementsRefused].contains(scenario) {
                    // The Update… buttons need an update model in the environment.
                    try render(DashboardView(model: model).environment(UpdateModel(client: PreviewEngine())),
                               size: CGSize(width: 1280, height: 720), dark: dark, to: out.appendingPathComponent(name))
                } else if [.findingVendor, .findingVendorNotAffected, .findingVendorHistory].contains(scenario) {
                    // The `Vendor assessment` section (#18) is below `Source`: a taller window shows it.
                    try render(DashboardView(model: model), size: CGSize(width: 1280, height: 1480), dark: dark,
                               to: out.appendingPathComponent(name))
                } else {
                    try render(DashboardView(model: model), size: CGSize(width: 1280, height: 720), dark: dark,
                               to: out.appendingPathComponent(name))
                }
                print(name)
                written += 1
            } catch {
                FileHandle.standardError.write(Data("\(name): \(error)\n".utf8))
            }
        }
    }
    for scenario in SampleData.UpdateScenario.allCases {
        for dark in [false, true] {
            let updates = SampleData.updateModel(scenario)
            let name = "\(scenario.rawValue)-\(dark ? "dark" : "light").png"
            do {
                switch scenario {
                case .log:
                    let model = SampleData.model(.complete)
                    model.selection = .updateLog
                    try render(DashboardView(model: model).environment(updates), size: CGSize(width: 1280, height: 720),
                               dark: dark, to: out.appendingPathComponent(name))
                case .majorAlert:
                    // SwiftUI shows this step as an NSAlert sheet. Render the same alert offscreen.
                    guard case .confirmMajor(let plan) = updates.step else { continue }
                    try renderAlert(title: "Update to a new major version?", text: plan.majorWarning,
                                    buttons: ["Update to \(plan.targetVersion ?? "?")", "Cancel"], dark: dark,
                                    to: out.appendingPathComponent(name))
                default:
                    try render(UpdateDialog(model: updates), size: CGSize(width: 580, height: 0), dark: dark,
                               to: out.appendingPathComponent(name))
                }
                print(name)
                written += 1
            } catch {
                FileHandle.standardError.write(Data("\(name): \(error)\n".utf8))
            }
        }
    }
    for scenario in SampleData.IncidentScenario.allCases {
        for dark in [false, true] {
            let (model, incidents) = SampleData.incidentScenario(scenario)
            let name = "\(scenario.rawValue)-\(dark ? "dark" : "light").png"
            do {
                if scenario == .researchConfirm {
                    // SwiftUI shows the confirm step as a sheet. Render the sheet itself (#19).
                    try render(ResearchConfirmSheet(model: incidents).background(Color(nsColor: .windowBackgroundColor)),
                               size: CGSize(width: 440, height: 0), dark: dark, chrome: false,
                               to: out.appendingPathComponent(name))
                } else {
                    try render(DashboardView(model: model).environment(incidents), size: CGSize(width: 1280, height: 720),
                               dark: dark, to: out.appendingPathComponent(name))
                }
                print(name)
                written += 1
            } catch {
                FileHandle.standardError.write(Data("\(name): \(error)\n".utf8))
            }
        }
    }
    // The Coverage popover with the Sparkle row (#14).
    for dark in [false, true] {
        let name = "sparkle-coverage-\(dark ? "dark" : "light").png"
        do {
            try render(CoverageView(rows: SampleData.model(.sparkleFailed).coverageRows)
                           .background(Color(nsColor: .windowBackgroundColor)),
                       size: CGSize(width: 320, height: 0), dark: dark, chrome: false,
                       to: out.appendingPathComponent(name))
            print(name)
            written += 1
        } catch {
            FileHandle.standardError.write(Data("\(name): \(error)\n".utf8))
        }
    }
    let expected = 2 + (SampleData.Scenario.allCases.count + SampleData.UpdateScenario.allCases.count
                    + SampleData.IncidentScenario.allCases.count) * 2
    exit(written == expected ? 0 : 1)
}
