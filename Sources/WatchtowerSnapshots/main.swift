// Renders the dashboard scenarios to PNG files, offscreen, in light and dark.
// Usage: WatchtowerSnapshots <out-dir>. No window is shown and no engine runs.
import AppKit
import SwiftUI
import WatchtowerCore
import WatchtowerUI

@MainActor
func render(_ view: some View, size: CGSize, dark: Bool, to url: URL) throws {
    let appearance = NSAppearance(named: dark ? .darkAqua : .aqua)!
    let window = NSWindow(contentRect: CGRect(origin: .zero, size: size),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
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
    let frameView = window.contentView?.superview ?? window.contentView!
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
                if scenario == .settingsInactive {
                    try render(SettingsView(model: model), size: CGSize(width: 560, height: 380), dark: dark,
                               to: out.appendingPathComponent(name))
                } else {
                    try render(DashboardView(model: model), size: CGSize(width: 1180, height: 660), dark: dark,
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
                    try render(DashboardView(model: model).environment(updates), size: CGSize(width: 1180, height: 660),
                               dark: dark, to: out.appendingPathComponent(name))
                case .majorAlert:
                    // SwiftUI shows this step as an NSAlert sheet. Render the same alert offscreen.
                    guard case .confirmMajor(let plan) = updates.step else { continue }
                    try renderAlert(title: "Update to a new major version?", text: plan.majorWarning,
                                    buttons: ["Update to \(plan.targetVersion ?? "?")", "Cancel"], dark: dark,
                                    to: out.appendingPathComponent(name))
                default:
                    try render(UpdateDialog(model: updates), size: CGSize(width: 580, height: 400), dark: dark,
                               to: out.appendingPathComponent(name))
                }
                print(name)
                written += 1
            } catch {
                FileHandle.standardError.write(Data("\(name): \(error)\n".utf8))
            }
        }
    }
    let expected = (SampleData.Scenario.allCases.count + SampleData.UpdateScenario.allCases.count) * 2
    exit(written == expected ? 0 : 1)
}
