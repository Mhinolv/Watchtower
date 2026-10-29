import AppKit
import SwiftUI
import WatchtowerCore

/// Images from design/logo/, copied into this module's resources.
public enum Brand {
    /// The resource bundle. In Watchtower.app it is in Contents/Resources (scripts/bundle.sh).
    /// SwiftPM's `Bundle.module` only looks next to the app and in the build folder, and stops the
    /// app if both are missing, so it is the fallback for `swift run` and snapshots.
    static let resources: Bundle = {
        if let url = Bundle.main.url(forResource: "Watchtower_WatchtowerUI", withExtension: "bundle"),
           let bundle = Bundle(url: url) {
            return bundle
        }
        return Bundle.module
    }()

    /// The 18 pt template image for the menu bar. `alert` while an item is vulnerable.
    public static func menuBarIcon(alert: Bool) -> NSImage {
        let name = alert ? "menubar-alert-template" : "menubar-template"
        let image = resources.image(forResource: name) ?? NSImage(systemSymbolName: "shield.lefthalf.filled",
                                                                      accessibilityDescription: nil)!
        image.isTemplate = true
        image.size = NSSize(width: 18, height: 18)
        return image
    }

    /// The app icon. The bundled app uses AppIcon.icns. Snapshots and `swift run` use this PNG.
    @MainActor public static var appIcon: NSImage {
        resources.image(forResource: "watchtower-icon") ?? NSApplication.shared.applicationIconImage
    }
}

/// The menu bar symbol. It changes when an item is vulnerable.
public struct MenuBarIcon: View {
    let model: DashboardModel

    public init(model: DashboardModel) {
        self.model = model
    }

    public var body: some View {
        let alert = model.menuBarSummary.alertIcon
        Image(nsImage: Brand.menuBarIcon(alert: alert))
            .accessibilityLabel(alert ? "Watchtower, vulnerable items open" : "Watchtower")
    }
}

/// The menu bar popover (`MenuBarExtra`, window style, 330 pt): header, tiles, rows, footer.
public struct MenuBarPopover: View {
    let model: DashboardModel
    let openWindow: () -> Void

    public init(model: DashboardModel, openWindow: @escaping () -> Void) {
        self.model = model
        self.openWindow = openWindow
    }

    public var body: some View {
        let summary = model.menuBarSummary
        VStack(alignment: .leading, spacing: 12) {
            header
            switch summary.mode {
            case .never:
                Text("Never refreshed. Click Refresh.")
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 6)
            case .allClear:
                HStack(spacing: 12) {
                    Image(systemName: "checkmark.seal")
                        .font(.system(size: 26))
                        .foregroundStyle(Tone.green.color)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Everything is up to date").fontWeight(.semibold)
                        Text("0 findings open. Scan was complete.").font(.callout).foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
                .padding(.vertical, 4)
            case .attention:
                tiles(summary)
                if !summary.rows.isEmpty {
                    VStack(alignment: .leading, spacing: 0) {
                        Text("Needs attention")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .padding(.bottom, 6)
                        ForEach(summary.rows) { row in
                            Divider()
                            attentionRow(row)
                        }
                    }
                }
            }
            Divider()
            footer
        }
        .padding(14)
        .frame(width: DesignTokens.popoverWidth)
        .tint(.watchtowerAccent)
    }

    var header: some View {
        let label = model.refreshLabel
        return HStack(spacing: 10) {
            Image(nsImage: Brand.appIcon)
                .resizable()
                .frame(width: 32, height: 32)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text("Watchtower").font(.system(size: 13, weight: .bold))
                Text(label.text).font(.system(size: 11.5)).foregroundStyle(label.tone.color)
            }
            Spacer()
            Button {
                model.isRefreshing ? model.stop() : model.refresh()
            } label: {
                Image(systemName: model.isRefreshing ? "stop.fill" : "arrow.clockwise")
            }
            .buttonStyle(.bordered)
            .help(model.isRefreshing ? "Stop the refresh" : "Refresh")
            .accessibilityLabel(model.isRefreshing ? "Stop" : "Refresh")
        }
    }

    func tiles(_ s: MenuBarSummary) -> some View {
        HStack(spacing: 8) {
            tile(s.vulnerable, "Vulnerable", "exclamationmark.shield", .red, spoken: "vulnerable")
            tile(s.updates, "Updates", "arrow.up.circle", .blue, spoken: s.updates == 1 ? "update" : "updates")
            tile(s.errors, "Error", "exclamationmark.triangle", .orange, spoken: s.errors == 1 ? "error" : "errors")
        }
    }

    func tile(_ count: Int, _ title: String, _ symbol: String, _ tone: Tone, spoken: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(count)").font(.system(size: 22, weight: .bold)).monospacedDigit()
            HStack(spacing: 3) {
                Image(systemName: symbol).imageScale(.small)
                Text(title).lineLimit(1).minimumScaleFactor(0.85)
            }
            .font(.system(size: 11, weight: .semibold))
        }
        .foregroundStyle(tone.color)
        .padding(.horizontal, 9)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tone.color.opacity(0.14), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(count) \(spoken)")
    }

    func attentionRow(_ row: AttentionRow) -> some View {
        Button {
            model.reveal(row)
            openWindow()
        } label: {
            HStack(spacing: 8) {
                ItemIcon(name: row.name, size: 18)
                Text(row.name).fontWeight(.semibold).lineLimit(1)
                if let version = row.version {
                    Text(version).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 4)
                StatusBadge(row.state)
            }
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Open \(row.name) in Watchtower")
    }

    var footer: some View {
        HStack(spacing: 10) {
            Button("Open Watchtower") { openWindow() }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
            Spacer()
            SettingsLink { Text("Settings…") }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            Button("Quit") { NSApplication.shared.terminate(nil) }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .keyboardShortcut("q", modifiers: .command)
        }
        .font(.callout)
    }
}
