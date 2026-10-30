import SwiftUI
import WatchtowerCore
import WatchtowerUI

@main
struct WatchtowerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = DashboardModel(engine: Engine())
    @State private var updates = UpdateModel(client: Engine())

    var body: some Scene {
        Window("Watchtower", id: "main") {
            DashboardView(model: model)
                .environment(updates)
                .frame(minWidth: 900, minHeight: 520)
                .task {
                    updates.onFinished = { Task { await model.load() } }
                    updates.onViewLog = { model.selection = .updateLog }
                    await model.load()
                    await updates.loadLog()
                }
        }
        .commands {
            CommandGroup(after: .sidebar) {
                ForEach(SidebarSection.allCases) { section in
                    Button(section.title) { model.selection = section }
                        .keyboardShortcut(KeyEquivalent(section.shortcutDigit), modifiers: .command)
                }
            }
        }

        Settings {
            SettingsView(model: model)
                .task { await model.loadProjects() }
        }

        MenuBarExtra {
            MenuBarMenu(model: model)
        } label: {
            MenuBarIcon(model: model)
        }
        .menuBarExtraStyle(.window)
    }
}

/// The menu bar popover, with access to `openWindow`.
struct MenuBarMenu: View {
    let model: DashboardModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        MenuBarPopover(model: model) {
            openWindow(id: "main")
            NSApplication.shared.activate()
        }
    }
}

/// Quit (⌘Q or the menu bar) stops every engine process at once (#33). A refresh engine saves a
/// `cancelled` refresh, so the next launch never shows it as complete. No confirm alert.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillTerminate(_ notification: Notification) {
        EngineProcesses.shared.terminateAll(wait: 2)
    }
}
