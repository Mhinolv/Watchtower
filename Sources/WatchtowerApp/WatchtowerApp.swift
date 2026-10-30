import SwiftUI
import WatchtowerCore
import WatchtowerUI

@main
struct WatchtowerApp: App {
    @State private var model = DashboardModel(engine: Engine())
    @State private var updates = UpdateModel(client: Engine())
    @State private var incidents = IncidentModel(client: Engine())

    var body: some Scene {
        Window("Watchtower", id: "main") {
            DashboardView(model: model)
                .environment(updates)
                .environment(incidents)
                .frame(minWidth: 900, minHeight: 520)
                .task {
                    updates.onFinished = { Task { await model.load() } }
                    updates.onViewLog = { model.selection = .updateLog }
                    await model.load()
                    await updates.loadLog()
                    await incidents.load()
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
