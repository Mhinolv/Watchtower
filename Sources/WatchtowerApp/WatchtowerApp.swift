import SwiftUI
import WatchtowerCore
import WatchtowerUI

@main
struct WatchtowerApp: App {
    @State private var model = DashboardModel(engine: Engine())

    var body: some Scene {
        Window("Watchtower", id: "main") {
            DashboardView(model: model)
                .frame(minWidth: 900, minHeight: 520)
                .task { await model.load() }
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
    }
}

/// The menu bar menu, with access to `openWindow`.
struct MenuBarMenu: View {
    let model: DashboardModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        MenuBarContent(model: model) {
            openWindow(id: "main")
            NSApplication.shared.activate()
        }
    }
}
