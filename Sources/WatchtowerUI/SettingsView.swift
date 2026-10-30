import SwiftUI
import WatchtowerCore

/// Settings (⌘,). Tab `General`: the running-version check (#17). Tab `Projects`: turn a project off to move it to Backlog.
public struct SettingsView: View {
    let model: DashboardModel

    public init(model: DashboardModel) {
        self.model = model
    }

    public var body: some View {
        TabView {
            GeneralSettings(model: model)
                .tabItem { Label("General", systemImage: "gearshape") }
            ProjectSettings(model: model)
                .tabItem { Label("Projects", systemImage: "folder") }
        }
        .frame(width: 560, height: 380)
    }
}

struct ProjectSettings: View {
    let model: DashboardModel

    var body: some View {
        if model.projects.isEmpty {
            ContentUnavailableView("No projects", systemImage: "folder",
                                   description: Text("Watchtower looks in ~/Projects and ~/Real."))
        } else {
            VStack(alignment: .leading, spacing: 8) {
                Table(model.projects) {
                    TableColumn("Active") { project in
                        Toggle("Active", isOn: Binding(
                            get: { project.isActive },
                            set: { on in Task { await model.setProject(project, active: on) } }
                        ))
                        .labelsHidden()
                        .disabled(project.state == "inaccessible")
                        .accessibilityLabel("\(project.name) active")
                    }
                    .width(52)
                    TableColumn("Name", value: \.name)
                    TableColumn("Path") { project in
                        Text(project.displayPath).foregroundStyle(.secondary)
                    }
                }
                Text("A project that is turned off moves to Backlog. Watchtower does not scan it.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding()
        }
    }
}

struct GeneralSettings: View {
    let model: DashboardModel

    var body: some View {
        Form {
            Toggle("Check running versions", isOn: Binding(
                get: { model.checkRunningVersions },
                set: { on in Task { await model.setCheckRunningVersions(on) } }
            ))
            Text("Reads process versions. Watchtower never starts services or reads credentials.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .padding()
    }
}
