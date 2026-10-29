import AppKit
import SwiftUI
import WatchtowerCore

/// The shared update sheet: plan, major-version alert, scripts, running, result.
public struct UpdateDialog: View {
    let model: UpdateModel

    public init(model: UpdateModel) {
        self.model = model
    }

    public var body: some View {
        Group {
            switch model.step {
            case .idle:
                EmptyView()
            case .loading(let name):
                VStack(spacing: 12) {
                    ProgressView()
                    Text("Planning the update of \(name)…")
                }
                .frame(maxWidth: .infinity, minHeight: 160)
            case .plan(let plan), .confirmMajor(let plan):
                PlanStep(model: model, plan: plan)
            case .confirmScripts(let plan):
                ScriptsStep(model: model, plan: plan)
            case .running(let plan):
                RunningStep(plan: plan, output: model.output)
            case .result(let attempt, let plan):
                ResultStep(model: model, attempt: attempt, plan: plan)
            case .failed(let error):
                FailedStep(model: model, error: error)
            }
        }
        .padding(24)
        .frame(width: 580)
        .tint(.watchtowerAccent)
        .interactiveDismissDisabled(model.isRunning)
        .alert("Update to a new major version?", isPresented: majorBinding, presenting: majorPlan) { plan in
            Button("Cancel", role: .cancel) { model.backToPlan() }
            Button("Update to \(plan.targetVersion ?? "?")") { Task { await model.confirmMajor() } }
        } message: { plan in
            Text(plan.majorWarning)
        }
    }

    var majorPlan: UpdatePlan? {
        if case .confirmMajor(let plan) = model.step { return plan }
        return nil
    }

    var majorBinding: Binding<Bool> {
        Binding(get: { majorPlan != nil }, set: { shown in if !shown { model.backToPlan() } })
    }
}

// MARK: - Steps

struct PlanStep: View {
    let model: UpdateModel
    let plan: UpdatePlan
    @FocusState private var cancelFocused: Bool
    @State var showsChanges = false

    var body: some View {
        if let refusal = plan.refusal, plan.targetVersion == nil {
            notSupported(refusal)
        } else {
            fullPlan
        }
    }

    /// The engine refused before it had a target: title, reason, Cancel. Update stays off.
    func notSupported(_ refusal: String) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Update \(plan.name)").font(.system(size: 16, weight: .bold))
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "hand.raised").font(.system(size: 22)).foregroundStyle(Tone.orange.color)
                VStack(alignment: .leading, spacing: 3) {
                    Text(refusal).font(.system(size: 14, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    ForEach(plan.rows ?? [], id: \.label) { row in
                        Text("\(row.label): \(row.value)").foregroundStyle(.secondary)
                    }
                }
            }
            .accessibilityElement(children: .combine)
            HStack {
                Spacer()
                Button("Cancel") { model.close() }
                    .keyboardShortcut(.cancelAction)
                    .focused($cancelFocused)
                Button("Update") {}.disabled(true).help(refusal)
            }
        }
        .onAppear { cancelFocused = true }
    }

    var fullPlan: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Update \(plan.name)").font(.system(size: 16, weight: .bold))
                Text(plan.versionLine).foregroundStyle(.secondary)
            }
            Grid(alignment: .topLeading, horizontalSpacing: 16, verticalSpacing: 12) {
                GridRow {
                    Text("Command").foregroundStyle(.secondary)
                    CommandBox(text: plan.commandText)
                }
                ForEach(plan.rows ?? [], id: \.label) { row in
                    GridRow {
                        Text(row.label).foregroundStyle(.secondary)
                        Text(row.value).font(.callout.monospaced()).textSelection(.enabled)
                    }
                }
                GridRow {
                    Text(plan.changesTitle ?? "Also changes").foregroundStyle(.secondary)
                    if plan.alsoChanges.isEmpty {
                        Text("No other packages change.")
                    } else if plan.changesTitle != nil {
                        // Project adapters: a count, the list opens on request.
                        VStack(alignment: .leading, spacing: 4) {
                            Text(plan.changesSummary)
                            DisclosureGroup(showsChanges ? "Hide list" : "Show list", isExpanded: $showsChanges) {
                                ChangeList(changes: plan.alsoChanges)
                            }
                        }
                    } else {
                        ChangeList(changes: plan.alsoChanges)
                    }
                }
                GridRow {
                    Text("Scripts").foregroundStyle(.secondary)
                    if plan.scripts.isEmpty {
                        SmallBadge(text: plan.scriptsOffText ?? "Disabled", tone: .gray)
                    } else {
                        VStack(alignment: .leading, spacing: 4) {
                            SmallBadge(text: "Needed", tone: .orange)
                            Text(plan.scripts.joined(separator: ", ")).font(.callout).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            if let refusal = plan.refusal {
                Label(refusal, systemImage: "hand.raised").foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("Cancel") { model.close() }
                    .keyboardShortcut(.cancelAction)
                    .focused($cancelFocused)
                // Not the default button: Return does nothing.
                Button("Update") { Task { await model.confirm() } }
                    .disabled(plan.refusal != nil)
            }
        }
        .onAppear {
            cancelFocused = true
            showsChanges = plan.alsoChanges.count <= 5  // A short list is open at once.
        }
    }
}

/// The exact command in a monospaced box, with a Copy button inside it.
struct CommandBox: View {
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            // The owner must see the whole command: wrap, never cut it.
            Text(text)
                .font(.callout.monospaced())
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy the command")
            .accessibilityLabel("Copy")
        }
        .padding(10)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.secondary.opacity(0.25)))
    }
}

/// A small gray or colored word in a rounded box, for example the `Disabled` scripts badge.
struct SmallBadge: View {
    let text: String
    let tone: Tone

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(tone.color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(tone.color.opacity(0.14), in: RoundedRectangle(cornerRadius: 4))
    }
}

struct ScriptsStep: View {
    let model: UpdateModel
    let plan: UpdatePlan
    @FocusState private var notNowFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Update \(plan.name)").font(.system(size: 16, weight: .bold))
                Text(plan.versionLine).foregroundStyle(.secondary)
            }
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: 26))
                    .foregroundStyle(Tone.orange.color)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(plan.scriptsText).font(.system(size: 15, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text("Scripts run only after you click Run Scripts.").foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            if let details = plan.scriptDetails, !details.isEmpty {
                Grid(alignment: .leading, horizontalSpacing: 40, verticalSpacing: 8) {
                    ForEach(details, id: \.self) { d in
                        GridRow {
                            Text("Package").foregroundStyle(.secondary)
                            Text("\(d.package) \(d.version ?? "")").font(.callout.monospaced())
                        }
                        GridRow {
                            Text("Script").foregroundStyle(.secondary)
                            Text(d.script).font(.callout.monospaced())
                        }
                    }
                }
            }
            HStack {
                Spacer()
                Button("Not Now") { model.backToPlan() }
                    .keyboardShortcut(.cancelAction)
                    .focused($notNowFocused)
                Button("Run Scripts") { Task { await model.confirmScripts() } }
            }
        }
        .onAppear { notNowFocused = true }
    }
}

/// `name before → after` lines, versions right-aligned.
struct ChangeList: View {
    let changes: [PackageChange]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(changes, id: \.name) { change in
                HStack {
                    Text(change.name)
                    Spacer()
                    Text(change.change == "install" ? "new \(change.after ?? "")"
                         : change.change == "remove" ? "\(change.before ?? "?") → removed"
                         : "\(change.before ?? "?") → \(change.after ?? "?")")
                        .font(.callout.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct RunningStep: View {
    let plan: UpdatePlan
    let output: [String]
    @State private var showsOutput = true

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Update \(plan.name)").font(.system(size: 16, weight: .bold))
                Text(plan.versionLine).foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("Running…").fontWeight(.semibold)
                ProgressView().progressViewStyle(.linear)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Running")
            DisclosureGroup("Show output", isExpanded: $showsOutput) {
                OutputText(text: output.joined(separator: "\n"))
            }
            HStack {
                Spacer()
                // Escape and Done do nothing while the update runs.
                Button("Done") {}.disabled(true)
            }
        }
    }
}

struct ResultStep: View {
    let model: UpdateModel
    let attempt: UpdateAttempt
    let plan: UpdatePlan
    @State private var showsOutput = false

    var body: some View {
        let style = UpdateResultStyle(attempt)
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: style.symbol)
                    .font(.system(size: 26))
                    .foregroundStyle(style.tone.color)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(style.text).font(.system(size: 15, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    if let detail = style.detail {
                        Text(detail).foregroundStyle(.secondary)
                    }
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isHeader)
            if let checks = attempt.checks, !checks.isEmpty {
                // Project adapters: one line for each check, each with its own symbol.
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(checks, id: \.label) { check in
                        HStack(spacing: 6) {
                            Image(systemName: check.ok ? "checkmark.seal" : "exclamationmark.triangle")
                                .foregroundStyle(check.ok ? Tone.green.color : Tone.orange.color)
                            Text("\(check.label): \(check.value)")
                        }
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel("\(check.label): \(check.value), \(check.ok ? "verified" : "not verified")")
                    }
                }
            } else if attempt.status == .verified || attempt.status == .notVerified {
                Grid(alignment: .leading, horizontalSpacing: 40, verticalSpacing: 8) {
                    GridRow {
                        Text("Before").foregroundStyle(.secondary)
                        Text(attempt.beforeVersion ?? "—").monospacedDigit()
                    }
                    GridRow {
                        Text("After").foregroundStyle(.secondary)
                        Text(attempt.afterVersion ?? "—").monospacedDigit()
                    }
                }
            }
            if attempt.status == .verified, !attempt.manualSteps.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Manual steps").font(.headline)
                    ForEach(attempt.manualSteps, id: \.self) { Text("• \($0)") }
                }
            }
            if !attempt.output.isEmpty, attempt.status != .verified, attempt.status != .notVerified {
                DisclosureGroup("Show output", isExpanded: $showsOutput) {
                    OutputText(text: attempt.output)
                }
            }
            HStack {
                if attempt.status == .planChanged {
                    Button("Review") { model.review() }
                }
                Spacer()
                Button("View Log") { model.viewLog() }
                Button("Done") { model.close() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .onAppear {
            AccessibilityNotification.Announcement(style.text).post()
        }
    }
}

struct FailedStep: View {
    let model: UpdateModel
    let error: EngineError

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(error.message, systemImage: "xmark.octagon").foregroundStyle(.red)
            if let detail = error.detail {
                OutputText(text: detail)
            }
            HStack {
                Spacer()
                Button("Done") { model.close() }.keyboardShortcut(.defaultAction)
            }
        }
    }
}

struct OutputText: View {
    let text: String

    var body: some View {
        ScrollView {
            Text(text.isEmpty ? "No output yet." : text)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(height: 140)
    }
}

// MARK: - Update Log

struct UpdateLogTable: View {
    @Bindable var model: UpdateModel

    var body: some View {
        if model.attempts.isEmpty {
            ContentUnavailableView("No updates yet", systemImage: "list.bullet.rectangle",
                                   description: Text("Every update attempt shows here."))
        } else {
            Table(model.attempts, selection: $model.selectedAttemptID) {
                TableColumn("Time") { a in Text(TimeText().absolute(a.startedAt)) }
                    .width(min: 90, ideal: 110)
                TableColumn("Item") { a in Text(a.name) }
                TableColumn("Before") { a in Text(a.beforeVersion ?? "—") }
                    .width(min: 60, ideal: 80)
                TableColumn("After") { a in Text(a.afterVersion ?? "—") }
                    .width(min: 60, ideal: 80)
                TableColumn("Result") { a in
                    let style = UpdateResultStyle(a)
                    Label(a.status.text, systemImage: style.symbol).foregroundStyle(style.tone.color)
                }
                .width(min: 110, ideal: 120)
            }
        }
    }
}

struct UpdateLogDetail: View {
    let attempt: UpdateAttempt

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(attempt.name).font(.title2).bold()
                let style = UpdateResultStyle(attempt)
                Label(style.text, systemImage: style.symbol).foregroundStyle(style.tone.color)
                Text("Command").font(.headline)
                Text(attempt.commandText).font(.callout.monospaced()).textSelection(.enabled)
                Text("Output").font(.headline)
                Text(attempt.output.isEmpty ? "No output." : attempt.output)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Wiring

/// `Update…` for one npm package in one project. Off, with the reason as help, when not supported.
struct NpmUpdateButton: View {
    let finding: FindingRecord
    let path: FindingPath
    @Environment(UpdateModel.self) private var updates: UpdateModel?

    var body: some View {
        let reason = updates == nil ? "Updates are not available here." : UpdateKeys.npmBlockReason(finding, path)
        Button("Update…") {
            let key = UpdateKeys.npm(projectPath: path.projectPath, lockfile: path.lockfile,
                                     package: finding.package, fixedIn: finding.fixedIn)
            Task { await updates?.start(itemKey: key, name: finding.package) }
        }
        .controlSize(.small)
        .disabled(reason != nil)
        .help(reason ?? "Show the update plan for \(finding.package) in \(path.projectPath). Nothing runs before you confirm.")
    }
}

/// Shows the update sheet when the app gives an UpdateModel in the environment.
struct UpdateSheetHost: ViewModifier {
    @Environment(UpdateModel.self) private var updates: UpdateModel?

    func body(content: Content) -> some View {
        if let updates {
            content.sheet(isPresented: Binding(get: { updates.isPresented },
                                               set: { if !$0 { updates.close() } })) {
                UpdateDialog(model: updates)
            }
        } else {
            content
        }
    }
}
