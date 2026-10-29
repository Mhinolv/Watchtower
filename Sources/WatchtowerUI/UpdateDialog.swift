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
        .padding(20)
        .frame(width: 580)
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

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Update \(plan.name)").font(.title2).bold()
                Text(plan.versionLine).foregroundStyle(.secondary)
            }
            Grid(alignment: .topLeading, horizontalSpacing: 14, verticalSpacing: 10) {
                GridRow {
                    Text("Command").foregroundStyle(.secondary)
                    HStack(alignment: .top) {
                        Text(plan.commandText)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Button {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(plan.commandText, forType: .string)
                        } label: {
                            Label("Copy", systemImage: "doc.on.doc")
                        }
                        .help("Copy the command")
                    }
                }
                if let rows = plan.rows, !rows.isEmpty {
                    ForEach(rows, id: \.label) { row in
                        GridRow {
                            Text(row.label).foregroundStyle(.secondary)
                            PlanRowValue(row: row)
                        }
                    }
                } else {
                    GridRow {
                        Text("Also changes").foregroundStyle(.secondary)
                        if plan.alsoChanges.isEmpty {
                            Text("No other packages change.")
                        } else {
                            VStack(alignment: .leading, spacing: 2) {
                                ForEach(plan.alsoChanges, id: \.name) { change in
                                    Text(change.change == "install"
                                         ? "\(change.name) \(change.after ?? "") (new)"
                                         : "\(change.name) \(change.before ?? "?") → \(change.after ?? "?")")
                                }
                            }
                        }
                    }
                    GridRow {
                        Text("Scripts").foregroundStyle(.secondary)
                        Text(plan.scripts.isEmpty ? "Disabled" : "Needed: \(plan.scripts.joined(separator: ", "))")
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
        .onAppear { cancelFocused = true }
    }
}

/// The value of a plan row. A row with a list opens it under a disclosure, for example `3 packages`.
struct PlanRowValue: View {
    let row: PlanRow
    @State private var opened = false

    var body: some View {
        if let items = row.items, !items.isEmpty {
            DisclosureGroup(row.value, isExpanded: $opened) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(items, id: \.self) { Text($0).font(.callout.monospaced()) }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } else {
            Text(row.value).textSelection(.enabled)
        }
    }
}

struct ScriptsStep: View {
    let model: UpdateModel
    let plan: UpdatePlan

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Install scripts", systemImage: "terminal").font(.title3).bold()
            Text(plan.scriptsText)
            Text("Watchtower runs them only after this second confirmation.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Not Now") { model.backToPlan() }.keyboardShortcut(.cancelAction)
                Button("Run Scripts") { Task { await model.confirmScripts() } }
            }
        }
    }
}

struct RunningStep: View {
    let plan: UpdatePlan
    let output: [String]
    @State private var showsOutput = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Update \(plan.name)").font(.title2).bold()
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text("Running…")
            }
            .accessibilityElement(children: .combine)
            DisclosureGroup("Show output", isExpanded: $showsOutput) {
                OutputText(text: output.joined(separator: "\n"))
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
            Text("Update \(attempt.name)").font(.title2).bold()
            Label(style.text, systemImage: style.symbol)
                .foregroundStyle(style.tone.color)
                .accessibilityAddTraits(.isHeader)
            if let rows = attempt.resultRows, !rows.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(rows, id: \.label) { row in
                        Text("\(row.label): \(row.value)").textSelection(.enabled)
                    }
                }
            }
            if attempt.status == .verified, !attempt.manualSteps.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Manual steps").font(.headline)
                    ForEach(attempt.manualSteps, id: \.self) { Text("• \($0)") }
                }
            }
            if !attempt.output.isEmpty {
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
                Button("Done") { model.close() }.keyboardShortcut(.defaultAction)
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
