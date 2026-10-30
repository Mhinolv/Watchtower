import Foundation

// Evidence rows for the detail pane of an app, an item or a finding (#17). The running version is separate from the
// installed version. The engine writes the running facts into item attributes (`runningState`, `runningVersion`,
// `runningKind`, `runningChecked`). Unknown stays unknown: a denied or skipped probe never reads "not running", and
// the Deployment row is `Unknown` because no check writes it.

public enum RunningState: String, Sendable, Equatable {
    case notChecked = "not_checked"
    case known
    case none
    case denied
    case unknownVersion = "unknown_version"
}

public struct RunningEvidence: Sendable {
    /// The attribute keys of this evidence. Other attribute lists leave them out.
    public static let keys: Set<String> = ["runningState", "runningVersion", "runningKind", "runningChecked"]

    public var state: RunningState
    /// The version that runs. For `kind == "build"` it is a build number, not a version.
    public var version: String?
    /// `version` or `build`.
    public var kind: String
    public var checked: Date?
    public var installed: String?
    /// The installed build (`CFBundleVersion`). Missing: it equals the installed version.
    public var installedBuild: String?
    public var name: String
    private let time: TimeText

    /// nil if the engine has no running probe for the item (macOS, casks, SDKs) or the scan is from before #17.
    /// If `enabled` is false (the owner turned the check off), the state is `notChecked` and old data stays hidden.
    public init?(_ item: ItemRecord, enabled: Bool = true, time: TimeText = TimeText()) {
        let a = item.attributes ?? [:]
        guard let raw = a["runningState"], let stored = RunningState(rawValue: raw) else { return nil }
        self.time = time
        name = item.name
        installed = item.installedVersion
        installedBuild = a["build"] ?? item.installedVersion
        state = enabled ? stored : .notChecked
        version = enabled ? a["runningVersion"] : nil
        kind = a["runningKind"] ?? "version"
        checked = enabled ? a["runningChecked"].flatMap { ISO8601DateFormatter().date(from: $0) } : nil
    }

    /// The running version is older than the installed one. Only a version is compared, never a build number.
    public var isOlder: Bool {
        guard state == .known, kind == "version", let running = version, let installed else { return false }
        return Self.compare(running, installed) < 0
    }

    /// A build number that is not the installed build. The two numbers do not say which one is newer.
    public var differs: Bool {
        guard state == .known, kind == "build", let running = version else { return false }
        return running != installedBuild
    }

    public var needsRestart: Bool { isOlder || differs }

    /// `Restart Slack.` nil if the running version is not older.
    public var restartText: String? { needsRestart ? "Restart \(name)." : nil }

    /// The full text: `Running: 2.4.1` and the other states of the design.
    public var text: String {
        switch state {
        case .notChecked: return "Running: not checked"
        case .denied: return "Running: not known (permission denied)"
        case .unknownVersion: return "Running: process found, version not known"
        case .none: return checked.map { "Running: no process found at \(time.absolute($0))" } ?? "Running: no process found"
        case .known:
            let running = version ?? "?"
            if isOlder { return "Running \(running) is older than installed \(installed ?? "?"). \(restartText ?? "")" }
            if differs { return "Running build \(running) differs from installed build \(installedBuild ?? "?"). \(restartText ?? "")" }
            return kind == "build" ? "Running: build \(running)" : "Running: \(running)"
        }
    }

    /// The value column of the `Running` row: the text without the `Running: ` prefix.
    public var value: String {
        text.hasPrefix("Running: ") ? String(text.dropFirst("Running: ".count)) : text
    }

    public var tone: Tone { needsRestart ? .orange : .secondary }

    /// Compare two versions part by part: numbers as numbers, then text. `2.10.0` is newer than `2.9.9`.
    static func compare(_ a: String, _ b: String) -> Int {
        func parts(_ s: String) -> [String] {
            s.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
        }
        let (x, y) = (parts(a), parts(b))
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : "0", r = i < y.count ? y[i] : "0"
            if let ln = Int(l), let rn = Int(r) {
                if ln != rn { return ln < rn ? -1 : 1 }
            } else if l != r {
                return l < r ? -1 : 1
            }
        }
        return 0
    }
}

public struct EvidenceRow: Equatable, Sendable {
    public var label: String
    public var value: String
    public var tone: Tone
    /// What VoiceOver reads for the row.
    public var accessibilityText: String
}

public enum Evidence {
    public static let deploymentUnknown = "Unknown"
    public static let noImages = "None found"

    /// Installed, Running and Deployment for an app, a formula or a runtime. No Lockfile or Container image row.
    public static func rows(for item: ItemRecord, enabled: Bool = true, time: TimeText = TimeText()) -> [EvidenceRow] {
        var rows = [EvidenceRow(label: "Installed", value: item.installedVersion ?? "—", tone: .secondary,
                                accessibilityText: "Installed: \(item.installedVersion ?? "not known")")]
        if let running = RunningEvidence(item, enabled: enabled, time: time) {
            rows.append(EvidenceRow(label: "Running", value: running.value, tone: running.tone, accessibilityText: running.text))
        }
        rows.append(deployment)
        return rows
    }

    /// Installed, Lockfile, Running, Container image and Deployment for a finding, in this order.
    /// The engine does not read `node_modules`, so Installed has a value only from a `.venv` check.
    public static func rows(for finding: FindingRecord, projects: [ProjectRecord], enabled: Bool = true) -> [EvidenceRow] {
        func distinct(_ values: [String]) -> [String] {
            var seen = Set<String>()
            return values.filter { seen.insert($0).inserted }
        }
        let venv = distinct(finding.paths.compactMap { $0.evidence?.installed })
        let locked = distinct(finding.paths.filter { !$0.isRequirements }.map(\.version))
        let projectPaths = distinct(finding.paths.map(\.projectPath))
        let found = projectPaths.compactMap { path in projects.first { $0.displayPath == path } }
        let images = distinct(found.flatMap { $0.containerImages ?? [] })
        // `None found` needs proof: every project was read and its list is empty. A project that was not read stays `Unknown`.
        let allRead = !projectPaths.isEmpty && found.count == projectPaths.count && found.allSatisfy { $0.containerImages != nil }
        let imageValue = !images.isEmpty ? images.joined(separator: ", ") : (allRead ? noImages : "Unknown")
        let runningValue = enabled ? "not known" : "not checked"
        return [
            EvidenceRow(label: "Installed", value: venv.isEmpty ? "not checked" : venv.joined(separator: ", "), tone: .secondary,
                        accessibilityText: "Installed: \(venv.isEmpty ? "not checked" : venv.joined(separator: ", "))"),
            EvidenceRow(label: "Lockfile", value: locked.isEmpty ? "—" : locked.joined(separator: ", "), tone: .secondary,
                        accessibilityText: "Lockfile: \(locked.isEmpty ? "none" : locked.joined(separator: ", "))"),
            EvidenceRow(label: "Running", value: runningValue, tone: .secondary, accessibilityText: "Running: \(runningValue)"),
            EvidenceRow(label: "Container image", value: imageValue, tone: .secondary,
                        accessibilityText: "Container image: \(imageValue). Metadata only."),
            deployment,
        ]
    }

    static var deployment: EvidenceRow {
        EvidenceRow(label: "Deployment", value: deploymentUnknown, tone: .secondary,
                    accessibilityText: "Deployment: \(deploymentUnknown)")
    }
}

extension ItemRecord {
    /// The attributes for a generic list, without the running keys.
    public var attributesWithoutRunning: [String: String] {
        (attributes ?? [:]).filter { !RunningEvidence.keys.contains($0.key) }
    }
}

/// The settings that the engine keeps in `settings.json` (#17).
public struct EngineSettings: Codable, Equatable, Sendable {
    /// On by default (owner decision 2026-10-29).
    public var checkRunningVersions: Bool

    public init(checkRunningVersions: Bool = true) {
        self.checkRunningVersions = checkRunningVersions
    }
}

struct SettingsResponse: Codable, Sendable {
    var schemaVersion: Int
    var settings: EngineSettings
}
