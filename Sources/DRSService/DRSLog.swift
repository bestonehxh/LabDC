import Foundation
import RPCKit
import os

/// The DRSUAPI operational log (WP-AM), in the style of WP-AK's `NETLOGON` lines: one line per
/// DsBind / DsUnbind / DsDomainControllerInfo and one per cracked name, e.g.
///
///     DsCrackNames offered=7(CANONICAL) desired=2(NT4_ACCOUNT) flags=0x0 "lab.sheep/" from Administrator@10.0.0.5 -> OK LABSHEEP\
///
/// `labdc serve` prints them as the `DRSUAPI` component. Only names and statuses are logged —
/// DRSUAPI carries no secrets in the calls served here.
extension DRSService {
    private static let logger = Logger(subsystem: "dev.labdc.app", category: "DRSUAPI")

    func logEvent(_ line: String) {
        Self.logger.info("\(line, privacy: .public)")
        onEvent?(line)
    }

    /// `Administrator@10.0.0.5` (the authenticated account, then the peer address).
    static func caller(_ context: RPCCallContext) -> String {
        let who = context.identity.isAnonymous ? "anonymous" : context.identity.sam
        return "\(who)@\(context.clientAddress)"
    }

    /// A client-supplied name, quoted, with control characters escaped (canonical-EX names carry a
    /// `\n`) and long values cut.
    static func quote(_ s: String) -> String {
        var out = ""
        for scalar in s.unicodeScalars.prefix(256) {
            switch scalar {
            case "\n": out += "\\n"
            case "\"": out += "\\\""
            case _ where scalar.value < 0x20 || scalar.value == 0x7F:
                out += String(format: "\\x%02X", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        if s.unicodeScalars.count > 256 { out += "..." }
        return "\"\(out)\""
    }

    /// `OK CN=...` / `notFound` (the pDomain of a regular lookup is always our DNS domain; not logged).
    private static func describe(_ item: CrackItem) -> String {
        var s = DSNameError.describe(item.status)
        if let name = item.name { s += " " + quoteIfNeeded(name) }
        return s
    }

    /// Result names are printed bare unless they contain a control character.
    private static func quoteIfNeeded(_ s: String) -> String {
        s.unicodeScalars.contains { $0.value < 0x20 } ? quote(s) : s
    }

    func logCrackNames(offeredRaw: UInt32, desiredRaw: UInt32, flags: UInt32, names: [String],
                       results: [CrackItem]?, context: RPCCallContext) {
        let head = "DsCrackNames offered=\(DSNameFormat.describe(offeredRaw)) "
            + "desired=\(DSNameFormat.describe(desiredRaw)) flags=0x\(String(flags, radix: 16, uppercase: true))"
        let from = " from \(Self.caller(context))"
        guard let results else {
            let what = names.isEmpty ? "" : " " + names.map(Self.quote).joined(separator: ",")
            logEvent(head + what + from + " -> unsupported (no result, as Samba)")
            return
        }
        let offered = DSNameFormat(rawValue: offeredRaw)
        if let offered, offered.isListFormat {
            let args = names.isEmpty ? "" : " " + names.map(Self.quote).joined(separator: ",")
            let items = results.map { item -> String in
                var s = item.status == 0 ? "" : DSNameError.describe(item.status) + " "
                s += item.name.map(Self.quoteIfNeeded) ?? "-"
                if let d = item.domain { s += " [\(d)]" }
                return s
            }
            logEvent(head + args + from + " -> \(results.count) item(s)"
                     + (items.isEmpty ? "" : ": " + items.joined(separator: "; ")))
            return
        }
        for (i, item) in results.enumerated() {
            let name = i < names.count ? Self.quote(names[i]) : "-"
            logEvent(head + " " + name + from + " -> " + Self.describe(item))
        }
    }
}

extension DSNameFormat {
    /// Formats whose answer is a list rather than one item per offered name.
    var isListFormat: Bool {
        switch self {
        case .listSites, .listServersInSite, .listDomains, .listNCs, .listDomainsInSite,
             .listServersForDomainInSite, .listServersWithDCsInSite, .listInfoForServer, .listRoles,
             .listGlobalCatalogServers, .mapSchemaGUID:
            return true
        default:
            return false
        }
    }
}
