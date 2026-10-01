import Foundation
import RPCKit
import Store
import SheepCrypto

extension NetlogonService {

    /// `NetrLogonGetCapabilities` (opnum 21): return the negotiated flags (levels 1 and 2).
    func getCapabilities(_ r: NDRReader) async throws -> NDRWriter {
        _ = try NLNDR.readInlineWSTR(r)                     // ServerName (LOGONSRV_HANDLE)
        let computer = try NLNDR.readTopLevelString(r) ?? ""
        let auth = try readAuthenticator(r)
        _ = try readAuthenticator(r)                        // ReturnAuthenticator (client sends zeros)
        let level = try r.u32()                             // QueryLevel

        let w = NDRWriter()
        guard let channel = state.channel(computer: computer) else {
            writeAuthenticator(w, credential: [UInt8](repeating: 0, count: 8), timestamp: 0)
            w.u32(level); w.u32(0)                          // NETLOGON_CAPABILITIES tag + value
            w.u32(NLStatus.accessDenied)
            return w
        }
        let step = stepAuthenticator(channel, received: auth)
        writeAuthenticator(w, credential: step.returnCredential, timestamp: 0)
        // The union tag must equal QueryLevel (Samba's NDR pull rejects any other switch value).
        // Level 1: ServerCapabilities = the negotiated flags. Level 2: RequestedFlags = what the
        // client sent in Authenticate3 (downgrade detection, MS-NRPC §3.5.4.4.10). WP-Z.
        switch level {
        case 1, 2:
            w.u32(level)
            w.u32(level == 2 ? channel.requestedFlags : channel.negotiatedFlags.rawValue)
            w.u32(step.ok ? NLStatus.success : NLStatus.accessDenied)
        default:
            w.u32(level); w.u32(0)
            w.u32(NLStatus.invalidLevel)
        }
        return w
    }

    /// `NetrServerPasswordSet2` (opnum 30): decrypt the `NL_TRUST_PASSWORD` and rotate the key.
    func passwordSet2(_ r: NDRReader) async throws -> NDRWriter {
        _ = try NLNDR.readTopLevelString(r)                 // PrimaryName
        let accountName = try NLNDR.readInlineWSTR(r)       // AccountName ("PC1$")
        _ = try r.enum16()                                  // SecureChannelType
        let computer = try NLNDR.readInlineWSTR(r)          // ComputerName
        let auth = try readAuthenticator(r)
        let blob = try r.take(516)                          // NL_TRUST_PASSWORD_FIXED_ARRAY

        let w = NDRWriter()
        let logHead = "ServerPasswordSet2 \(accountName) (\(computer))"
        guard let channel = state.channel(computer: computer) else {
            logEvent(logHead + fromClause(account: nil) + Self.outcome(NLStatus.accessDenied, "no secure channel"))
            writeAuthenticator(w, credential: [UInt8](repeating: 0, count: 8), timestamp: 0)
            w.u32(NLStatus.accessDenied)
            return w
        }
        let step = stepAuthenticator(channel, received: auth)
        guard step.ok else {
            logEvent(logHead + fromClause(account: nil) + Self.outcome(NLStatus.accessDenied, "authenticator mismatch"))
            writeAuthenticator(w, credential: step.returnCredential, timestamp: 0)
            w.u32(NLStatus.accessDenied)
            return w
        }
        // A member may only change its own trust password: the account and computer must be the
        // ones the secure channel was established for (as Windows/Samba; GetTrustInfo checks the same).
        guard accountName.caseInsensitiveCompare(channel.accountName) == .orderedSame,
              computer.caseInsensitiveCompare(channel.computerName) == .orderedSame else {
            logEvent(logHead + fromClause(account: channel.accountName)
                     + Self.outcome(NLStatus.accessDenied, "account is not the channel's \(channel.accountName)"))
            writeAuthenticator(w, credential: step.returnCredential, timestamp: 0)
            w.u32(NLStatus.accessDenied)
            return w
        }

        let plain = channel.usesAES
            ? NetlogonCrypto.aesCFB8(key: channel.sessionKey, iv: [UInt8](repeating: 0, count: 16), blob, encrypt: false)
            : RC4.apply(key: channel.sessionKey, blob)
        // NL_TRUST_PASSWORD: Buffer[512] then Length (bytes) at offset 512; password is the tail.
        var status = NLStatus.success
        var reason: String?
        if plain.count == 516 {
            let length = Int(UInt32(plain[512]) | (UInt32(plain[513]) << 8)
                             | (UInt32(plain[514]) << 16) | (UInt32(plain[515]) << 24))
            if length == 0 {
                // An empty trust password is the Zerologon end state; never store it.
                status = NLStatus.accessDenied; reason = "empty password refused"
            } else if length <= 512, length % 2 == 0 {
                let pwBytes = Array(plain[(512 - length)..<512])
                var units = [UInt16](); units.reserveCapacity(length / 2)
                for i in stride(from: 0, to: length, by: 2) { units.append(UInt16(pwBytes[i]) | (UInt16(pwBytes[i + 1]) << 8)) }
                let password = String(decoding: units, as: UTF16.self)
                if let entry = try? await store.read(sam: accountName) {
                    do {
                        try await store.setPassword(id: entry.id, password: password, enforcePolicy: false)
                        if let kvno = try? await store.secrets(id: entry.id)?.kvno { reason = "kvno \(kvno)" }
                    } catch {
                        // Refuse so the member keeps its old password (the DC still has it).
                        status = NLStatus.accessDenied; reason = "store: \(error)"
                    }
                } else { status = NLStatus.noTrustSamAccount; reason = "no such machine account" }
            } else { status = NLStatus.invalidParameter; reason = "bad NL_TRUST_PASSWORD length" }
        } else { status = NLStatus.invalidParameter }
        logEvent(logHead + fromClause(account: channel.accountName) + Self.outcome(status, reason))

        writeAuthenticator(w, credential: step.returnCredential, timestamp: 0)
        w.u32(status)
        return w
    }
}
