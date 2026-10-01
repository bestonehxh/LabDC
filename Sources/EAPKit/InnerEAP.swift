import Foundation
import RADIUSKit

/// Phase 2 inside PEAP and TTLS (1 Oct 2026): one inner EAP conversation — Identity, then
/// EAP-MSCHAPv2 (RFC 2759 in EAP, draft-kamath-pppext-eap-mschapv2) or EAP-GTC (RFC 3748 §5.6)
/// when the peer NAKs to it. MS-CHAPv2 answers account states with the Windows codes (E=647
/// disabled, E=648 password expired, E=646 logon hours, E=691 otherwise) and, after E=648,
/// accepts a Change-Password (OpCode 7) so Windows can change an expired password at the
/// Wi-Fi/wired logon. Works on full EAP packets; PEAP compresses the header away, TTLS wraps
/// them in EAP-Message AVPs.
final class InnerEAP: @unchecked Sendable {   // only touched from the EAPServer actor
    enum Outcome {
        /// Send this EAP-Request (a full packet).
        case send([UInt8])
        /// Done: the account, the MS-CHAPv2 ISK for PEAP crypto binding (nil for GTC).
        case success(account: String, isk: [UInt8]?, method: String, passwordChanged: Bool)
        case failure(reason: String, account: String?, method: String)
    }

    private enum Step {
        case identity
        case mschapChallenge(challenge: [UInt8], msID: UInt8)
        case mschapChange(challenge: [UInt8], msID: UInt8, name: String)
        case mschapSuccessSent(account: String, isk: [UInt8], changed: Bool)
        case mschapFailureSent(reason: String, account: String?)
        case gtcSent
        case done
    }

    private var step = Step.identity
    private(set) var id: UInt8
    private(set) var user = ""
    private let serverName: String
    private let methods: [EAPType]
    private var tried: Set<EAPType> = []
    /// The method in use, for the facts (`EAP-MSCHAPv2`, `EAP-GTC`).
    private(set) var method = EAPType.mschapv2

    init(firstID: UInt8 = 0, serverName: String, methods: [EAPType] = [.mschapv2, .gtc]) {
        id = firstID
        self.serverName = serverName
        self.methods = methods.filter { $0 == .mschapv2 || $0 == .gtc }
    }

    private func request(_ type: EAPType, _ data: [UInt8]) -> Outcome {
        id &+= 1
        return .send(EAPPacket(code: .request, id: id, type: type.rawValue, data: data).bytes)
    }

    /// PEAP starts phase 2 with an EAP-Request/Identity (TTLS peers send their identity unasked).
    func start() -> [UInt8] {
        id &+= 1
        return EAPPacket(code: .request, id: id, type: EAPType.identity.rawValue).bytes
    }

    /// The next id the tunnel's own requests (PEAP's EAP-TLV) should use.
    func nextID() -> UInt8 { id &+= 1; return id }

    func handle(type: UInt8, data: [UInt8], backend: EAPBackend) async -> Outcome {
        switch step {
        case .identity:
            guard type == EAPType.identity.rawValue else { return fail("expected the inner identity", account: nil) }
            user = String(decoding: data, as: UTF8.self)
            return offer(methods.first ?? .mschapv2)
        case .mschapChallenge(let challenge, let msID):
            if type == EAPType.nak.rawValue { return nak(data) }
            // [2][MS-CHAPv2-ID][MS-Length][49][Peer-Challenge 16][Reserved 8][NT-Response 24][Flags][Name]
            guard type == EAPType.mschapv2.rawValue, data.count >= 54, data[0] == 2, data[4] == 49 else {
                return fail("malformed EAP-MSCHAPv2 response", account: user)
            }
            let response = MSCHAPv2.Response(ident: msID, flags: data[53], peerChallenge: Array(data[5..<21]), ntResponse: Array(data[29..<53]))
            let name = data.count > 54 ? String(decoding: data[54...], as: UTF8.self) : user
            return mschapResult(await backend.verifyMSCHAPv2(user: name, challenge: challenge, response: response),
                                msID: msID, name: name, changed: false)
        case .mschapChange(let challenge, _, let name):
            // [7][MS-CHAPv2-ID][MS-Length][Encrypted-Password 516][Encrypted-Hash 16][Peer-Challenge 16][Reserved 8][NT-Response 24][Flags 2]
            guard type == EAPType.mschapv2.rawValue, let op = data.first else { return fail("malformed EAP-MSCHAPv2 response", account: name) }
            if op == 4 { return .failure(reason: "the password has expired and was not changed", account: name, method: method.title) }
            guard op == 7, data.count >= 4, let change = MSCHAPv2.ChangePassword(Array(data.dropFirst(4))) else {
                return fail("malformed EAP-MSCHAPv2 Change-Password", account: name)
            }
            return mschapResult(await backend.changePassword(user: name, challenge: challenge, change: change),
                                msID: data[1], name: name, changed: true)
        case .mschapSuccessSent(let account, let isk, let changed):
            guard type == EAPType.mschapv2.rawValue, data.first == 3 else {
                return fail("expected the MS-CHAPv2 success acknowledgement", account: account)
            }
            step = .done
            return .success(account: account, isk: isk, method: method.title, passwordChanged: changed)
        case .mschapFailureSent(let reason, let account):
            step = .done
            return .failure(reason: reason, account: account, method: method.title)
        case .gtcSent:
            if type == EAPType.nak.rawValue { return nak(data) }
            guard type == EAPType.gtc.rawValue else { return fail("expected an EAP-GTC response", account: user) }
            var password = String(decoding: data, as: UTF8.self)
            if password.hasPrefix("RESPONSE="), let nul = data.firstIndex(of: 0) {   // RESPONSE=<id>\0<password>
                password = String(decoding: data[(nul + 1)...], as: UTF8.self)
            }
            step = .done
            switch await backend.verifyPassword(user: user, password: password) {
            case .success(let account, _): return .success(account: account, isk: nil, method: method.title, passwordChanged: false)
            case .failure(let why), .denied(let why, _), .passwordExpired(_, let why):
                return .failure(reason: why, account: user, method: method.title)
            }
        case .done:
            return fail("unexpected inner EAP data", account: user)
        }
    }

    private func offer(_ type: EAPType) -> Outcome {
        method = type
        tried.insert(type)
        switch type {
        case .gtc:
            step = .gtcSent
            return request(.gtc, Array("Password".utf8))
        default:
            var challenge = [UInt8](repeating: 0, count: 16)
            _ = SecRandomCopyBytes(kSecRandomDefault, 16, &challenge)
            let msID = UInt8.random(in: 0...255)
            step = .mschapChallenge(challenge: challenge, msID: msID)
            return request(.mschapv2, Self.withMSLength([1, msID, 0, 0, 16] + challenge + Array(serverName.utf8)))
        }
    }

    private func nak(_ wanted: [UInt8]) -> Outcome {
        guard let next = wanted.compactMap(EAPType.init(rawValue:)).first(where: { methods.contains($0) && !tried.contains($0) }) else {
            return fail("the client refused \(method.title)", account: user)
        }
        return offer(next)
    }

    private func mschapResult(_ result: EAPAuthResult, msID: UInt8, name: String, changed: Bool) -> Outcome {
        switch result {
        case .success(let account, let mschap?):
            let message = Array((String(decoding: mschap.successValue.dropFirst(), as: UTF8.self) + " M=Authentication succeeded").utf8)
            step = .mschapSuccessSent(account: account, isk: MSCHAPv2.innerSessionKey(mschap), changed: changed)
            return request(.mschapv2, Self.withMSLength([3, msID, 0, 0] + message))
        case .success(let account, nil):
            return fail("MS-CHAPv2 without key material", account: account)
        case .passwordExpired(let account, let reason):
            // E=648 with a fresh challenge: the peer answers with a Change-Password over it.
            var challenge = [UInt8](repeating: 0, count: 16)
            _ = SecRandomCopyBytes(kSecRandomDefault, 16, &challenge)
            if changed {   // a second expiry after a change cannot happen; refuse rather than loop
                return failure(.changingPassword, reason: reason, account: account, msID: msID)
            }
            step = .mschapChange(challenge: challenge, msID: msID, name: name)
            let message = Array(MSCHAPv2.failureMessage(.passwordExpired, challenge: challenge).utf8)
            return request(.mschapv2, Self.withMSLength([4, msID, 0, 0] + message))
        case .denied(let reason, let code):
            return failure(code, reason: reason, account: name, msID: msID)
        case .failure(let reason):
            return failure(changed ? .changingPassword : .authenticationFailure, reason: reason, account: name, msID: msID)
        }
    }

    private func failure(_ code: MSCHAPv2.ErrorCode, reason: String, account: String?, msID: UInt8) -> Outcome {
        var challenge = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &challenge)
        step = .mschapFailureSent(reason: reason, account: account)
        let message = Array(MSCHAPv2.failureMessage(code, challenge: challenge).utf8)
        return request(.mschapv2, Self.withMSLength([4, msID, 0, 0] + message))
    }

    private func fail(_ reason: String, account: String?) -> Outcome {
        step = .done
        return .failure(reason: reason, account: account, method: method.title)
    }

    /// Fills MS-Length (bytes 2–3: the EAP-MSCHAPv2 data from OpCode on).
    static func withMSLength(_ body: [UInt8]) -> [UInt8] {
        var b = body
        b[2] = UInt8(b.count >> 8 & 0xff); b[3] = UInt8(b.count & 0xff)
        return b
    }
}
