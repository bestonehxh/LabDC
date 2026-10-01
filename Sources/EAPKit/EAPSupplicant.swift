import Foundation
import RADIUSKit

/// A minimal EAP peer (the Windows/wpa_supplicant side) for in-process tests and checks:
/// EAP-TLS with a client certificate (192-bit mode too), PEAPv0 (EAP-MSCHAPv2 or EAP-GTC, the
/// Crypto-Binding TLV, a password change after E=648), TTLS with PAP, MS-CHAPv2, EAP-MSCHAPv2
/// or EAP-GTC; TLS 1.2 or 1.3; resumption from an earlier session. It fragments its own TLS
/// records (small fragments, to exercise the server's reassembly).
public final class EAPSupplicant {
    public enum Method {
        case tls(chain: [[UInt8]], keyDER: [UInt8])
        case peap(user: String, password: String)
        case peapGTC(user: String, password: String)
        case ttlsPAP(user: String, password: String)
        case ttlsMSCHAPv2(user: String, password: String)
        case ttlsEAPMSCHAPv2(user: String, password: String)
        case ttlsEAPGTC(user: String, password: String)

        var type: EAPType {
            switch self {
            case .tls: .tls
            case .peap, .peapGTC: .peap
            case .ttlsPAP, .ttlsMSCHAPv2, .ttlsEAPMSCHAPv2, .ttlsEAPGTC: .ttls
            }
        }

        var credentials: (user: String, password: String) {
            switch self {
            case .tls: ("", "")
            case .peap(let u, let p), .peapGTC(let u, let p), .ttlsPAP(let u, let p), .ttlsMSCHAPv2(let u, let p),
                 .ttlsEAPMSCHAPv2(let u, let p), .ttlsEAPGTC(let u, let p): (u, p)
            }
        }

        var innerEAP: EAPType? {
            switch self {
            case .peap, .ttlsEAPMSCHAPv2: .mschapv2
            case .peapGTC, .ttlsEAPGTC: .gtc
            default: nil
            }
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case protocolError(String)
        public var description: String { if case .protocolError(let s) = self { s } else { "?" } }
    }

    let identity: String
    let method: Method
    let fragmentSize: Int
    let maxTLS: UInt16
    let suiteB: Bool
    let resume: [UInt8]?
    /// After E=648, answer with a Change-Password to this password (nil: give up).
    public var newPassword: String?
    /// PEAP: answer the server's Crypto-Binding TLV (Windows / wpa_supplicant do by default).
    public var cryptoBinding = true
    /// The TLS 1.2 suites to offer (BoringSSL cipher-list syntax) instead of the default list.
    public var tls12Ciphers: String?
    private var engine: TLSEngine?
    private var inbound: [UInt8] = []
    private var pending: [TLSMethodMessage] = []
    private var sentCredentials = false
    private var password: String
    private var mschap: (challenge: [UInt8], peer: [UInt8], nt: [UInt8], user: String)?
    private var isk: [UInt8]?
    public private(set) var msk: [UInt8]?
    /// The server's certificate chain as received (leaf first), for the caller to check.
    public private(set) var serverChain: [[UInt8]] = []
    public private(set) var tlsVersion: UInt16?
    public private(set) var cipher: String?
    public private(set) var group: String?
    /// The handshake resumed `resume`.
    public private(set) var resumed = false
    /// PEAP: the Crypto-Binding TLV was exchanged (the MSK is the compound session key).
    public private(set) var usedCryptoBinding = false
    /// The last MS-CHAPv2 failure code the server sent (E=…).
    public private(set) var mschapError: Int?
    /// The TLS alert the server sent (a refused client certificate: 42, 44, 48…); the peer
    /// acknowledges it with an empty response, as wpa_supplicant does, and waits for EAP-Failure.
    public private(set) var receivedAlert: UInt8?
    /// The session to offer next time (`resume:`).
    public var session: [UInt8]? { engine?.savedSession }

    public init(identity: String, method: Method, fragmentSize: Int = 300, maxTLS: UInt16 = 0x0304,
                suiteB: Bool = false, resume: [UInt8]? = nil) {
        self.identity = identity
        self.method = method
        self.fragmentSize = fragmentSize
        self.maxTLS = maxTLS
        self.suiteB = suiteB
        self.resume = resume
        password = method.credentials.password
    }

    /// The EAP-Response to one EAP-Request (bytes in, bytes out).
    public func respond(to requestBytes: [UInt8]) throws -> [UInt8] {
        guard let request = EAPPacket(requestBytes) else { throw Failure.protocolError("not an EAP packet") }
        guard request.code == .request, let type = request.type else { throw Failure.protocolError("expected an EAP-Request") }
        func reply(_ t: UInt8, _ data: [UInt8]) -> [UInt8] { EAPPacket(code: .response, id: request.id, type: t, data: data).bytes }
        if type == EAPType.identity.rawValue { return reply(type, Array(identity.utf8)) }
        guard type == method.type.rawValue else { return reply(EAPType.nak.rawValue, [method.type.rawValue]) }
        guard let message = TLSMethodMessage(request.data) else { throw Failure.protocolError("malformed TLS-method request") }

        if message.isStart {
            let ctx: TLSContext
            switch method {
            case .tls(let chain, let key):
                ctx = try TLSContext(isServer: false, chain: chain, privateKeyDER: key, maxVersion: maxTLS, suiteBClient: suiteB,
                                     cipherList: tls12Ciphers)
            default:
                ctx = try TLSContext(isServer: false, chain: [], privateKeyDER: nil, maxVersion: maxTLS, suiteBClient: suiteB,
                                     cipherList: tls12Ciphers)
            }
            let e = try TLSEngine(context: ctx, isServer: false, eapType: type, resume: resume)
            engine = e
            e.advance()
            return try sendRecords(e.drain(), request.id, type)
        }
        guard let engine else { throw Failure.protocolError("TLS data before Start") }
        if !pending.isEmpty {
            guard message.data.isEmpty else { throw Failure.protocolError("server sent data while our fragments were pending") }
            return reply(type, pending.removeFirst().bytes)
        }
        inbound += message.data
        if message.more { return reply(type, [0]) }
        let records = inbound
        inbound = []
        engine.feed(records)
        guard engine.advance() else {
            if let alert = engine.peerAlert { receivedAlert = alert; return reply(type, [0]) }
            throw Failure.protocolError(engine.failure ?? "handshake failed")
        }
        var out = engine.drain()
        if engine.established {
            if tlsVersion == nil {
                serverChain = engine.peerCertificates; tlsVersion = engine.version
                cipher = engine.cipherName; group = engine.groupName
                resumed = engine.sessionReused
                msk = Self.msk(method.type, engine)
            }
            let app = engine.read()
            if let failure = engine.failure {
                // TLS 1.3: the client finished first; the refusal arrives as an alert afterwards.
                if let alert = engine.peerAlert { receivedAlert = alert; return reply(type, [0]) }
                throw Failure.protocolError(failure)
            }
            try tunnel(engine, app)
            out += engine.drain()
        }
        return try sendRecords(out, request.id, type)
    }

    private func sendRecords(_ out: [UInt8], _ id: UInt8, _ type: UInt8) throws -> [UInt8] {
        if out.isEmpty { return EAPPacket(code: .response, id: id, type: type, data: [0]).bytes }
        pending = TLSMethodMessage.fragments(out, size: fragmentSize, version: 0)
        return EAPPacket(code: .response, id: id, type: type, data: pending.removeFirst().bytes).bytes
    }

    /// Phase 2: what the tunnel data asks for, written into the engine (records drained by the caller).
    private func tunnel(_ engine: TLSEngine, _ app: [UInt8]) throws {
        if app == [0] { return }   // RFC 9190 / RFC 9427 protected success indication
        let (user, _) = method.credentials
        switch method {
        case .tls:
            return
        case .ttlsPAP:
            guard !sentCredentials, !resumed else { return }
            sentCredentials = true
            var pw = Array(password.utf8)
            while pw.count % 16 != 0 || pw.isEmpty { pw.append(0) }
            engine.write(TTLSAVP(code: 1, data: Array(user.utf8)).bytes + TTLSAVP(code: 2, data: pw).bytes)
        case .ttlsMSCHAPv2:
            guard !sentCredentials, !resumed else { return }   // later: the server's MS-CHAP2-Success: ack
            sentCredentials = true
            guard let material = engine.export(label: "ttls challenge", length: 17) else { throw Failure.protocolError("no exporter") }
            let challenge = Array(material.prefix(16))
            let peer = Self.random(16)
            let nt = MSCHAPv2.ntResponse(challenge: challenge, peerChallenge: peer, username: user, ntHash: MSCHAPv2.ntHash(password))
            let response = MSCHAPv2.Response(ident: material[16], peerChallenge: peer, ntResponse: nt)
            engine.write(TTLSAVP(code: 1, data: Array(user.utf8)).bytes
                         + TTLSAVP(code: 11, vendor: VendorSpecific.microsoft, data: challenge).bytes
                         + TTLSAVP(code: 25, vendor: VendorSpecific.microsoft, data: response.bytes).bytes)
        case .ttlsEAPMSCHAPv2, .ttlsEAPGTC:
            if !sentCredentials {
                guard !resumed else { return }
                sentCredentials = true
                engine.write(TTLSAVP(code: 79, data: EAPPacket(code: .response, id: 0, type: EAPType.identity.rawValue,
                                                               data: Array(user.utf8)).bytes).bytes)
                return
            }
            guard !app.isEmpty else { return }
            guard let avps = TTLSAVP.parse(app), let eap = avps.first(where: { $0.code == 79 })?.data,
                  let request = EAPPacket(eap), let type = request.type else { throw Failure.protocolError("expected an EAP-Message AVP") }
            if let answer = try innerAnswer(type: type, data: request.data) {
                engine.write(TTLSAVP(code: 79, data: EAPPacket(code: .response, id: request.id, type: answer.first ?? 0,
                                                               data: Array(answer.dropFirst())).bytes).bytes)
            }
        case .peap, .peapGTC:
            guard !app.isEmpty, let (type, data) = EAPServer.peapInner(app) else { return }
            if type == EAPType.tlv.rawValue {
                let id = app.count >= 2 ? app[1] : 0
                engine.write(EAPPacket(code: .response, id: id, type: EAPType.tlv.rawValue, data: try tlvAnswer(engine, data)).bytes)
                return
            }
            if let answer = try innerAnswer(type: type, data: data) { engine.write(answer) }
        }
    }

    /// The inner EAP answer as `[type] + data` (the compressed PEAP form).
    private func innerAnswer(type: UInt8, data: [UInt8]) throws -> [UInt8]? {
        let (user, _) = method.credentials
        switch type {
        case EAPType.identity.rawValue:
            return [EAPType.identity.rawValue] + Array(user.utf8)
        case EAPType.gtc.rawValue:
            guard method.innerEAP == .gtc else { return [EAPType.nak.rawValue, method.innerEAP?.rawValue ?? 26] }
            return [EAPType.gtc.rawValue] + Array(password.utf8)
        case EAPType.mschapv2.rawValue:
            guard method.innerEAP == .mschapv2 else { return [EAPType.nak.rawValue, EAPType.gtc.rawValue] }
            guard let op = data.first else { throw Failure.protocolError("empty EAP-MSCHAPv2") }
            switch op {
            case 1:   // Challenge: [1][id][len2][16][challenge][name]
                guard data.count >= 21 else { throw Failure.protocolError("short challenge") }
                let msID = data[1]
                let challenge = Array(data[5..<21])
                let peer = Self.random(16)
                let nt = MSCHAPv2.ntResponse(challenge: challenge, peerChallenge: peer, username: user, ntHash: MSCHAPv2.ntHash(password))
                mschap = (challenge, peer, nt, user)
                let body: [UInt8] = [2, msID, 0, 0, 49] + peer + [UInt8](repeating: 0, count: 8) + nt + [0] + Array(user.utf8)
                return [EAPType.mschapv2.rawValue] + EAPServer.withMSLength(body)
            case 3:
                if let m = mschap {
                    let keys = MSCHAPv2.mppeKeys(ntHash: MSCHAPv2.ntHash(password), ntResponse: m.nt)
                    isk = keys.recv + keys.send
                }
                return [EAPType.mschapv2.rawValue, 3]
            case 4:
                let text = String(decoding: data.dropFirst(4), as: UTF8.self)
                mschapError = text.split(separator: " ").first { $0.hasPrefix("E=") }.flatMap { Int($0.dropFirst(2)) }
                if mschapError == 648, let newPassword,
                   let c = text.split(separator: " ").first(where: { $0.hasPrefix("C=") }).map({ String($0.dropFirst(2)) }),
                   let challenge = Self.hex(c), challenge.count == 16 {
                    let peer = Self.random(16)
                    let change = MSCHAPv2.ChangePassword.make(oldPassword: password, newPassword: newPassword, username: user,
                                                              challenge: challenge, peerChallenge: peer)
                    mschap = (challenge, peer, change.ntResponse, user)
                    password = newPassword
                    self.newPassword = nil
                    return [EAPType.mschapv2.rawValue] + EAPServer.withMSLength([7, data[1] &+ 1, 0, 0] + change.bytes)
                }
                return [EAPType.mschapv2.rawValue, 4]
            default: throw Failure.protocolError("EAP-MSCHAPv2 opcode \(op)")
            }
        default:
            throw Failure.protocolError("unexpected inner type \(type)")
        }
    }

    /// PEAP's EAP-TLV answer: our Result (the server's), plus a Crypto-Binding TLV (SubType 1)
    /// when the server sent one and it verifies; the MSK becomes the compound session key.
    private func tlvAnswer(_ engine: TLSEngine, _ data: [UInt8]) throws -> [UInt8] {
        let tlvs = PEAPCrypto.parseTLVs(data)
        let result = tlvs.result ?? 2
        var out: [UInt8] = [0x80, 0x03, 0x00, 0x02, UInt8(result >> 8), UInt8(result & 0xff)]
        if result == 1, cryptoBinding, let cb = tlvs.cryptoBinding, cb.count == 60,
           let tk = EAPServer.keyMaterial(.peap, engine).map({ Array($0.prefix(60)) }) {
            let binding = PEAPCrypto.binding(tk: tk, isk: resumed ? nil : (isk ?? []))
            guard PEAPCrypto.compoundMAC(cb, cmk: binding.cmk) == Array(cb[40..<60]) else {
                throw Failure.protocolError("the server's Crypto-Binding TLV does not verify")
            }
            out += PEAPCrypto.cryptoBindingTLV(nonce: Array(cb[8..<40]), cmk: binding.cmk, subType: 1)
            msk = Array(PEAPCrypto.compoundSessionKey(ipmk: binding.ipmk).prefix(64))
            usedCryptoBinding = true
        }
        return out
    }

    static func msk(_ type: EAPType, _ engine: TLSEngine) -> [UInt8]? {
        let m = EAPServer.msk(type, engine)
        return m.count == 64 ? m : nil
    }

    static func random(_ n: Int) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: n)
        _ = SecRandomCopyBytes(kSecRandomDefault, n, &b)
        return b
    }

    static func hex(_ s: String) -> [UInt8]? {
        let chars = Array(s.utf8)
        guard chars.count % 2 == 0 else { return nil }
        return stride(from: 0, to: chars.count, by: 2).compactMap { UInt8(String(decoding: chars[$0..<($0 + 2)], as: UTF8.self), radix: 16) }
    }
}
