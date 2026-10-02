import Foundation
import Crypto
import SheepCrypto

/// MAC addresses as NASes write them: `aabbccddeeff`, `AA-BB-CC-DD-EE-FF`, `aa:bb:cc:dd:ee:ff`,
/// `aabb.ccdd.eeff` (Cisco), `aabb-ccdd-eeff` (Huawei/H3C), `AABBCCDDEEFF` (Aruba). One
/// canonical form everywhere in LabDC: lowercase `aa:bb:cc:dd:ee:ff`.
public enum RADIUSMAC {
    /// The canonical `aa:bb:cc:dd:ee:ff`, or nil when `text` is not a 48-bit MAC in a known
    /// format. A Called-Station-Id style `aa-bb-cc-dd-ee-ff:SSID` suffix is not a MAC.
    public static func normalize(_ text: String) -> String? {
        let t = text.trimmingCharacters(in: .whitespaces)
        let hex = t.filter { $0.isHexDigit }
        guard hex.count == 12 else { return nil }
        // The separators must form one of the known groupings, nothing else in between.
        let shape = String(t.map { $0.isHexDigit ? "h" : $0 })
        let known: Set<String> = [
            "hhhhhhhhhhhh",
            "hh:hh:hh:hh:hh:hh", "hh-hh-hh-hh-hh-hh", "hh.hh.hh.hh.hh.hh",
            "hhhh.hhhh.hhhh", "hhhh-hhhh-hhhh", "hhhh:hhhh:hhhh",
            "hhhhhh-hhhhhh", "hhhhhh:hhhhhh",
        ]
        guard known.contains(shape) else { return nil }
        let lower = hex.lowercased()
        return stride(from: 0, to: 12, by: 2).map { i -> String in
            let a = lower.index(lower.startIndex, offsetBy: i)
            return String(lower[a..<lower.index(a, offsetBy: 2)])
        }.joined(separator: ":")
    }

    /// The spellings a NAS may use as the MAB password for `mac` (canonical form in): the
    /// plain hex both cases and the common separators.
    public static func passwordForms(_ mac: String) -> [String] {
        let hex = mac.replacingOccurrences(of: ":", with: "")
        let pairs = stride(from: 0, to: 12, by: 2).map { i -> String in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: 2)])
        }
        let quads = stride(from: 0, to: 12, by: 4).map { i -> String in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: 4)])
        }
        let lower = [hex, pairs.joined(separator: ":"), pairs.joined(separator: "-"), quads.joined(separator: "."),
                     quads.joined(separator: "-")]
        var all: [String] = []
        for form in lower + lower.map({ $0.uppercased() }) where !all.contains(form) { all.append(form) }
        return all
    }
}

/// MAC Authentication Bypass (owner, 1 Oct 2026): a NAS that saw no 802.1X supplicant sends the
/// client's MAC as the credentials. LabDC recognises it by shape, never by trying the
/// directory: a MAB request is evaluated only by policies that allow MAB, with
/// `auth_method = mab`, and no directory account is ever signed in by it.
///
/// Recognised forms (no EAP-Message; User-Name is a MAC in a known format; Calling-Station-Id
/// present, a MAC, and the same one):
/// - Cisco: Service-Type = Call-Check (10) — the password, if any, is not consulted.
/// - Aruba / Huawei / generic PAP: User-Password (decrypted) is the same MAC in any format.
/// - CHAP (Huawei `mac-authen` CHAP, some HPE): CHAP-Password over the MAC as the password.
public enum MABDetector {
    public struct Result: Sendable, Equatable {
        /// Canonical `aa:bb:cc:dd:ee:ff`.
        public var mac: String
        /// `Call-Check`, `PAP MAC/MAC`, `CHAP MAC/MAC`.
        public var form: String
    }

    public static func detect(_ packet: RADIUSPacket, secret: [UInt8]) -> Result? {
        guard packet.code == .accessRequest, packet.first(.eapMessage) == nil,
              let user = packet.string(.userName), let mac = RADIUSMAC.normalize(user) else { return nil }
        // Review fix (2 Oct 2026): the Calling-Station-Id is what makes it MAB. Every switch and
        // controller doing MAB sends it; a request without one (or with a non-MAC one, e.g. a VPN
        // concentrator's client IP) comes from a PAP/CHAP client — VPN, captive portal — where
        // anyone can type a registered device's MAC as user and password and would otherwise get
        // that device's VLAN. Such a request takes the normal password path instead.
        guard let calling = packet.string(.callingStationId), RADIUSMAC.normalize(calling) == mac else { return nil }
        if packet.integer(.serviceType) == 10 { return Result(mac: mac, form: "Call-Check") }
        if let hidden = packet.first(.userPassword)?.value {
            guard let plain = RADIUSPacket.userPassword(hidden, secret: secret, authenticator: packet.authenticator),
                  RADIUSMAC.normalize(String(decoding: plain, as: UTF8.self)) == mac else { return nil }
            return Result(mac: mac, form: "PAP MAC/MAC")
        }
        if let chap = packet.first(.chapPassword)?.value, chap.count == 17 {
            // RFC 1994 / RFC 2865 §5.3: MD5(CHAP ident + password + challenge); the challenge is
            // CHAP-Challenge, else the Request Authenticator.
            let challenge = packet.first(.chapChallenge)?.value ?? packet.authenticator
            let given = Array(chap[1...])
            for form in [user] + RADIUSMAC.passwordForms(mac) {
                let expected = Array(Insecure.MD5.hash(data: [chap[0]] + Array(form.utf8) + challenge))
                if ConstantTime.equal(expected, given) { return Result(mac: mac, form: "CHAP MAC/MAC") }
            }
        }
        return nil
    }
}
