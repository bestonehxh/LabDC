import Foundation

/// An in-memory replay cache (RFC 4120 §3.2.3, §10) for PA-ENC-TIMESTAMP and kpasswd
/// authenticators.
///
/// An entry is the ciphertext that carried the timestamp (unique per encryption because of
/// the confounder) together with the bytes of the whole request it arrived in. It is kept for
/// `KDCPolicy.replayWindow` (twice the skew: a timestamp is accepted up to `maxSkew` on either
/// side of the KDC's clock). The same ciphertext in a *byte-identical* request is a
/// retransmission, not a replay: Heimdal resends the same AS-REQ over TCP after
/// KRB_ERR_RESPONSE_TOO_BIG, and UDP clients resend after a lost reply. Only the client whose
/// key opens the reply can use it, so answering a retransmission again gives nothing away.
struct ReplayCache {
    private struct Entry {
        var request: [UInt8]
        var expires: Int64
    }

    private var entries: [[UInt8]: Entry] = [:]
    private var nextPurge: Int64 = 0
    let window: Int64

    init(window: Int64 = KDCPolicy.replayWindow) { self.window = window }

    enum Verdict: Equatable { case fresh, retransmission, replay }

    /// Records `authenticator` (seen in `request` at `now`) and says whether it was new.
    mutating func check(_ authenticator: [UInt8], request: [UInt8], now: Int64) -> Verdict {
        purge(now: now)
        if let e = entries[authenticator], e.expires > now {
            return e.request == request ? .retransmission : .replay
        }
        entries[authenticator] = Entry(request: request, expires: now + window)
        return .fresh
    }

    var count: Int { entries.count }

    private mutating func purge(now: Int64) {
        guard now >= nextPurge else { return }
        entries = entries.filter { $0.value.expires > now }
        nextPurge = now + 30
    }
}
