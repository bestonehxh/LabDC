import CommonCrypto
import Foundation
import MSPAC
import RPCKit
import SheepCrypto
import Store
import os

/// The BackupKey Remote Protocol (MS-BKRP) interface `backupkey`
/// (`3dde7c30-165d-11d1-ab8f-00805f14db40` v1.0): the DC side of DPAPI master-key backup. A
/// domain member's DPAPI fetches the domain's backup public key, wraps each new user master key
/// with it and keeps the result in the profile; if the user's password is reset, the DC unwraps
/// it again. Without this interface Windows logs Crypto-DPAPI event 16387 ("Fallback backup is
/// disabled") and every operation that needs a new user master key — user certificate
/// enrollment's private key, for one — fails.
///
/// One opnum, `BackupKey` (0), whose `pguidActionAgent` picks the action (§3.1.4.1):
/// - `BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID`: the ClientWrap public-key certificate (§2.2.1), the
///   RSA key created on first use and kept as `G$BCKUPKEY_PREFERRED` → `G$BCKUPKEY_<guid>`;
/// - `BACKUPKEY_RESTORE_GUID`: unwraps a ClientWrap blob (version 2/3) for the user it names, or
///   a ServerWrap blob (version 1);
/// - `BACKUPKEY_BACKUP_GUID` / `BACKUPKEY_RESTORE_GUID_WIN2K`: the legacy ServerWrap
///   subprotocol (RC4 + HMAC-SHA1 under `G$BCKUPKEY_P`), as Samba implements it.
///
/// Every call requires an authenticated caller at `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (§3.1.4.1);
/// anything less faults `nca_s_fault_access_denied`, which is how Samba's dcesrv (`bind_require_
/// privacy`) and Windows answer — the client sees `NT_STATUS_ACCESS_DENIED`.
public struct BackupKeyService: RPCInterface {
    public static let uuid = DCEUUID("3dde7c30-165d-11d1-ab8f-00805f14db40")

    public enum Opnum {
        public static let backupKey: UInt16 = 0
    }

    /// The `pguidActionAgent` values (§3.1.4.1).
    public enum Action {
        public static let restore = DCEUUID("47270c64-2fc7-499b-ac5b-0e37cdce899a")
        public static let retrieveBackupKey = DCEUUID("018ff48a-eaba-40c6-8f6d-72370240e967")
        public static let restoreWin2K = DCEUUID("7fe94d50-178e-11d1-ab8f-00805f14db40")
        public static let backup = DCEUUID("7f752b10-178e-11d1-ab8f-00805f14db40")
    }

    /// The LSA global secret names (§3.1.1; AD stores them as `BCKUPKEY_… Secret` objects).
    public enum SecretName {
        public static let preferred = "G$BCKUPKEY_PREFERRED"
        public static let legacyPreferred = "G$BCKUPKEY_P"
        public static func key(_ guid: [UInt8]) -> String { "G$BCKUPKEY_\(BackupKeyService.guidString(guid))" }
    }

    public let store: DirectoryStore
    /// When true (the default) a call below PKT_PRIVACY, or an anonymous one, faults
    /// `nca_s_fault_access_denied`. Tests that drive the NDR without an auth layer disable it.
    public let requirePrivacy: Bool
    /// One activity line per call (`labdc serve` prints them as the `BKRP` component). Never
    /// carries key material or secrets — only the action, caller, key GUID and outcome.
    public let onEvent: (@Sendable (String) -> Void)?
    let rng: RandomBytes
    let clock: @Sendable () -> Date

    public init(store: DirectoryStore, requirePrivacy: Bool = true, rng: RandomBytes = RandomBytes(),
                clock: @escaping @Sendable () -> Date = { Date() },
                onEvent: (@Sendable (String) -> Void)? = nil) {
        self.store = store
        self.requirePrivacy = requirePrivacy
        self.rng = rng
        self.clock = clock
        self.onEvent = onEvent
    }

    public var interfaceUUID: DCEUUID { Self.uuid }
    public var interfaceVersion: (UInt16, UInt16) { (1, 0) }

    public func dispatch(opnum: UInt16, input r: NDRReader, context: RPCCallContext) async throws -> NDRWriter {
        guard opnum == Opnum.backupKey else { throw RPCError.fault(.opRangeError) }
        if requirePrivacy && (context.authLevel != .pktPrivacy || context.identity.isAnonymous) {
            // §3.1.4.1: the server MUST reject a call that is not authenticated at packet privacy.
            logEvent("BackupKey from \(Self.caller(context)) -> access denied ("
                     + (context.identity.isAnonymous ? "anonymous caller" : "auth level below PKT_PRIVACY") + ")")
            throw RPCError.fault(.accessDenied)
        }
        // BackupKey([in] handle_t, [in] GUID* pguidActionAgent, [in, size_is(cbDataIn)] byte* pDataIn,
        //   [in] DWORD cbDataIn, [out, size_is(,*pcbDataOut)] byte** ppDataOut,
        //   [out] DWORD* pcbDataOut, [in] DWORD dwParam). Both [in] pointers are [ref].
        let request = try Request(r)
        let (status, output) = await perform(request, context: context)
        return Self.response(status == .ok ? output : nil, status: status)
    }

    /// The decoded `[in]` arguments.
    public struct Request: Sendable, Equatable {
        public var action: DCEUUID
        public var data: [UInt8]
        public var param: UInt32

        public init(action: DCEUUID, data: [UInt8], param: UInt32 = 0) {
            self.action = action; self.data = data; self.param = param
        }

        init(_ r: NDRReader) throws {
            action = try r.guid()
            data = try r.conformantByteArray()
            r.align(4)
            let length = try r.u32()
            guard Int(length) == data.count else {
                throw NDRError(offset: r.offset, reason: "cbDataIn \(length) != pDataIn size \(data.count)")
            }
            param = try r.u32()
        }

        /// The request stub, as a client marshals it.
        public var encoded: [UInt8] {
            let w = NDRWriter()
            w.guid(action)
            w.conformantByteArray(data)
            w.align(4)
            w.u32(UInt32(data.count))
            w.u32(param)
            return w.bytes
        }
    }

    /// The `[out]` stub: `*ppDataOut` (a unique pointer to a conformant byte array, NULL on
    /// error), `*pcbDataOut`, then the WERROR.
    static func response(_ data: [UInt8]?, status: BackupKeyStatus) -> NDRWriter {
        let w = NDRWriter()
        if let data {
            _ = w.uniquePointer(true)
            w.conformantByteArray(data)
        } else {
            w.u32(0)
        }
        w.align(4)
        w.u32(UInt32(data?.count ?? 0))
        w.u32(status.rawValue)
        return w
    }

    /// Decodes a response stub: (data, WERROR).
    public static func decodeResponse(_ stub: [UInt8]) throws -> (data: [UInt8]?, status: UInt32) {
        let r = NDRReader(stub)
        var data: [UInt8]?
        if try r.pointer() != nil { data = try r.conformantByteArray() }
        r.align(4)
        let length = try r.u32()
        guard Int(length) == (data?.count ?? 0) else { throw NDRError(offset: r.offset, reason: "pcbDataOut mismatch") }
        return (data, try r.u32())
    }

    // MARK: actions

    func perform(_ request: Request, context: RPCCallContext) async -> (BackupKeyStatus, [UInt8]) {
        let who = Self.caller(context)
        do {
            switch request.action {
            case Action.retrieveBackupKey:
                let (guid, key, created) = try await preferredClientWrapKey()
                logEvent("RetrieveBackupKey from \(who) -> OK key {\(Self.guidString(guid))}" + (created ? " (created)" : ""))
                return (.ok, key.certificate)
            case Action.restore:
                // §3.1.4.1.4 step 1: the first DWORD tells a ServerWrap blob (1) from ClientWrap (2, 3).
                guard request.data.count >= 4 else { throw Failure(.invalidParameter, "blob shorter than 4 bytes") }
                if request.data.prefix(4).elementsEqual(BKRPBytes.le32(1)) {
                    return try await serverWrapRestore(request.data, context: context, label: "Restore v1")
                }
                return try await clientWrapRestore(request.data, context: context)
            case Action.restoreWin2K:
                guard !request.data.isEmpty else { throw Failure(.invalidParameter, "empty blob") }
                return try await serverWrapRestore(request.data, context: context, label: "RestoreWin2k")
            case Action.backup:
                return try await serverWrapBackup(request.data, context: context)
            default:
                // An unknown action agent: Samba (and Windows) answer ERROR_INVALID_PARAMETER.
                throw Failure(.invalidParameter, "unknown action {\(request.action)}", label: "BackupKey")
            }
        } catch let f as Failure {
            logEvent("\(f.label ?? Self.label(request.action)) from \(who) -> \(f.status)" + (f.detail.isEmpty ? "" : " (\(f.detail))"))
            return (f.status, [])
        } catch let s as BackupKeyStatus {
            logEvent("\(Self.label(request.action)) from \(who) -> \(s)")
            return (s, [])
        } catch {
            logEvent("\(Self.label(request.action)) from \(who) -> INTERNAL_ERROR (\(error))")
            return (.internalError, [])
        }
    }

    /// An action outcome other than OK, with a short reason for the activity line.
    struct Failure: Error {
        let status: BackupKeyStatus
        let detail: String
        var label: String?
        init(_ status: BackupKeyStatus, _ detail: String = "", label: String? = nil) {
            self.status = status; self.detail = detail; self.label = label
        }
    }

    /// ClientWrap restore (§3.1.4.1.4, Samba `bkrp_client_wrap_decrypt_data`): unwrap the secret
    /// with the named key, decrypt and verify the access check, and return the secret only to the
    /// user whose SID the access check carries — one key serves the whole domain, so without this
    /// check anyone holding a copy of another user's profile could have its master key unwrapped.
    func clientWrapRestore(_ blob: [UInt8], context: RPCCallContext) async throws -> (BackupKeyStatus, [UInt8]) {
        let version = UInt32(blob[0]) | UInt32(blob[1]) << 8 | UInt32(blob[2]) << 16 | UInt32(blob[3]) << 24
        let label = "Restore v\(version)"
        guard version == 2 || version == 3 else {
            throw Failure(.invalidParameter, "unknown blob version \(version)", label: "Restore")
        }
        let wrapped = try ClientSideWrapped(decoding: blob)
        let keyName = "key {\(Self.guidString(wrapped.keyGUID))}"
        do {
            guard let stored = try await store.lsaSecret(named: SecretName.key(wrapped.keyGUID)) else {
                throw Failure(.invalidData, "no such key", label: label)
            }
            let pair = try ExportedRSAKeyPair(decoding: stored)
            // From RSA decryption to the access-check hash every failure is the same answer and
            // log line, so a caller learns nothing about the padding (see `unwrapSecret`).
            let secret: EncryptedSecretPlaintext, check: AccessCheck
            do {
                let plain = try BackupKeyCrypto.unwrapSecret(wrapped.encryptedSecret, pair: pair)
                secret = try EncryptedSecretPlaintext(decoding: plain, version: version)
                let decrypted = try BackupKeyCrypto.accessCheckCipher(CCOperation(kCCDecrypt), version: version,
                                                                      payloadKey: secret.payloadKey, wrapped.accessCheck)
                check = try AccessCheck(decrypted: decrypted, version: version) {
                    BackupKeyCrypto.accessCheckHash(version: version, $0)
                }
            } catch {
                throw Failure(.invalidData, "\(keyName); the blob does not decrypt", label: label)
            }
            guard check.sid == context.identity.sid else {
                throw Failure(.invalidAccess, "\(keyName); the blob belongs to \(check.sid)", label: label)
            }
            logEvent("\(label) from \(Self.caller(context)) -> OK \(keyName)")
            // The reply is the secret behind a 4-byte zero version prefix (Samba's
            // `bkrp_client_side_unwrapped`: magic 0 then the secret).
            return (.ok, [0, 0, 0, 0] + secret.secret)
        } catch let s as BackupKeyStatus {
            throw Failure(s, keyName, label: label)
        }
    }

    /// ServerWrap backup (§3.1.4.1.1, Samba `bkrp_server_wrap_encrypt_data`): the secret and the
    /// caller's SID, MAC'd and RC4-encrypted under keys derived from the DC's 256-byte ServerWrap
    /// key with fresh R2/R3, so the per-blob keys reveal nothing about the long-term key.
    func serverWrapBackup(_ secret: [UInt8], context: RPCCallContext) async throws -> (BackupKeyStatus, [UInt8]) {
        guard !secret.isEmpty else { throw Failure(.invalidParameter, "empty secret", label: "Backup") }
        let (guid, key, created) = try await preferredServerWrapKey()
        let r2 = rng.next(68), r3 = rng.next(32)
        // Samba notes that the HMAC key is the whole 256-byte key, not the "leading 64 bytes" the
        // spec's wording suggests; Windows interoperates with that.
        let symmetricKey = BackupKeyCrypto.hmacSHA1(key: key.key, r2)
        let macKey = BackupKeyCrypto.hmacSHA1(key: key.key, r3)
        let sid = context.identity.sid
        let mac = BackupKeyCrypto.hmacSHA1(key: macKey, sid.bytes, secret)
        let payload = ServerWrapPayload(r3: r3, mac: mac, sid: sid, secret: secret).encoded
        let blob = ServerSideWrapped(payloadLength: UInt32(secret.count), keyGUID: guid, r2: r2,
                                     ciphertext: RC4.apply(key: symmetricKey, payload))
        logEvent("Backup from \(Self.caller(context)) -> OK key {\(Self.guidString(guid))}" + (created ? " (created)" : ""))
        return (.ok, blob.encoded)
    }

    /// ServerWrap restore (§3.1.4.1.2, Samba `bkrp_server_wrap_decrypt_data`).
    func serverWrapRestore(_ blob: [UInt8], context: RPCCallContext, label: String) async throws -> (BackupKeyStatus, [UInt8]) {
        let wrapped: ServerSideWrapped
        do { wrapped = try ServerSideWrapped(decoding: blob) } catch let s as BackupKeyStatus {
            throw Failure(s, "malformed blob", label: label)
        }
        let keyName = "key {\(Self.guidString(wrapped.keyGUID))}"
        do {
            guard let stored = try await store.lsaSecret(named: SecretName.key(wrapped.keyGUID)) else {
                throw Failure(.invalidData, "\(keyName) not found", label: label)
            }
            let key = try ServerWrapKey(decoding: stored)
            let symmetricKey = BackupKeyCrypto.hmacSHA1(key: key.key, wrapped.r2)
            let payload = try ServerWrapPayload(decoding: RC4.apply(key: symmetricKey, wrapped.ciphertext))
            guard Int(wrapped.payloadLength) == payload.secret.count else { throw BackupKeyStatus.invalidParameter }
            let macKey = BackupKeyCrypto.hmacSHA1(key: key.key, payload.r3)
            let mac = BackupKeyCrypto.hmacSHA1(key: macKey, payload.sid.bytes, payload.secret)
            guard ConstantTime.equal(mac, payload.mac) else { throw Failure(.invalidAccess, "\(keyName); bad MAC", label: label) }
            guard payload.sid == context.identity.sid else {
                throw Failure(.invalidAccess, "\(keyName); the blob belongs to \(payload.sid)", label: label)
            }
            logEvent("\(label) from \(Self.caller(context)) -> OK \(keyName)")
            return (.ok, payload.secret)
        } catch let s as BackupKeyStatus {
            throw Failure(s, keyName, label: label)
        }
    }

    // MARK: keys (§3.1.1)

    /// The current ClientWrap key, created on first use (Samba `bkrp_retrieve_client_wrap_key`
    /// → `generate_bkrp_cert`). Returns the GUID, the key pair and whether this call created it.
    func preferredClientWrapKey() async throws -> ([UInt8], ExportedRSAKeyPair, Bool) {
        var created = false
        if try await store.lsaSecret(named: SecretName.preferred) == nil {
            let info = try await store.domainInfo()
            let guid = GUID.random(rng).bytes
            let generated = try BackupKeyCrypto.generateClientWrapKey(guid: guid, dnsDomain: info.dnsDomain, now: clock())
            // `G$BCKUPKEY_PREFERRED` holds the GUID in its binary form (Samba `GUID_to_ndr_blob`).
            created = try await store.createLSASecrets([(SecretName.key(guid), try generated.keyPair.encoded()),
                                                        (SecretName.preferred, guid)],
                                                       unlessPresent: SecretName.preferred)
        }
        guard let guid = try await store.lsaSecret(named: SecretName.preferred), guid.count == 16 else {
            throw BackupKeyStatus.fileNotFound
        }
        guard let stored = try await store.lsaSecret(named: SecretName.key(guid)) else { throw BackupKeyStatus.fileNotFound }
        return (guid, try ExportedRSAKeyPair(decoding: stored), created)
    }

    /// The current ServerWrap key, created on first use (Samba `generate_bkrp_server_wrap_key`).
    func preferredServerWrapKey() async throws -> ([UInt8], ServerWrapKey, Bool) {
        var created = false
        if try await store.lsaSecret(named: SecretName.legacyPreferred) == nil {
            let guid = GUID.random(rng).bytes
            let key = ServerWrapKey(key: rng.next(256))
            created = try await store.createLSASecrets([(SecretName.key(guid), key.encoded),
                                                        (SecretName.legacyPreferred, guid)],
                                                       unlessPresent: SecretName.legacyPreferred)
        }
        guard let guid = try await store.lsaSecret(named: SecretName.legacyPreferred), guid.count == 16,
              let stored = try await store.lsaSecret(named: SecretName.key(guid)) else {
            throw BackupKeyStatus.fileNotFound
        }
        return (guid, try ServerWrapKey(decoding: stored), created)
    }

    // MARK: log

    private static let logger = Logger(subsystem: "dev.labdc.app", category: "BKRP")

    func logEvent(_ line: String) {
        Self.logger.info("\(line, privacy: .public)")
        onEvent?(line)
    }

    /// `best@192.0.2.10` (the authenticated account, then the peer address).
    static func caller(_ context: RPCCallContext) -> String {
        let who = context.identity.isAnonymous ? "anonymous" : context.identity.sam
        return "\(who)@\(context.clientAddress)"
    }

    static func label(_ action: DCEUUID) -> String {
        switch action {
        case Action.retrieveBackupKey: "RetrieveBackupKey"
        case Action.restore: "Restore"
        case Action.restoreWin2K: "RestoreWin2k"
        case Action.backup: "Backup"
        default: "BackupKey"
        }
    }

    /// Lower-case `xxxxxxxx-xxxx-…` of a GUID in its MS-DTYP binary layout (the form AD and Samba
    /// use in `G$BCKUPKEY_<guid>`).
    static func guidString(_ bytes: [UInt8]) -> String {
        bytes.count == 16 ? DCEUUID(bytes: bytes).description : bytes.map { String(format: "%02x", $0) }.joined()
    }
}
