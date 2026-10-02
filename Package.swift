// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "LabDC",
    platforms: [
        .macOS(.v26),
    ],
    products: [
        .executable(name: "labdc", targets: ["labdc"]),
        // Legacy phase-0 front end (JSON principals); `labdc serve` replaces it.
        .executable(name: "labdc-kdc", targets: ["labdc-kdc"]),
        // UI-1: the macOS app (bundle it with Scripts/make-app.sh → LabDC.app).
        .executable(name: "LabDCApp", targets: ["LabDCApp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        // PK-1: `_CryptoExtras` (RSA CA keys); already resolved through swift-certificates.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"6.0.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.25.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.70.0"),
    ],
    targets: [
        .target(name: "SheepCrypto"),
        .target(name: "KerberosCrypto", dependencies: ["SheepCrypto"]),
        .target(name: "KerberosASN1", dependencies: [
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .target(name: "MSPAC", dependencies: ["SheepCrypto"]),
        .target(name: "Store", dependencies: ["SheepCrypto", "KerberosCrypto", "MSPAC", "RADIUSKit", "DHCPKit",
            .product(name: "Crypto", package: "swift-crypto")]),  // RADIUS secrets sealed at rest
        .target(name: "KDC", dependencies: [
            "SheepCrypto", "KerberosCrypto", "KerberosASN1", "MSPAC", "Store",
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .executableTarget(name: "labdc-kdc", dependencies: ["KDC"]),
        .target(name: "PKIKit", dependencies: [
            // SYSVOL (PK-5): the Configuration NC `Certification Authorities` publisher of PK-4.
            "Store", "MSPAC", "CertConvert", "SYSVOL",
            // AuthKit (PK-6): HTTP Negotiate (SPNEGO / Kerberos / NTLM) in front of the CEP / CES.
            "AuthKit",
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOHTTP1", package: "swift-nio"),
            .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
        ]),
        // PK-3: certificate/key format converter (PEM, DER, PKCS#7, PKCS#12, JKS read).
        .target(name: "CertConvert", dependencies: [
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        // GSS-TSIG (RFC 3645): TKEY contexts through AuthKit's Kerberos/SPNEGO acceptors.
        .target(name: "DNSKit", dependencies: ["AuthKit", "MSPAC"]),
        // Phase 5: DHCPv4/DHCPv6 wire formats, the server state machines, option 43 builders
        // and the light device classifier (no dependencies: every parser is bounds-checked).
        .target(name: "DHCPKit"),
        // Phase 4a: RADIUS wire format, MS-CHAPv2 and the policy evaluator.
        .target(name: "RADIUSKit", dependencies: ["SheepCrypto",
            .product(name: "Crypto", package: "swift-crypto")]),
        // Phase 4b/4c: the EAP server (EAP-TLS, PEAP-MSCHAPv2, TTLS) over BoringSSL on memory BIOs.
        .target(name: "EAPKit", dependencies: [
            "RADIUSKit", "SheepCrypto",
            .product(name: "NIOSSL", package: "swift-nio-ssl"),   // builds CNIOBoringSSL
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .target(name: "AuthKit", dependencies: [
            "SheepCrypto", "KerberosCrypto", "KerberosASN1", "MSPAC",
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .target(name: "RPCKit", dependencies: ["SheepCrypto", "KerberosCrypto", "AuthKit", "MSPAC"]),
        .target(name: "LSAService", dependencies: ["RPCKit", "Store", "MSPAC", "AuthKit"]),
        .target(name: "DRSService", dependencies: ["RPCKit", "Store", "MSPAC"]),
        .target(name: "SAMService", dependencies: ["RPCKit", "Store", "SheepCrypto", "MSPAC", "AuthKit", "KerberosCrypto"]),
        .target(name: "NetlogonService", dependencies: [
            "RPCKit", "Store", "AuthKit", "MSPAC", "SheepCrypto", "KerberosCrypto",
        ]),
        // MS-BKRP: DPAPI master-key backup (RSA ClientWrap certificate, legacy ServerWrap).
        .target(name: "BackupKeyService", dependencies: [
            "RPCKit", "Store", "MSPAC", "SheepCrypto",
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .target(name: "LDAPCore", dependencies: ["Store"]),
        .target(name: "SYSVOL", dependencies: ["Store"]),
        .target(name: "SNTPKit"),
        .target(name: "DirectoryKit", dependencies: [
            "LDAPCore", "Store", "PKIKit", "AuthKit", "MSPAC", "KerberosCrypto",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
        ]),
        .target(name: "SMBKit", dependencies: [
            "AuthKit", "Store", "SheepCrypto", "KerberosCrypto",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),
        .target(name: "RPCPipes", dependencies: [
            "SMBKit", "RPCKit", "LSAService", "SAMService", "NetlogonService", "DRSService", "BackupKeyService", "Store",
        ]),
        .target(name: "RPCTCP", dependencies: [
            "RPCKit",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
        ]),
        // UI-1: the embedded server (ServeRuntime, ServeLog, DataDirectory, serve options) shared by
        // the CLI and the app, plus the app's observable status/log model.
        .target(name: "LabDCCore", dependencies: [
            "Store", "DNSKit", "DHCPKit", "RADIUSKit", "EAPKit", "PKIKit", "KDC", "DirectoryKit", "MSPAC", "KerberosCrypto", "AuthKit",
            "SMBKit", "RPCKit", "RPCPipes", "RPCTCP", "LSAService", "SAMService", "NetlogonService", "DRSService", "SYSVOL", "SNTPKit",
            "CertConvert",  // UI-3: PKIEditor (trusted-root files)
            // UI-5: Test login (Kerberos AS client, LDAP bind client, NTLM/MS-CHAPv2 responses).
            "KerberosASN1", "LDAPCore", "SheepCrypto",
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),   // EAP-TLS certificate mapping (UPN otherName)
        ]),
        .target(name: "LabDCCLI", dependencies: [
            "LabDCCore", "Store", "RADIUSKit", "DNSKit", "DHCPKit", "PKIKit", "CertConvert", "KDC", "DirectoryKit", "MSPAC", "KerberosCrypto",
            "SMBKit", "RPCKit", "RPCPipes", "RPCTCP", "LSAService", "SAMService", "NetlogonService", "DRSService", "SYSVOL", "SNTPKit",
        ]),
        .executableTarget(name: "labdc", dependencies: ["LabDCCLI"]),
        // UI-1: the SwiftUI app. Named LabDCApp (not LabDC) because `labdc` and
        // `LabDC` would share one build product path on a case-insensitive disk.
        .executableTarget(name: "LabDCApp", dependencies: [
            "LabDCCore", "Store", "PKIKit", "NetlogonService", "DHCPKit", "AuthKit", "DNSKit",
            "CertConvert", "SYSVOL", .product(name: "X509", package: "swift-certificates"),  // UI-3
        ], path: "Sources/LabDCApp", exclude: ["Bundle"]),

    ],
    swiftLanguageModes: [.v6]
)
