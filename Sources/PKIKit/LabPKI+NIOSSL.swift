// NIOSSL loading helpers. Kept in their own file so the NIOSSL dependency can be split into a
// separate target later without touching LabPKI itself.
import NIOSSL

extension LabPKI {
    /// Server certificate followed by the lab CA, as NIOSSL certificates.
    public func nioServerCertificateChain() throws -> [NIOSSLCertificate] {
        do {
            return [
                try NIOSSLCertificate(bytes: Array(serverPEM().utf8), format: .pem),
                try NIOSSLCertificate(bytes: Array(caPEM().utf8), format: .pem),
            ]
        } catch let error as PKIKitError {
            throw error
        } catch {
            throw PKIKitError.encoding("NIOSSL certificate: \(error)")
        }
    }

    /// The server private key as an NIOSSL key.
    public func nioServerPrivateKey() throws -> NIOSSLPrivateKey {
        let pem = try serverKeyPEM()
        do {
            return try NIOSSLPrivateKey(bytes: Array(pem.utf8), format: .pem)
        } catch {
            throw PKIKitError.encoding("NIOSSL private key: \(error)")
        }
    }

    /// The lab CA as an NIOSSL certificate (for test clients' trust roots).
    public func nioCACertificate() throws -> NIOSSLCertificate {
        let pem = try caPEM()
        do {
            return try NIOSSLCertificate(bytes: Array(pem.utf8), format: .pem)
        } catch {
            throw PKIKitError.encoding("NIOSSL certificate: \(error)")
        }
    }

    /// A TLS server configuration (TLS 1.2+) presenting the server certificate and the lab CA.
    public func serverTLSConfiguration() throws -> TLSConfiguration {
        let chain = try nioServerCertificateChain()
        let key = try nioServerPrivateKey()
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: chain.map { .certificate($0) },
            privateKey: .privateKey(key)
        )
        configuration.minimumTLSVersion = .tlsv12
        return configuration
    }
}
