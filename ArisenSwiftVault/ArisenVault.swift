//
//  ArisenVault.swift
//  ArisenVault
//
//  Created by Todd Bowden on 6/4/18.
//  Copyright (c) 2017-2019 block.one and its contributors. All rights reserved.
//

import Foundation
import LocalAuthentication
import ArisenSwift
import ArisenSwiftEcc

/// Utility library for managing keys and signing with Apple's Keychain and Secure Enclave.
public final class ArisenVault {

    /// Notification you can subscribe to notifying of Keychain updates.
    public static let updateNotification = Notification.Name("ArisenVaultUpdateNotification")

    private let keychain: Keychain
    private let vaultTag = "__VAULT__"
    private let ArisenKeyMetadataService = "ArisenKeyMetadataService"

    /// The accessGroup allows multiple apps (including extensions) in the same team to share the same Keychain.
    public let accessGroup = ""

    /// Setting on the key dictating biometric authentication requirements and whether the key persists after device's biometric settings are modified.
    public enum BioFactor: String {
        /// Biometric authentication is not required for the key.
        case none = ""
        /// Keys persist even after the device's biometric settings are modified.
        case flex = "bio flex"
        /// Keys are bricked in the event the device's biometric settings are modified.
        case fixed = "bio fixed"
    }

    private var context: LAContext?

    /// Init with accessGroup. The accessGroup allows multiple apps (including extensions) in the same team to share the same Keychain.
    ///
    /// - Parameter accessGroup: The access group should be an `App Group` on the developer account.
    public init(accessGroup: String) {
        keychain = Keychain(accessGroup: accessGroup)
    }

    private func postUpdateNotification(ArisenPublicKey: String, action: String) {
        NotificationCenter.default.post(name: ArisenVault.updateNotification, object: nil, userInfo: ["ArisenPublicKey": ArisenPublicKey, "action": action])
    }

    /// Get the vaultIdentifierKey (a special Secure Enclave key with tag "__VAULT__".) Create if not present.
    ///
    /// - Returns: The vault identifier key, as an ECKey.
    /// - Throws: If a vault key does not exist and cannot be created.
    public func vaultIdentifierKey() throws -> Keychain.ECKey {
        var vaultKeyArray = try keychain.getAllEllipticCurveKeys(tag: vaultTag)

        if vaultKeyArray.count == 0 {
            _ = try keychain.createSecureEnclaveSecKey(tag: vaultTag, label: nil, accessFlag: nil)
            vaultKeyArray = try keychain.getAllEllipticCurveKeys(tag: vaultTag)
        }
        guard let vaultIdentifierKey = vaultKeyArray.first else {
            throw ArisenError(ArisenErrorCode.keyManagementError, reason: "Unable to create vault key")
        }
        return vaultIdentifierKey
    }

    /// Get the vaultIdentifierKey public key, as hex.
    ///
    /// - Returns: The vaultIdentifierKey public key, as hex.
    /// - Throws: If a vault key does not exist and cannot be created.
    public func vaultIdentifier() throws -> String {
        let key = try vaultIdentifierKey()
        return key.uncompressedPublicKey.hex
    }

    /// Create a new Secure Enclave key and return the Vault Key.
    ///
    /// - Parameters:
    ///   - protection: Accessibility defaults to whenUnlockedThisDeviceOnly.
    ///   - bioFactor: The `BioFactor` for this key.
    ///   - metadata: Any metadata to associate with this key.
    /// - Returns: The new key as a VaultKey.
    /// - Throws: If a new key cannot be created.
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    public func newSecureEnclaveKey(protection: Keychain.AccessibleProtection = .whenUnlockedThisDeviceOnly,
                                    bioFactor: BioFactor = .none,
                                    metadata: [String: Any]? = nil) throws -> ArisenVault.VaultKey {

        return try newVaultKey(secureEnclave: true, protection: protection, bioFactor: bioFactor, metadata: metadata)
    }

    /// Create a new elliptic curve key and return as a VaultKey.
    ///
    /// - Parameters:
    ///   - secureEnclave: Generate this key in Secure Enclave?
    ///   - protection: Accessibility defaults to whenUnlockedThisDeviceOnly.
    ///   - bioFactor: The `BioFactor` for this key.
    ///   - metadata: Any metadata to associate with this key.

    /// - Returns: The new key as a VaultKey.
    /// - Throws: If a new key cannot be created.
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    public func newVaultKey(secureEnclave: Bool,
                            protection: Keychain.AccessibleProtection = .whenUnlockedThisDeviceOnly,
                            bioFactor: BioFactor = .none,
                            metadata: [String: Any]? = nil) throws -> ArisenVault.VaultKey {
        var tag: String?
        var accessFlag: SecAccessControlCreateFlags?
        switch bioFactor {
        case .flex:
            accessFlag = .biometryAny
            tag = bioFactor.rawValue
        case .fixed:
            accessFlag = .biometryCurrentSet
            tag = bioFactor.rawValue
        case .none:
            accessFlag = nil
            tag = nil
        }

        let secKey = try keychain.createEllipticCurveSecKey(secureEnclave: secureEnclave, tag: tag, label: nil, protection: protection, accessFlag: accessFlag)
        guard let ArisenPublicKey = secKey.publicKey?.externalRepresentation?.compressedPublicKey?.toArisenR1PublicKey else {
            throw ArisenError(.keyManagementError, reason: "Unable to create public key")
        }
        var vaultKey = try getVaultKey(ArisenPublicKey: ArisenPublicKey)
        if let metadata = metadata {
            vaultKey.metadata = metadata
            _ = update(key: vaultKey)
        }
        postUpdateNotification(ArisenPublicKey: ArisenPublicKey, action: "new")
        return vaultKey
    }

    /// Import an external Arisen private key into the Keychain. Returns a VaultKey or throws an error.
    ///
    /// - Parameters:
    ///   - ArisenPrivateKey: An Arisen private key.
    ///   - protection: Accessibility defaults to .whenUnlockedThisDeviceOnly.
    ///   - bioFactor: The `BioFactor` for this key.
    ///   - metadata: Any metadata to associate with this key.
    /// - Returns: The imported key as a VaultKey.
    /// - Throws: If the key is not valid or cannot be imported.
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    public func addExternal(ArisenPrivateKey: String,
                            protection: Keychain.AccessibleProtection = .whenUnlockedThisDeviceOnly,
                            bioFactor: BioFactor = .none,
                            metadata: [String: Any]? = nil) throws -> ArisenVault.VaultKey {

        let ArisenKeyComponents = try ArisenPrivateKey.ArisenComponents()
        let curve = try EllipticCurveType(ArisenKeyComponents.version)

        let tag: String
        var accessFlag: SecAccessControlCreateFlags?
        switch bioFactor {
        case .flex:
            accessFlag = .biometryAny
            tag = "\(curve.rawValue) \(bioFactor.rawValue)"
        case .fixed:
            accessFlag = .biometryCurrentSet
            tag = "\(curve.rawValue) \(bioFactor.rawValue)"
        case .none:
            accessFlag = nil
            tag = curve.rawValue
        }

        let privateKeyData = try Data(ArisenPrivateKey: ArisenPrivateKey)
        let publicKeyData = try EccRecoverKey.recoverPublicKey(privateKey: privateKeyData, curve: curve)
        let ecKey = try keychain.importExternal(privateKey: publicKeyData + privateKeyData, tag: tag, protection: protection, accessFlag: accessFlag)
        var vaultKey = try getVaultKey(ArisenPublicKey: ecKey.compressedPublicKey.toArisenPublicKey(curve: curve.rawValue))
        if let metadata = metadata {
            vaultKey.metadata = metadata
            _ = update(key: vaultKey)
        }
        postUpdateNotification(ArisenPublicKey: vaultKey.ArisenPublicKey, action: "new")
        return vaultKey
    }

    /// Delete a key given the public key. USE WITH CARE!
    ///
    /// - Parameter ArisenPublicKey: The public key for the Arisen key to delete.
    /// - Throws: If there is an error deleting the key.
    public func deleteKey(ArisenPublicKey: String) throws {
        let pubKeyData = try Data(ArisenPublicKey: ArisenPublicKey)
        keychain.deleteKey(publicKey: pubKeyData)
        deleteKeyMetadata(publicKey: ArisenPublicKey)
    }

    /// Update the label identifying the key.
    ///
    /// - Parameters:
    ///   - label: The new value for the label.
    ///   - publicKey: The public Arisen key.
    /// - Throws: If the label cannot be updated.
    public func update(label: String, publicKey: String) throws {
        let pubKeyData = try Data(ArisenPublicKey: publicKey)
        keychain.update(label: label, publicKey: pubKeyData)
    }

    /// Update key. (The only items that are updatable are the metadata items.)
    ///
    /// - Parameter key: The VaultKey to update.
    /// - Returns: True if the key was updated, otherwise false.
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    public func update(key: ArisenVault.VaultKey) -> Bool {
        return saveKeyMetadata(ArisenPublicKey: key.ArisenPublicKey, dictionary: key.metadata)
    }

    /// Get all vault keys and their metadata by combining all Keychain keys (excluding the special __VAULT__ identifier key.)
    ///
    /// - Returns: An array of VaultKeys.
    /// - Throws: If there is an error getting the keys.
    public func getAllVaultKeys() throws -> [ArisenVault.VaultKey] {
        var vaultKeys = [String: VaultKey]()

        // add all ecKeys to the dict
        let ecKeys = try keychain.getAllEllipticCurveKeys()
        for ecKey in ecKeys where ecKey.tag != vaultTag {
            if let vaultKey = VaultKey(ecKey: ecKey, metadata: nil) {
                vaultKeys[vaultKey.ArisenPublicKey] = vaultKey
            }
        }

        // add metadata
        let allMetadata = getAllKeysMetadata() ?? [String: [String: Any]]()
        for (name, metadata) in allMetadata {
            if var vaultKey = vaultKeys[name] ?? VaultKey(ArisenPublicKey: name, ecKey: nil, metadata: metadata) {
                vaultKey.metadata = metadata
                vaultKeys[name] = vaultKey
            }
        }
        return Array(vaultKeys.values)
    }

    /// Get the vault key for the ArisenPublicKey.
    ///
    /// - Parameter ArisenPublicKey: An Arisen public key.
    /// - Returns: A VaultKey.
    /// - Throws: If the key cannot be found.
    public func getVaultKey(ArisenPublicKey: String) throws -> ArisenVault.VaultKey {
        let pubKeyData = try Data(ArisenPublicKey: ArisenPublicKey)
        let ecKey = keychain.getEllipticCurveKey(publicKey: pubKeyData)
        let metadata = getKeyMetadata(ArisenPublicKey: ArisenPublicKey)
        if let key = ArisenVault.VaultKey(ecKey: ecKey, metadata: metadata) {
            return key
        } else {
            throw ArisenError(ArisenErrorCode.keyManagementError, reason: "\(ArisenPublicKey) not found")
        }
    }

    /// Sign a message with the private key corresponding to the public key if the private key is found in the Keychain.
    /// Throws an error if the public key is not valid or the key is not found.
    ///
    /// - Parameters:
    ///   - message: The message to sign.
    ///   - ArisenPublicKey: The Arisen public key corresponding to the key to use for signing.
    ///   - requireBio: Require biometric identification even if the key does not require it.
    ///   - completion: Closure returning an Arisen signature or an error.
    public func sign(message: Data, ArisenPublicKey: String, requireBio: Bool, completion: @escaping (String?, ArisenError?) -> Void) {
        do {
            let vaultKey = try getVaultKey(ArisenPublicKey: ArisenPublicKey)
            sign(message: message, vaultKey: vaultKey, requireBio: requireBio, completion: completion)
        } catch {
            completion(nil, error.ArisenError)
        }
    }

    // Sign with VaultKey.
    private func sign(message: Data, vaultKey: VaultKey, requireBio: Bool, completion: @escaping (String?, ArisenError?) -> Void) {
        // if require bio and the bio factor is none, then sign with software bio check
        if requireBio && vaultKey.bioFactor == .none {
            return signWithBioCheck(message: message, vaultKey: vaultKey, completion: completion)
        }
        // otherwise just sign
        DispatchQueue.main.async {
            do {
                let sig = try self.sign(message: message, vaultKey: vaultKey)
                completion(sig, nil)
            } catch {
                completion(nil, error.ArisenError)
            }
        }
    }

    // Sign with VaultKey after bio check.
    private func signWithBioCheck(message: Data, vaultKey: VaultKey, completion: @escaping (String?, ArisenError?) -> Void) {
        context = LAContext()
        guard let context = context else {
            return completion(nil, ArisenError(.keySigningError, reason: "no LAContext")) // this should never happen
        }
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return completion(nil, error?.ArisenError)
        }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Sign Transaction", reply: { (isValid, error) in
            if isValid {
                do {
                    let sig = try self.sign(message: message, vaultKey: vaultKey)
                    completion(sig, nil)
                } catch {
                    let ArisenError = ArisenError(.keySigningError, reason: error.localizedDescription, originalError: error as NSError?)
                    completion(nil, ArisenError)
                }
            }

            if let error = error {
                switch error {
                case LAError.appCancel: // Request expiration has occurred and the app has canceled the biometrics authentication.
                    return
                default:
                    let ArisenError = ArisenError(.keySigningError, reason: error.localizedDescription, originalError: error as NSError?)
                    completion(nil, ArisenError)
                }
            }
        })
    }

    /// Dismiss biometrics dialogue and cancel the sign request.
    public func cancelPendingSigningRequest() {
        context?.invalidate()
    }

    /// Sign message with the private key corresponding to the public key if the private key is found in the Keychain.
    /// Throws an error if the public key is not valid or the key is not found.
    private func sign(message: Data, vaultKey: VaultKey) throws -> String {
        guard let privateSecKey = vaultKey.privateSecKey else {
            throw ArisenError(.keySigningError, reason: "Unable to get private key reference for \(vaultKey.ArisenPublicKey)")
        }
        guard let uncompressedPublicKey = vaultKey.uncompressedPublicKey else {
            throw ArisenError(.keySigningError, reason: "Unable to get uncompressed public key for \(vaultKey.ArisenPublicKey)")
        }

        // If R1, sign using Keychain
        if vaultKey.curve == .r1 {
            let der = try keychain.sign(privateKey: privateSecKey, data: message)
            guard let sig = EcdsaSignature(der: der as Data) else {
                throw ArisenError(.keySigningError, reason: "Unable to create EcdsaSignature for \(der)")
            }
            let recid = try EccRecoverKey.recid(signatureDer: sig.der, message: message.sha256, targetPublicKey: uncompressedPublicKey)
            let headerByte: UInt8 = 27 + 4 + UInt8(recid)
            return Data([headerByte] + sig.r + sig.s).toArisenR1Signature
        }

        // If K1, sign using ArisenSwiftEcc (uses openSSL)
        if vaultKey.curve == .k1 {
            guard let privateKey = privateSecKey.externalRepresentation?.suffix(32) else {
                throw ArisenError(.keySigningError, reason: "Unable to get private key for \(vaultKey.ArisenPublicKey)")
            }
            let sig = try ArisenEccSign.signWithK1(publicKey: uncompressedPublicKey, privateKey: privateKey, data: message)
            return sig.toArisenK1Signature
        }

        throw ArisenError(.keySigningError, reason: "Cannot sign with key \(vaultKey.ArisenPublicKey)")
    }

    /// Save metadata for the ArisenPublicKey.
    ///
    /// - Parameters:
    ///   - ArisenPublicKey: The Arisen public key.
    ///   - dictionary: A metadata dictionary to save.
    /// - Returns: True if the metadata was saved, otherwise false.
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    public func saveKeyMetadata(ArisenPublicKey: String, dictionary: [String: Any]) -> Bool {
        guard let json = dictionary.jsonString else { return false }
        return saveKeyMetadata(ArisenPublicKey: ArisenPublicKey, json: json)
    }

    /// Save metadata for the ArisenPublicKey
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    private func saveKeyMetadata(ArisenPublicKey: String, json: String) -> Bool {
        let name = ArisenPublicKey
        var result = false
        if getKeyMetadata(ArisenPublicKey: ArisenPublicKey) != nil {
            result = keychain.updateValue(name: name, value: json, service: ArisenKeyMetadataService)
        } else {
            result = keychain.saveValue(name: name, value: json, service: ArisenKeyMetadataService)
        }
        if result == true {
            postUpdateNotification(ArisenPublicKey: ArisenPublicKey, action: "metadata update")
        }
        return result
    }

    /// Delete metadata for the ArisenPublicKey.
    ///
    /// - Parameter publicKey: The public key.
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    public func deleteKeyMetadata(publicKey: String) {
        keychain.delete(name: publicKey, service: ArisenKeyMetadataService)
    }

    /// Get metadata for the ArisenPublicKey.
    ///
    /// - Parameter ArisenPublicKey: An Arisen public key.
    /// - Returns: The metadata dictionary for the key, if existing.
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    public func getKeyMetadata(ArisenPublicKey: String) -> [String: Any]? {
        guard let json = keychain.getValue(name: ArisenPublicKey, service: ArisenKeyMetadataService) else { return nil }
        return json.toJsonDictionary
    }

    /// Get metadata for all keys.
    ///
    /// - Returns: Dictionary of metadata dictionaries for all keys.
    /// - Important: Metadata must follow the rules for JSONSerialization.
    /// - SeeAlso: https://developer.apple.com/documentation/foundation/jsonserialization
    public func getAllKeysMetadata() -> [String: [String: Any]]? {
        guard let values = keychain.getValues(service: ArisenKeyMetadataService) else { return nil }
        var keyMetadataArray = [String: [String: Any]]()
        for (name, value) in values {
            if let dictionary = value.toJsonDictionary {
                keyMetadataArray[name] = dictionary
            }
        }
        return keyMetadataArray
    }

}
