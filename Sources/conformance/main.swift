import Foundation
import CoreFoundation
import AnyOAuth

var output: [String: Any]
do {
    guard let input = try JSONSerialization.jsonObject(with: FileHandle.standardInput.readDataToEndOfFile()) as? [String: Any] else { throw SDKError("invalid_argument", "Expected input object") }
    let p = input["params"] as? [String: Any] ?? [:]
    func string(_ key: String) throws -> String { guard let v = p[key] as? String else { throw SDKError("invalid_argument", "Missing string parameter") }; return v }
    let client = try AnyOAuth(clientId: input["clientId"] as? String ?? "conformance", baseUrl: input["baseUrl"] as? String ?? "https://api.anyoauth.com")
    let result: Any
    switch input["action"] as? String {
    case "pkceChallenge": result = try client.pkceChallenge(string("codeVerifier"))
    case "createTransaction": result = try client.createTransaction().toJSON()
    case "authorizationUrl": result = try client.authorizationUrl(provider: string("provider"), redirectUri: string("redirectUri"), state: string("state"), codeChallenge: string("codeChallenge"))
    case "validateCallback":
        guard let expires = p["expiresAt"] as? NSNumber, CFGetTypeID(expires) != CFBooleanGetTypeID(), expires.doubleValue.isFinite, expires.doubleValue.rounded() == expires.doubleValue, abs(expires.doubleValue) <= 9007199254740991 else { throw SDKError("invalid_argument", "Expected integer expiry") }
        result = try client.validateCallback(callbackUrl: string("callbackUrl"), redirectUri: string("redirectUri"), state: string("state"), expiresAt: expires.intValue)
    default: throw SDKError("unsupported_action", "Client SDK supports local helpers only")
    }
    output = ["ok": true, "result": result]
} catch let e as SDKError { output = ["ok": false, "error": ["status": e.status, "code": e.code, "message": e.message]] }
catch { output = ["ok": false, "error": ["status": 0, "code": "invalid_argument", "message": "Invalid runner input"]] }
let bytes = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
FileHandle.standardOutput.write(bytes)
FileHandle.standardOutput.write(Data([10]))
