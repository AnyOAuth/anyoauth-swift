import Foundation
import CoreFoundation
import CryptoKit

public struct SDKError: Error, Sendable {
    public let status: Int = 0
    public let code: String
    public let message: String
    public init(_ code: String, _ message: String) { self.code = code; self.message = message }
}
private func fail(_ message: String) throws -> Never { throw SDKError("invalid_argument", message) }
private func safeURL(_ text: String, origin: Bool = false, query: Bool = false) throws -> URLComponents {
    if text.isEmpty || text.contains("\\") || text.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) || $0.value < 32 || $0.value == 127 }) { try fail("Unsafe URL") }
    if text.range(of: "%(?![A-Fa-f0-9]{2})", options: .regularExpression) != nil { try fail("Invalid URL encoding") }
    guard let u = URLComponents(string: text), let host = u.host, !host.isEmpty,
          u.user == nil, u.password == nil, u.fragment == nil,
          u.scheme == "https" || (u.scheme == "http" && ["localhost", "127.0.0.1", "[::1]", "::1"].contains(host)),
          u.port == nil || (1...65535).contains(u.port!), query || u.query == nil,
          !origin || u.percentEncodedPath.isEmpty || u.percentEncodedPath == "/" else { try fail("Unsafe URL") }
    let authority = text.components(separatedBy: "://").last!.components(separatedBy: "/").first!.components(separatedBy: "?").first!
    if authority.contains("%") || authority.contains("@") { try fail("Unsafe URL authority") }
    return u
}
public func validateSchema(_ name: String, _ value: Any) throws {
    guard let schema = nativeSchemas[name] else { try fail("Unknown model") }
    try validateValue(schema, value)
}
private func validateValue(_ s: [String: Any], _ value: Any) throws {
    if let r = s["$ref"] as? String { try validateSchema(r.components(separatedBy: "/").last!, value); return }
    let types = (s["type"] as? [String]) ?? [s["type"] as! String]
    if value is NSNull { if types.contains("null") { return }; try fail("Unexpected null") }
    let kind = types.first(where: { $0 != "null" })!
    switch kind {
    case "string":
        guard let v = value as? String else { try fail("Expected string") }
        let length = v.unicodeScalars.count
        if let min = s["minLength"] as? Int, length < min { try fail("String too short") }
        if let max = s["maxLength"] as? Int, length > max { try fail("String too long") }
        if let pattern = s["pattern"] as? String {
            let match = v.range(of: pattern, options: .regularExpression)
            if match == nil || (pattern.hasPrefix("^") && pattern.hasSuffix("$") && match != (v.startIndex..<v.endIndex)) { try fail("Invalid string format") }
        }
        if let values = s["enum"] as? [String], !values.contains(v) { try fail("Invalid enum") }
        if let constant = s["const"] as? String, v != constant { try fail("Invalid constant") }
        if s["format"] as? String == "uri" { _ = try safeURL(v) }
    case "integer":
        guard let v = value as? NSNumber, CFGetTypeID(v) != CFBooleanGetTypeID(), v.doubleValue.isFinite, v.doubleValue.rounded() == v.doubleValue, abs(v.doubleValue) <= 9007199254740991 else { try fail("Expected safe integer") }
        if let constant = s["const"] as? NSNumber, v != constant { try fail("Invalid constant") }
    case "boolean":
        guard let v = value as? NSNumber, CFGetTypeID(v) == CFBooleanGetTypeID() else { try fail("Expected boolean") }
    case "array":
        guard let values = value as? [Any], let item = s["items"] as? [String: Any] else { try fail("Expected array") }
        for v in values { try validateValue(item, v) }
    case "object":
        guard let m = value as? [String: Any], let props = s["properties"] as? [String: Any] else { try fail("Expected object") }
        for key in s["required"] as? [String] ?? [] { if m[key] == nil { try fail("Missing required field") } }
        if s["additionalProperties"] as? Bool == false && m.keys.contains(where: { props[$0] == nil }) { try fail("Unexpected field") }
        for (key, p) in props { if let v = m[key] { try validateValue(p as! [String: Any], v) } }
    default: try fail("Unsupported schema")
    }
}
public struct AnyOAuth: Sendable {
    public let baseUrl: String
    public let clientId: String
    public init(clientId: String, baseUrl: String = "https://api.anyoauth.com") throws {
        _ = try safeURL(baseUrl, origin: true)
        let properties = nativeSchemas["AuthorizationParameters"]!["properties"] as! [String: Any]
        try validateValue(properties["client_id"] as! [String: Any], clientId)
        self.clientId = clientId; self.baseUrl = baseUrl.hasSuffix("/") ? String(baseUrl.dropLast()) : baseUrl
    }
    public func pkceChallenge(_ verifier: String) throws -> String {
        try validateSchema("CodeVerifier", verifier)
        return Self.base64url(Data(SHA256.hash(data: Data(verifier.utf8))))
    }
    private static func base64url(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    public func createTransaction() throws -> Transaction {
        var rng = SystemRandomNumberGenerator()
        let state = Self.base64url(Data((0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }))
        let verifier = Self.base64url(Data((0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }))
        let now = Int(Date().timeIntervalSince1970)
        return try Transaction.fromJSON(["state": state, "codeVerifier": verifier, "codeChallenge": pkceChallenge(verifier), "createdAt": now, "expiresAt": now + 600])
    }
    public func authorizationUrl(provider: String, redirectUri: String, state: String, codeChallenge: String) throws -> String {
        let params = ["client_id": clientId, "provider": provider, "redirect_uri": redirectUri, "state": state, "code_challenge": codeChallenge, "code_challenge_method": "S256", "response_type": "code"]
        try validateSchema("AuthorizationParameters", params)
        var u = URLComponents(string: baseUrl + "/authorize")!
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        u.percentEncodedQuery = params.keys.sorted().map { $0 + "=" + params[$0]!.addingPercentEncoding(withAllowedCharacters: allowed)! }.joined(separator: "&")
        return u.string!
    }
    public func validateCallback(callbackUrl: String, redirectUri: String, state: String, expiresAt: Int) throws -> [String: String] {
        try validateSchema("RedirectUri", redirectUri)
        _ = try safeURL(callbackUrl, query: true)
        guard callbackUrl.components(separatedBy: "?").first == redirectUri else { throw SDKError("invalid_callback", "Callback does not match saved redirect") }
        guard expiresAt > Int(Date().timeIntervalSince1970) else { throw SDKError("transaction_expired", "Transaction expired") }
        var params: [String: String] = [:]
        let raw = callbackUrl.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        if raw.count == 2 {
            for pair in raw[1].split(separator: "&", omittingEmptySubsequences: false) {
                let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard let key = String(parts[0]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
                      let value = (parts.count == 2 ? String(parts[1]) : "").replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
                      params[key] == nil else { throw SDKError("invalid_callback", "Invalid or duplicate query parameter") }
                params[key] = value
            }
        }
        guard !state.isEmpty, params["state"] == state else { throw SDKError("state_mismatch", "Callback state mismatch") }
        guard (params["code"] != nil) != (params["error"] != nil), !(params["code"] ?? params["error"] ?? "").isEmpty else { throw SDKError("invalid_callback", "Expected exactly one code or error") }
        if let code = params["code"] { try validateSchema("CallbackCode", code); return ["code": code, "state": state] }
        return ["error": params["error"]!, "state": state]
    }
}

private let nativeSchemas = try! JSONSerialization.jsonObject(with: Data(###"{"Provider":{"type":"string","enum":["google","github"]},"RedirectUri":{"type":"string","format":"uri","maxLength":2048,"x-validation":"redirect","description":"Exact registered HTTPS URL or HTTP loopback; no credentials, query or fragment."},"TokenResponse":{"type":"object","required":["access_token","token_type","expires_in","scope"],"properties":{"access_token":{"type":"string","pattern":"^aop_[A-Za-z0-9_-]{43}$"},"token_type":{"type":"string","const":"Bearer"},"expires_in":{"type":"integer","const":900},"scope":{"type":"string","const":"profile"}}},"Profile":{"type":"object","required":["subject","provider","providerSubject","name","username","email","emailVerified","avatarUrl"],"properties":{"subject":{"type":"string"},"provider":{"$ref":"#/components/schemas/Provider"},"providerSubject":{"type":"string"},"name":{"type":["string","null"]},"username":{"type":["string","null"]},"email":{"type":["string","null"]},"emailVerified":{"type":"boolean"},"avatarUrl":{"type":["string","null"]}}},"ProviderStatus":{"type":"object","required":["id","configured","enabled","available"],"properties":{"id":{"$ref":"#/components/schemas/Provider"},"configured":{"type":"boolean"},"enabled":{"type":"boolean"},"available":{"type":"boolean"}}},"ProviderStatuses":{"type":"array","items":{"$ref":"#/components/schemas/ProviderStatus"}},"ApiError":{"type":"object","required":["error"],"properties":{"error":{"type":"string"},"message":{"type":"string"}}},"Transaction":{"type":"object","required":["state","codeVerifier","codeChallenge","createdAt","expiresAt"],"properties":{"state":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"},"codeVerifier":{"type":"string","pattern":"^[A-Za-z0-9._~-]{43,128}$"},"codeChallenge":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"},"createdAt":{"type":"integer"},"expiresAt":{"type":"integer"}}},"AuthorizationParameters":{"type":"object","additionalProperties":false,"required":["client_id","provider","redirect_uri","state","code_challenge","code_challenge_method","response_type"],"properties":{"client_id":{"type":"string","minLength":1},"provider":{"$ref":"#/components/schemas/Provider"},"redirect_uri":{"$ref":"#/components/schemas/RedirectUri"},"state":{"type":"string","minLength":16,"maxLength":512},"code_challenge":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"},"code_challenge_method":{"type":"string","const":"S256"},"response_type":{"type":"string","const":"code"}}},"CodeVerifier":{"type":"string","pattern":"^[A-Za-z0-9._~-]{43,128}$"},"CallbackCode":{"type":"string","minLength":1,"maxLength":200}}"###.utf8)) as! [String: [String: Any]]

public enum Provider: String, Codable, Sendable { case google; case github }

public typealias RedirectUri = String

public struct TokenResponse: Sendable {
    public let access_token: String
    public let token_type: String
    public let expires_in: Int
    public let scope: String
    public static func fromJSON(_ value: Any) throws -> TokenResponse {
        try validateSchema("TokenResponse", value)
        let m = value as! [String: Any]
        return TokenResponse(access_token: m["access_token"] as! String, token_type: m["token_type"] as! String, expires_in: (m["expires_in"] as! NSNumber).intValue, scope: m["scope"] as! String)
    }
    public func toJSON() -> [String: Any] {
        let result: [String: Any] = ["access_token": access_token, "token_type": token_type, "expires_in": expires_in, "scope": scope]

        return result
    }
}

public struct Profile: Sendable {
    public let subject: String
    public let provider: Provider
    public let providerSubject: String
    public let name: String?
    public let username: String?
    public let email: String?
    public let emailVerified: Bool
    public let avatarUrl: String?
    public static func fromJSON(_ value: Any) throws -> Profile {
        try validateSchema("Profile", value)
        let m = value as! [String: Any]
        return Profile(subject: m["subject"] as! String, provider: Provider(rawValue: m["provider"] as! String)!, providerSubject: m["providerSubject"] as! String, name: (m["name"] == nil || m["name"] is NSNull) ? nil : (m["name"] as! String), username: (m["username"] == nil || m["username"] is NSNull) ? nil : (m["username"] as! String), email: (m["email"] == nil || m["email"] is NSNull) ? nil : (m["email"] as! String), emailVerified: m["emailVerified"] as! Bool, avatarUrl: (m["avatarUrl"] == nil || m["avatarUrl"] is NSNull) ? nil : (m["avatarUrl"] as! String))
    }
    public func toJSON() -> [String: Any] {
        let result: [String: Any] = ["subject": subject, "provider": provider.rawValue, "providerSubject": providerSubject, "name": name as Any? ?? NSNull(), "username": username as Any? ?? NSNull(), "email": email as Any? ?? NSNull(), "emailVerified": emailVerified, "avatarUrl": avatarUrl as Any? ?? NSNull()]

        return result
    }
}

public struct ProviderStatus: Sendable {
    public let id: Provider
    public let configured: Bool
    public let enabled: Bool
    public let available: Bool
    public static func fromJSON(_ value: Any) throws -> ProviderStatus {
        try validateSchema("ProviderStatus", value)
        let m = value as! [String: Any]
        return ProviderStatus(id: Provider(rawValue: m["id"] as! String)!, configured: m["configured"] as! Bool, enabled: m["enabled"] as! Bool, available: m["available"] as! Bool)
    }
    public func toJSON() -> [String: Any] {
        let result: [String: Any] = ["id": id.rawValue, "configured": configured, "enabled": enabled, "available": available]

        return result
    }
}

public typealias ProviderStatuses = [ProviderStatus]

public struct ApiError: Sendable {
    public let error: String
    public let message: String?
    public static func fromJSON(_ value: Any) throws -> ApiError {
        try validateSchema("ApiError", value)
        let m = value as! [String: Any]
        return ApiError(error: m["error"] as! String, message: (m["message"] == nil || m["message"] is NSNull) ? nil : (m["message"] as! String))
    }
    public func toJSON() -> [String: Any] {
        var result: [String: Any] = ["error": error, "message": message as Any? ?? NSNull()]
        if message == nil { result.removeValue(forKey: "message") }
        return result
    }
}

public struct Transaction: Sendable {
    public let state: String
    public let codeVerifier: String
    public let codeChallenge: String
    public let createdAt: Int
    public let expiresAt: Int
    public static func fromJSON(_ value: Any) throws -> Transaction {
        try validateSchema("Transaction", value)
        let m = value as! [String: Any]
        return Transaction(state: m["state"] as! String, codeVerifier: m["codeVerifier"] as! String, codeChallenge: m["codeChallenge"] as! String, createdAt: (m["createdAt"] as! NSNumber).intValue, expiresAt: (m["expiresAt"] as! NSNumber).intValue)
    }
    public func toJSON() -> [String: Any] {
        let result: [String: Any] = ["state": state, "codeVerifier": codeVerifier, "codeChallenge": codeChallenge, "createdAt": createdAt, "expiresAt": expiresAt]

        return result
    }
}
