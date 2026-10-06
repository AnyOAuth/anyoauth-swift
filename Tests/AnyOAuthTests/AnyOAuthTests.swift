import XCTest
@testable import AnyOAuth
final class AnyOAuthTests: XCTestCase {
    func testRFC7636() throws {
        XCTAssertEqual(try AnyOAuth(clientId: "test").pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }
    func testModelDecoding() throws {
        var value: [String: Any] = ["subject": "google:123", "provider": "google", "providerSubject": "123", "name": NSNull(), "username": NSNull(), "email": NSNull(), "emailVerified": false, "avatarUrl": NSNull(), "additive": true]
        let profile = try Profile.fromJSON(value)
        XCTAssertNil(profile.name)
        XCTAssertEqual(profile.provider, .google)
        XCTAssertTrue(profile.toJSON()["name"] is NSNull)
        value.removeValue(forKey: "name")
        XCTAssertThrowsError(try Profile.fromJSON(value))
        value["name"] = NSNull(); value["provider"] = "other"
        XCTAssertThrowsError(try Profile.fromJSON(value))
        value["provider"] = "google"; value["emailVerified"] = 1
        XCTAssertThrowsError(try Profile.fromJSON(value))
        let error = try ApiError.fromJSON(["error": "denied"])
        XCTAssertNil(error.toJSON()["message"])
        XCTAssertThrowsError(try ApiError.fromJSON(["error": "denied", "message": NSNull()]))
        XCTAssertThrowsError(try validateSchema("TokenResponse", ["access_token": "invalid", "token_type": "Bearer", "expires_in": 900, "scope": "profile"]))
    }
}
