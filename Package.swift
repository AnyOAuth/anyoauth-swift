// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "AnyOAuth", platforms: [.macOS(.v10_15), .iOS(.v13)], products: [.library(name: "AnyOAuth", targets: ["AnyOAuth"])], targets: [.target(name: "AnyOAuth"), .executableTarget(name: "conformance", dependencies: ["AnyOAuth"]), .testTarget(name: "AnyOAuthTests", dependencies: ["AnyOAuth"])])
