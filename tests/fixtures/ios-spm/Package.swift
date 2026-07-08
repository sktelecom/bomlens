// swift-tools-version:5.7
import PackageDescription
let package = Package(name: "App", dependencies: [
  .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.8.1"),
  .package(url: "https://github.com/apple/swift-log.git", from: "1.5.3"),
])
