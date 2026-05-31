import ArgumentParser
import Logging

@main
struct SwiftExample: ParsableCommand {
    func run() throws {
        let logger = Logger(label: "com.example.swift")
        logger.info("SBOM tools Swift/SPM example")
    }
}
