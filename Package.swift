// swift-tools-version:5.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-multiaddr",
    platforms: [
        .iOS(.v12),
        .macOS(.v10_14)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "Multiaddr",
            targets: ["Multiaddr"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/swift-libp2p/swift-varint.git", .upToNextMajor(from: "0.0.1")),
        .package(url: "https://github.com/swift-libp2p/swift-multicodec.git", .upToNextMajor(from: "0.0.1")),
        .package(url: "https://github.com/swift-libp2p/swift-multibase.git", .upToNextMajor(from: "0.0.1")),
        .package(url: "https://github.com/swift-libp2p/swift-multihash.git", .upToNextMajor(from: "0.0.1")),
        .package(url: "https://github.com/swift-libp2p/swift-cid.git", .upToNextMajor(from: "0.0.1"))
        //.package(name: "PeerID", path: "../PeerID")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "Multiaddr",
            dependencies: [
                .product(name: "VarInt", package: "swift-varint"),
                .product(name: "Multicodec", package: "swift-multicodec"),
                .product(name: "Multibase", package: "swift-multibase"),
                .product(name: "Multihash", package: "swift-multihash"),
                .product(name: "CID", package: "swift-cid"),
            ]),
        .testTarget(
            name: "MultiaddrTests",
            dependencies: ["Multiaddr"]),
    ]
)
