// swift-tools-version:5.5
//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2025 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

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
