# Multiaddr

[![](https://img.shields.io/badge/made%20by-Breth-blue.svg?style=flat-square)](https://breth.app)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](https://github.com/multiformats/multiformats)
[![Swift Package Manager compatible](https://img.shields.io/badge/SPM-compatible-blue.svg?style=flat-square)](https://github.com/apple/swift-package-manager)
![Build & Test (macos and linux)](https://github.com/swift-libp2p/swift-multiaddr/actions/workflows/build+test.yml/badge.svg)

> Composable and future-proof network addresses 

## Table of Contents

- [Overview](#overview)
- [Install](#install)
- [Usage](#usage)
  - [Example](#example)
  - [API](#api)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Overview
Multiaddr aims to make network addresses future-proof, composable, and efficient.

Current addressing schemes have a number of problems.
- They hinder protocol migrations and interoperability between protocols.
- They don't compose well. There are plenty of X-over-Y constructions, but only few of them can be addressed in a classic URI/URL or host:port scheme.
- They don't multiplex: they address ports, not processes.
- They're implicit, in that they presume out-of-band values and context.
- They don't have efficient machine-readable representations.

Multiaddr solves these problems by modelling network addresses as arbitrary encapsulations of protocols.
- support addresses for any network protocol.
- are self-describing.
- conform to a simple syntax, making them trivial to parse and construct.
- have human-readable and efficient machine-readable representations.
- encapsulate well, allowing trivial wrapping and unwrapping of encapsulation layers.

#### Note:
For more info check out the [Multiformats / Multiaddr Spec](https://github.com/multiformats/multiaddr)


## Install

Include the following dependency in your Package.swift file
```Swift
let package = Package(
    ...
    dependencies: [
        ...
        .package(url: "https://github.com/swift-libp2p/swift-multiaddr.git", .upToNextMinor(from: "0.2.0"))
    ],
    ...
        .target(
            ...
            dependencies: [
                ...
                .product(name: "Multiaddr", package: "swift-multiaddr"),
            ]),
    ...
)
```

## Usage

### Example 
check out the [tests](https://github.com/swift-libp2p/swift-multiaddr/tree/main/Tests/MultiaddrTests) for more examples

```Swift

import Multiaddr

/// Instantiate a Multiaddr from a String describing your protocol stack 
let addr = try Multiaddr("/dns6/foo.com/tcp/443/https")

/// - Note: This Multiaddr indicates that the server is reachable over `DNS` at `foo.com` and is running an `https` server over `tcp` on port 443
/// - Note: This lets a libp2p node know what protocol stack is necessary for communication with this server.

dump(addr)

// ▿ /dns6/foo.com/tcp/443/https
//   ▿ addresses: 3 elements
//     ▿ /dns6/foo.com
//       - addrProtocol: Multicodec.Codecs.dns6
//       ▿ address: Optional("foo.com")
//         - some: "foo.com"
//     ▿ /tcp/443
//       - addrProtocol: Multicodec.Codecs.tcp
//       ▿ address: Optional("443")
//         - some: "443"
//     ▿ /https
//       - addrProtocol: Multicodec.Codecs.https
//       - address: nil


/// Address Encapsulation
let ip = try! Multiaddr("/ip4/127.0.0.1")
let proto = try! Multiaddr("/udt")

ip.encapsulate(proto) // -> "/ip4/127.0.0.1/udt"

/// Address Decapsulation (removes the last occurrence of the target and everything after it)
let full = try! Multiaddr("/ip4/1.2.3.4/tcp/80")
let port = try! Multiaddr("/tcp/80")

full.decapsulate(port) // -> "/ip4/1.2.3.4"


/// Multiaddr is a Collection of its Addresses, so you can iterate and use the standard library
for address in full {
    print(address.codec, address.addr as Any)
}
full.count      // -> 2
full.first?.codec // -> .ip4


/// Extract a PeerID (as a String or a typed Multihash)
let p2p = try! Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
p2p.getPeerIDString()    // -> Optional("Qmcgpsy...")
p2p.getPeerIDMultihash() // -> Optional(<Multihash>)


/// Multiaddr is Codable (encoded as its human-readable string), Hashable, Equatable and Sendable
let json = try JSONEncoder().encode(full)      // "\/ip4\/1.2.3.4\/tcp\/80"
let back = try JSONDecoder().decode(Multiaddr.self, from: json)
let set: Set<Multiaddr> = [full, back]          // count == 1

```

### API
```Swift

/// Initializers
Multiaddr.init(_ string: String) throws    // parse the human-readable form, e.g. "/ip4/127.0.0.1/tcp/4001"
Multiaddr.init(_ bytes: Data) throws        // parse the packed binary form
Multiaddr.init(_ proto: MultiaddrProtocol, address: String?) throws


/// The ordered list of Address components (left-to-right)
Multiaddr.addresses: [Address] { get }

/// Data representation of the `Multiaddr`
Multiaddr.binaryPacked() throws -> Data

/// Returns a list of `Protocol` elements contained by this `Multiaddr`, ordered from left-to-right.
Multiaddr.protocols() -> [MultiaddrProtocol]

/// Returns the protocols as Multicodec Names, ordered from left-to-right.
Multiaddr.protoNames() -> [String]

/// Returns the protocols as Multicodec Codes, ordered from left-to-right.
Multiaddr.protoCodes() -> [UInt64]

/// Encapsulation
Multiaddr.encapsulate(_ other: Multiaddr) -> Multiaddr
Multiaddr.encapsulate(_ other: String) throws -> Multiaddr
Multiaddr.encapsulate(proto: MultiaddrProtocol, address: String?) throws -> Multiaddr

/// Decapsulation — removes the LAST occurrence of the target and everything after it
Multiaddr.decapsulate(_ other: Multiaddr) -> Multiaddr
Multiaddr.decapsulate(_ other: String) -> Multiaddr
Multiaddr.decapsulate(_ other: MultiaddrProtocol) -> Multiaddr

/// Removes and returns the last `Address` of this `Multiaddr`.
Multiaddr.pop() -> Address?

/// Peer ID accessors (for /p2p and /ipfs components)
Multiaddr.getPeerIDString() -> String?          // the raw peer-id string, if present
Multiaddr.getPeerIDMultihash() -> Multihash?    // the peer-id as a typed Multihash (handles CID-encoded ids)

/// Extracts a Unix Path from the Multiaddress if one exists, otherwise returns nil
Multiaddr.getPath() -> String?

/// Lookup / mutation by codec
Multiaddr.getFirstAddress(forCodec codec: MultiaddrProtocol) -> Address?
Multiaddr.getAddresses(forCodec codec: MultiaddrProtocol) -> [Address]
Multiaddr.swap(address newAddress: String, forCodec codec: MultiaddrProtocol) throws -> Multiaddr
Multiaddr.mutatingSwap(address newAddress: String, forCodec codec: MultiaddrProtocol) throws


/// Protocol conformances
/// - Equatable, Hashable, Sendable
/// - CustomStringConvertible  (`description` is the human-readable string)
/// - Codable                  (encoded/decoded as the human-readable string)
/// - RandomAccessCollection   (iterate the `Address` components directly)

```

### Supported Protocols
`ip4`, `ip6`, `ip6zone`, `ipcidr`, `tcp`, `udp`, `dccp`, `sctp`, `dns`, `dns4`, `dns6`, `dnsaddr`,
`sni`, `http`, `https`, `ws`, `wss`, `quic`, `quic-v1`, `webtransport`, `certhash`, `p2p`/`ipfs`,
`p2p-circuit`, `p2p-webrtc-star`, `p2p-websocket-star`, `p2p-webrtc-direct`, `webrtc`,
`webrtc-direct`, `tls`, `noise`, `plaintextv2`, `onion`, `onion3`, `garlic32`, `garlic64`, `unix`,
`udt`, `utp`.

> Parsing is strict: unknown protocol names and malformed binary are rejected rather than silently
> dropped. The binary (`binaryPacked()`) encoding is verified byte-for-byte against the
> go-, js-, and rust-multiaddr reference test vectors.

## Contributing

Contributions are welcomed! This code is very much a proof of concept. I can guarantee you there's a better / safer way to accomplish the same results. Any suggestions, improvements, or even just critques, are welcome! 

Let's make this code better together! 🤝

## Credits

- Major credit to the work done by [lukereichold - swift-multiaddr](https://github.com/lukereichold/swift-multiaddr), this repo is a slightly modified fork of his project
- [NeoTeo & Richard Litt - SwiftMultiaddr ](https://github.com/multiformats/SwiftMultiaddr) 
- [krzyzanowskim - CryptoSwift](https://github.com/krzyzanowskim/CryptoSwift)

## License

[MIT](LICENSE) © 2026 Breth Inc.























