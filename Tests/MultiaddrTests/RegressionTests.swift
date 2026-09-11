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

import Foundation
import Multihash
import Testing

@testable import Multiaddr

/// Regression tests covering the audit bug-fixes and the new public API surface.
@Suite("Regression Tests")
struct RegressionTests {

    @Test func testUnknownProtocolInStringThrows() {
        // Previously "/foo" was silently skipped, yielding just "/ip4/1.2.3.4".
        #expect(throws: MultiaddrError.unknownProtocol) {
            try Multiaddr("/foo/ip4/1.2.3.4")
        }
    }

    @Test func testTruncatedBinaryThrows() {
        // ip4 (code 0x04) claims a 4-byte address but only 1 byte follows.
        #expect(throws: (any Error).self) {
            try Multiaddr(Data([0x04, 0x01]))
        }
    }

    @Test func testValidBinaryRoundTrips() throws {
        let original = try Multiaddr("/ip4/127.0.0.1/tcp/4001")
        let packed = try original.binaryPacked()
        let restored = try Multiaddr(packed)
        #expect(restored == original)
        #expect(restored.description == "/ip4/127.0.0.1/tcp/4001")
    }

    @Test func testHashableInSetDoesNotTrap() throws {
        let a = try Multiaddr("/ip4/127.0.0.1/tcp/4001")
        let b = try Multiaddr("/ip4/127.0.0.1/tcp/4001")
        let c = try Multiaddr("/ip4/10.0.0.1/udp/53")
        let set: Set<Multiaddr> = [a, b, c]
        #expect(set.count == 2)
    }

    @Test func testIPv6WrongLengthThrowsIPv6Error() {
        #expect(throws: MultiaddrError.parseIPv6AddressFail) {
            try IPv6.string(for: Data([0x01, 0x02, 0x03]))
        }
    }

    @Test func testIPv6RoundTrips() throws {
        let ma = try Multiaddr("/ip6/2001:db8::1/tcp/443")
        let restored = try Multiaddr(ma.binaryPacked())
        #expect(restored == ma)
    }

    @Test func testDecapsulateOverloadsAreConsistent() throws {
        let ma = try Multiaddr("/ip4/1.1.1.1/tcp/80/ip4/1.1.1.1/tcp/90")
        let expected = "/ip4/1.1.1.1/tcp/80"

        let byMultiaddr = ma.decapsulate(try Multiaddr("/ip4/1.1.1.1"))
        let byString = ma.decapsulate("ip4")

        #expect(byMultiaddr.description == expected)
        #expect(byString.description == expected)
        #expect(byMultiaddr == byString)
    }

    @Test func testOnion3WrongLengthThrows() {
        #expect(throws: MultiaddrError.invalidOnionHostAddress) {
            try Onion3.string(for: Data(repeating: 0, count: 10))
        }
    }

    @Test func testOnion3RoundTrips() throws {
        let ma = try Multiaddr("/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234")
        let restored = try Multiaddr(ma.binaryPacked())
        #expect(restored == ma)
    }

    @Test func testCodableRoundTrip() throws {
        let ma = try Multiaddr("/ip4/127.0.0.1/tcp/4001")
        let data = try JSONEncoder().encode(ma)
        let decoded = try JSONDecoder().decode(Multiaddr.self, from: data)
        #expect(decoded == ma)
        // Encodes as a plain JSON string.
        #expect(String(data: data, encoding: .utf8) == "\"\\/ip4\\/127.0.0.1\\/tcp\\/4001\"")
    }

    @Test func testIterationOverAddresses() throws {
        let ma = try Multiaddr("/ip4/127.0.0.1/tcp/4001")
        #expect(ma.count == 2)
        #expect(ma.first?.codec == .ip4)
        #expect(ma.last?.codec == .tcp)
        let codecs = ma.map { $0.codec }
        #expect(codecs == [.ip4, .tcp])
    }

    @Test func testGetPeerIDMultihash() throws {
        let peerID = "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let ma = try Multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/\(peerID)")
        #expect(ma.getPeerIDString() == peerID)
        #expect(ma.getPeerIDMultihash()?.asString(base: .base58btc) == peerID)

        let noPeer = try Multiaddr("/ip4/127.0.0.1/tcp/4001")
        #expect(noPeer.getPeerIDMultihash() == nil)
    }
}
