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
import Testing

@testable import Multiaddr

/// Cross-implementation interop fixtures ported from the reference multiaddr test suites
/// (go-multiaddr `multiaddr_test.go`, js-multiaddr `test/index.spec.ts`, rust-multiaddr
/// `tests/lib.rs`). Fixtures using protocols this library does not implement (`http-path`,
/// `memory`) are intentionally omitted.
@Suite("Cross-Implementation Interop")
struct InteropTests {

    // MARK: - Hex helpers

    static func hexToData(_ hex: String) -> Data {
        var data = Data()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            data.append(UInt8(hex[idx..<next], radix: 16)!)
            idx = next
        }
        return data
    }

    // MARK: - Invalid multiaddrs (must throw)

    /// Ported from go/js/rust `construct_fail` suites (supported protocols only).
    static let invalid: [String] = [
        // Missing / incomplete address values
        "/ip4",
        "/ip4/::1",
        "/ip4/fdpsofodsajfdoisa",
        "/ip6",
        "/ip6zone",
        "/ip6zone/",
        "/udp",
        "/tcp",
        "/sctp",
        "/udp/65536",
        "/tcp/65536",
        "/quic/65536",
        "/quic-v1/65536",
        "/ip4/127.0.0.1/udp/jfodsajfidosajfoidsa",
        "/ip4/127.0.0.1/udp",
        "/ip4/127.0.0.1/tcp/jfodsajfidosajfoidsa",
        "/ip4/127.0.0.1/tcp",
        "/ip4/127.0.0.1/quic/1234",
        "/ip4/127.0.0.1/quic-v1/1234",
        "/ip4/1.2.3.4/tcp/-1",
        // Trailing / zero-sized protocols that cannot carry a value
        "/udp/1234/sctp",
        "/udp/1234/udt/1234",
        "/udp/1234/utp/1234",
        // p2p / ipfs peer-id validation
        "/ip4/127.0.0.1/ipfs",
        "/ip4/127.0.0.1/ipfs/tcp",
        "/ip4/127.0.0.1/p2p",
        "/ip4/127.0.0.1/p2p/tcp",
        // unix requires a path
        "/unix",
        // Unknown / typo'd protocol name
        "/ip4/127.0.0.1/unknown",
        // Onion
        "/onion/9imaq4ygg2iegci7:80",
        "/onion/aaimaq4ygg2iegci7:80",
        "/onion/timaq4ygg2iegci7:0",
        "/onion/timaq4ygg2iegci7:-1",
        "/onion/timaq4ygg2iegci7",
        "/onion/timaq4ygg2iegci@:666",
        // Onion3
        "/onion3/9ww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:80",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd7:80",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:0",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:-1",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyy@:666",
        // Garlic32
        "/garlic32/566niximlxdzpanmn4qouucvua3k7neniwss47li5r6ugoertzu",
    ]

    @Test(arguments: invalid)
    func rejectsInvalidMultiaddr(_ string: String) {
        #expect(throws: (any Error).self, "Expected \(string) to fail to parse") {
            try Multiaddr(string)
        }
    }

    // MARK: - Valid multiaddrs (must construct + string→bytes→string round-trip)

    /// Ported from go/js/rust success suites (supported protocols only).
    static let valid: [String] = [
        "/ip4/1.2.3.4",
        "/ip4/0.0.0.0",
        "/ip6/::1",
        "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21",
        "/ip6zone/x/ip6/fe80::1",
        "/udp/0",
        "/tcp/0",
        "/sctp/0",
        "/udp/1234",
        "/tcp/1234",
        "/sctp/1234",
        "/udp/65535",
        "/tcp/65535",
        "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "/udp/1234/sctp/1234",
        "/udp/1234/udt",
        "/udp/1234/utp",
        "/tcp/1234/http",
        "/tcp/1234/tls/http",
        "/tcp/1234/https",
        "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
        "/ip4/127.0.0.1/udp/1234",
        "/ip4/127.0.0.1/udp/0",
        "/ip4/127.0.0.1/tcp/1234",
        "/ip4/127.0.0.1/udp/1234/quic",
        "/ip4/127.0.0.1/udp/1234/quic-v1",
        "/ip4/127.0.0.1/udp/1234/quic-v1/webtransport",
        "/ip4/127.0.0.1/udp/1234/quic-v1/webtransport/certhash/b2uaraocy6yrdblb4sfptaddgimjmmpy",
        "/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234",
        "/unix/a/b/c/d/e",
        "/unix/stdio",
        "/ip4/1.2.3.4/tcp/80/unix/a/b/c/d/e/f",
        "/ip4/127.0.0.1/tcp/9090/http/p2p-webrtc-direct",
        "/ip4/127.0.0.1/tcp/127/ws",
        "/ip4/127.0.0.1/tcp/127/tls",
        "/ip4/127.0.0.1/tcp/127/tls/ws",
        "/ip4/127.0.0.1/tcp/127/noise",
        "/ip4/127.0.0.1/tcp/127/wss",
        "/ip4/127.0.0.1/tcp/127/webrtc-direct",
        "/ip4/127.0.0.1/tcp/127/webrtc",
        "/onion/timaq4ygg2iegci7:1234",
        "/onion/timaq4ygg2iegci7:80/http",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234",
        "/dnsaddr/sjc-1.bootstrap.libp2p.io",
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
        "/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
        "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit",
    ]

    @Test(arguments: valid)
    func binaryRoundTripsValidMultiaddr(_ string: String) throws {
        let ma = try Multiaddr(string)
        let restored = try Multiaddr(ma.binaryPacked())
        #expect(restored == ma, "Binary round-trip changed \(string)")
    }

    // MARK: - Exact string → bytes vectors (from rust-multiaddr `ma_valid`)

    struct Vector: Sendable {
        let string: String
        let hex: String
    }

    static let vectors: [Vector] = [
        Vector(string: "/ip4/1.2.3.4", hex: "0401020304"),
        Vector(string: "/ip4/0.0.0.0", hex: "0400000000"),
        Vector(string: "/ip6/::1", hex: "2900000000000000000000000000000001"),
        Vector(string: "/ip6/2601:9:4f81:9700:803e:ca65:66e8:c21", hex: "29260100094f819700803eca6566e80c21"),
        Vector(string: "/udp/0", hex: "91020000"),
        Vector(string: "/tcp/0", hex: "060000"),
        Vector(string: "/sctp/0", hex: "84010000"),
        Vector(string: "/udp/1234", hex: "910204d2"),
        Vector(string: "/tcp/1234", hex: "0604d2"),
        Vector(string: "/sctp/1234", hex: "840104d2"),
        Vector(string: "/udp/65535", hex: "9102ffff"),
        Vector(string: "/tcp/65535", hex: "06ffff"),
        Vector(
            string: "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC",
            hex: "a503221220d52ebb89d85b02a284948203a62ff28389c57c9f42beec4ec20db76a68911c0b"
        ),
        Vector(string: "/udp/1234/sctp/1234", hex: "910204d2840104d2"),
        Vector(string: "/udp/1234/udt", hex: "910204d2ad02"),
        Vector(string: "/udp/1234/utp", hex: "910204d2ae02"),
        Vector(string: "/tcp/1234/http", hex: "0604d2e003"),
        Vector(string: "/tcp/1234/tls/http", hex: "0604d2c003e003"),
        Vector(string: "/tcp/1234/https", hex: "0604d2bb03"),
        Vector(string: "/ip4/127.0.0.1/udp/1234", hex: "047f000001910204d2"),
        Vector(string: "/ip4/127.0.0.1/udp/0", hex: "047f00000191020000"),
        Vector(string: "/ip4/127.0.0.1/tcp/1234", hex: "047f0000010604d2"),
        Vector(string: "/onion/aaimaq4ygg2iegci:80", hex: "bc030010c0439831b48218480050"),
        Vector(
            string: "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234",
            hex: "bd03adadec040be047f9658668b11a504f3155001f231a37f54c4476c07fb4cc139ed7e30304d2"
        ),
        Vector(
            string: "/dnsaddr/sjc-1.bootstrap.libp2p.io",
            hex: "3819736a632d312e626f6f7473747261702e6c69627032702e696f"
        ),
        Vector(string: "/ip4/127.0.0.1/tcp/127/ws", hex: "047f00000106007fdd03"),
        Vector(string: "/ip4/127.0.0.1/tcp/127/tls", hex: "047f00000106007fc003"),
        Vector(string: "/ip4/127.0.0.1/tcp/127/tls/ws", hex: "047f00000106007fc003dd03"),
        Vector(string: "/ip4/127.0.0.1/tcp/127/noise", hex: "047f00000106007fc603"),
    ]

    @Test(arguments: vectors)
    func encodesToExpectedBytes(_ v: Vector) throws {
        let packed = try Multiaddr(v.string).binaryPacked()
        #expect(packed.hexString() == v.hex, "Encoding mismatch for \(v.string)")
    }

    @Test(arguments: vectors)
    func decodesFromExpectedBytes(_ v: Vector) throws {
        let ma = try Multiaddr(InteropTests.hexToData(v.hex))
        #expect(ma.description == v.string, "Decoding mismatch for hex \(v.hex)")
    }

    // MARK: - Decapsulate (from go-multiaddr `TestDecapsulate`)

    struct DecapCase: Sendable {
        let source: String
        let arg: String
        let expected: String
    }

    static let decapCases: [DecapCase] = [
        DecapCase(source: "/ip4/1.2.3.4/tcp/1234", arg: "/ip4/1.2.3.4", expected: "/"),
        DecapCase(source: "/ip4/1.2.3.5/tcp/1234", arg: "/ip4/5.3.2.1", expected: "/ip4/1.2.3.5/tcp/1234"),
        DecapCase(source: "/ip4/1.2.3.5/udp/1234/quic-v1", arg: "/udp/1234", expected: "/ip4/1.2.3.5"),
        DecapCase(source: "/ip4/1.2.3.6/udp/1234/quic-v1", arg: "/udp/1234/quic-v1", expected: "/ip4/1.2.3.6"),
        DecapCase(source: "/ip4/1.2.3.7/tcp/1234", arg: "/ws", expected: "/ip4/1.2.3.7/tcp/1234"),
        DecapCase(source: "/dnsaddr/wss.com/tcp/4001/ws", arg: "/wss", expected: "/dnsaddr/wss.com/tcp/4001/ws"),
        DecapCase(source: "/dnsaddr/wss.com/tcp/4001/wss", arg: "/wss", expected: "/dnsaddr/wss.com/tcp/4001"),
    ]

    @Test(arguments: decapCases)
    func decapsulateMatchesReference(_ c: DecapCase) throws {
        let ma = try Multiaddr(c.source)
        let arg = try Multiaddr(c.arg)
        #expect(ma.decapsulate(arg).description == c.expected, "Decapsulate mismatch for \(c.source) / \(c.arg)")
    }
}
