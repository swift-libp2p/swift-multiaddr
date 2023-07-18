import XCTest
@testable import Multiaddr
import Multibase
import Multihash
import CID

final class MultiaddrTests: XCTestCase {
    func testDump() throws {
        let addr = try Multiaddr("/dns6/foo.com/tcp/443/https")
        dump(addr)
    }
    
    func testCreateMultiaddrFromString() throws {
        let m = try! Multiaddr("/ip4/127.0.0.1/udp/1234")
        let expectedAddress1 = try Address(addrProtocol: .ip4, address: "127.0.0.1")
        let expectedAddress2 = try Address(addrProtocol: .udp, address: "1234")
        
        XCTAssertEqual(m.addresses.first, expectedAddress1)
        XCTAssertEqual(m.addresses.last, expectedAddress2)
    }
    
    func testCreateMultiaddrFromString_LeadingSlashRequired() {
        XCTAssertThrowsError(try Multiaddr("ip4/127.0.0.1/udp/1234")) { error in
            XCTAssertEqual(error as! MultiaddrError, MultiaddrError.invalidFormat)
        }
    }
    
    func testSwapMultiaddrFromString() {
        let ma = try! Multiaddr("/ip4/127.0.0.1/udp/1234")
        // Assert Invalid Address Throws Error
        XCTAssertThrowsError(try ma.swap(address: "192.168.1.644", forCodec: .ip4))
        // Assert Valid Address works
        XCTAssertNoThrow(try ma.swap(address: "192.168.1.44", forCodec: .ip4))
        XCTAssertEqual(try ma.swap(address: "192.168.1.44", forCodec: .ip4).description, "/ip4/192.168.1.44/udp/1234")
        
        // Assert Invalid UDP Port Throws Error
        XCTAssertThrowsError(try ma.swap(address: "1235.1", forCodec: .udp))
        XCTAssertThrowsError(try ma.swap(address: "123511", forCodec: .udp))
        // Assert Valid Port works
        XCTAssertNoThrow(try ma.swap(address: "1235", forCodec: .udp))
        XCTAssertEqual(try ma.swap(address: "1235", forCodec: .udp).description, "/ip4/127.0.0.1/udp/1235")
        
        XCTAssertEqual(ma.description, "/ip4/127.0.0.1/udp/1234")
    }
    
    func testSwapMultiaddrFromStringMutating() {
        var ma = try! Multiaddr("/ip4/127.0.0.1/udp/1234")
        // Assert Invalid Address Throws Error
        XCTAssertThrowsError(try ma.mutatingSwap(address: "192.168.1.644", forCodec: .ip4))
        // Assert Valid Address works
        XCTAssertNoThrow(try ma.mutatingSwap(address: "192.168.1.44", forCodec: .ip4))
        print(ma)
        
        // Assert Invalid UDP Port Throws Error
        XCTAssertThrowsError(try ma.mutatingSwap(address: "1235.1", forCodec: .udp))
        XCTAssertThrowsError(try ma.mutatingSwap(address: "123511", forCodec: .udp))
        // Assert Valid Port works
        XCTAssertNoThrow(try ma.mutatingSwap(address: "1235", forCodec: .udp))
        
        print(ma)
        XCTAssertEqual(ma.description, "/ip4/192.168.1.44/udp/1235")
    }
    
    func testHashable() {
        let addresses = [
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt"),
            try! Multiaddr("/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"),
            
            /// Duplicate Entries
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt"),
            try! Multiaddr("/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ")
        ]
        
        XCTAssertEqual(addresses.count, 10)
        
        /// Convert to Set and ensure we only have 5
        XCTAssertEqual(Set(addresses).count, 5)
    }
    
    func testContainsEquatable() {
        var addresses = [
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt"),
            try! Multiaddr("/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"),
        ]
        
        /// Mostly Duplicate Entries
        let duplicates = [
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb"),
            try! Multiaddr("/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt"),
            try! Multiaddr("/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ")
        ]
        
        for duplicate in duplicates {
            if !addresses.contains(duplicate) {
                addresses.append(duplicate)
            }
        }
        
        XCTAssertEqual(addresses.count, 5)
    }
    
    func testCreateMultiaddrFromBytes_IPv4() {
        let bytes = [0x04, 0xc0, 0x00, 0x02, 0x2a] as [UInt8] // 04c000022a
        let data = Data(bytes: bytes, count: bytes.count)
        let m = try! Multiaddr(data)
       
        XCTAssertEqual("/ip4/192.0.2.42", m.description)
    }
    
    func testCreateMultiaddrFromBytes_TcpAddress() {
        let bytes = [0x06, 0x10, 0xe1] as [UInt8]
        let data = Data(bytes: bytes, count: bytes.count)
        
        let m_fromString = try! Multiaddr("/tcp/4321")
        let m_fromData = try! Multiaddr(data)
        
        XCTAssertEqual(m_fromData.description, m_fromString.description)
        XCTAssertEqual(try! m_fromData.binaryPacked(), try! m_fromString.binaryPacked())
     }
    
    func testDnsSerialization() {
        let addr = try! Multiaddr("/dns6/foo.com")
        let serialized = try! addr.binaryPacked()
        
        let deserialized = try! Multiaddr(serialized)
        XCTAssertEqual(addr, deserialized)
    }
    
    func testCreateMultiaddrFromBytes_Onion() {
        
        let bytes = [0xBC, 0x03, 0x9a, 0x18, 0x08, 0x73, 0x06, 0x36, 0x90, 0x43, 0x09, 0x1f, 0x00, 0x50] as [UInt8]
        let data = Data(bytes: bytes, count: bytes.count)
        
        let m_fromString = try! Multiaddr("/onion/timaq4ygg2iegci7:80")
        let m_fromData = try! Multiaddr(data)
        
        XCTAssertEqual(m_fromData.description, m_fromString.description)
        XCTAssertEqual(try! m_fromData.binaryPacked(), try! m_fromString.binaryPacked())
    }
    
    /// IPFS Overload no longer exists (these should no longer be equal)
    /// - Note: https://github.com/multiformats/multicodec/pull/283
    func testCreateMultiaddrFromBytes_IpfsAddress() {
        let bytes = [0xa5, 0x03, 0x22, 0x12, 0x20, 0xd5, 0x2e, 0xbb, 0x89, 0xd8, 0x5b, 0x02, 0xa2, 0x84, 0x94, 0x82, 0x03, 0xa6, 0x2f, 0xf2, 0x83, 0x89, 0xc5, 0x7c, 0x9f, 0x42, 0xbe, 0xec, 0x4e, 0xc2, 0x0d, 0xb7, 0x6a, 0x68, 0x91, 0x1c, 0x0b] as [UInt8]
        let data = Data(bytes: bytes, count: bytes.count)
        
        let m_fromData = try! Multiaddr(data)
        let m_fromStringIPFS = try! Multiaddr("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        let m_fromStringP2P = try! Multiaddr("/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        
        /// The descriptions should not be same
        XCTAssertNotEqual(m_fromData.description, m_fromStringIPFS.description)
        XCTAssertEqual(m_fromData.description, m_fromStringP2P.description)
        
        /// The binary data should be the same across p2p and deprecated ipfs codecs
        XCTAssertEqual(try! m_fromData.binaryPacked(), try! m_fromStringP2P.binaryPacked())
        XCTAssertNotEqual(try! m_fromData.binaryPacked(), try! m_fromStringIPFS.binaryPacked())
    }
    
    func testCreateMultiaddrFromBytes_P2PAddressBase32() throws {
        let bytes = [0xa5, 0x03, 0x22, 0x12, 0x20, 0x73, 0xd7, 0x7b, 0x46, 0xc9, 0x4f, 0x21, 0x52, 0xc8, 0x07, 0x51, 0x16, 0xbf, 0x54, 0xd3, 0x17, 0x73, 0xd5, 0x73, 0x03, 0x0b, 0xba, 0x13, 0xe7, 0xdb, 0x7d, 0x39, 0xf1, 0x2e, 0x55, 0xb8, 0x7f] as [UInt8]
        let data = Data(bytes: bytes, count: bytes.count)
        
        let addrBase32 = try Multiaddr("/p2p/bafzbeidt255unskpefjmqb2rc27vjuyxopkxgaylxij6pw35hhys4vnyp4")
        let str = "/p2p/QmW8rAgaaA6sRydK1k6vonShQME47aDxaFidbtMevWs73t"
        let addrBase58 = try Multiaddr("/p2p/QmW8rAgaaA6sRydK1k6vonShQME47aDxaFidbtMevWs73t")
        
        // Description should equal the base58 string
        XCTAssertEqual(addrBase32.description, str)
        XCTAssertEqual(addrBase32, addrBase58)
        XCTAssertEqual(addrBase32, try Multiaddr(data))
        XCTAssertEqual(addrBase58, try Multiaddr(data))
        XCTAssertEqual(try addrBase32.binaryPacked(), try addrBase58.binaryPacked())
    }
    
    func testCreateMultiaddrFromString_WithoutAddressValue() throws {
        let m = try! Multiaddr("/dns6/foo.com/tcp/443/https")
        let expectedAddress1 = try Address(addrProtocol: .dns6, address: "foo.com")
        let expectedAddress2 = try Address(addrProtocol: .tcp, address: "443")
        let expectedAddress3 = try Address(addrProtocol: .https, address: nil)
        
        XCTAssertEqual(m.addresses[0], expectedAddress1)
        XCTAssertEqual(m.addresses[1], expectedAddress2)
        XCTAssertEqual(m.addresses[2], expectedAddress3)
    }
    
    func testCreateMultiaddrFromString_AddressValueHasMultipleSlashes() throws {
        let m = try! Multiaddr("/dns4/foo.com/tcp/80/http/bar/baz.jpg")
        let expectedAddress1 = try Address(addrProtocol: .dns4, address: "foo.com")
        let expectedAddress2 = try Address(addrProtocol: .tcp, address: "80")
        let expectedAddress3 = try Address(addrProtocol: .http, address: "bar/baz.jpg")
        
        XCTAssertEqual(m.addresses[0], expectedAddress1)
        XCTAssertEqual(m.addresses[1], expectedAddress2)
        XCTAssertEqual(m.addresses[2], expectedAddress3)
    }
    
    func testCreateMultiaddrFromString_AddressValueHasColons() throws {
        let m = try! Multiaddr("/ip6/::1/tcp/3217")
        let expectedAddress1 = try Address(addrProtocol: .ip6, address: "::1")
        let expectedAddress2 = try Address(addrProtocol: .tcp, address: "3217")
        
        XCTAssertEqual(m.addresses[0], expectedAddress1)
        XCTAssertEqual(m.addresses[1], expectedAddress2)
    }
    
    func testEncapsulated_BasedOnStringEquality() {
        let m1 = try! Multiaddr("/ip4/127.0.0.1")
        let m2 = try! Multiaddr("/udt")
    
        let encapsulated = m1.encapsulate(m2)
        XCTAssertEqual(String(describing: encapsulated), "/ip4/127.0.0.1/udt")
        
        let m3 = try! Multiaddr("/ip4/127.0.0.1")
        let encapsulated2 = try! m3.encapsulate("/udp/1234")
        XCTAssertEqual(String(describing: encapsulated2), "/ip4/127.0.0.1/udp/1234")
    }
    
    func testEncapsulated_BasedOnObjectEquality() {
        let m1 = try! Multiaddr("/ip4/127.0.0.1")
        let m2 = try! Multiaddr("/udt")
        
        let expected = try! Multiaddr("/ip4/127.0.0.1/udt")
        XCTAssertEqual(m1.encapsulate(m2), expected)
    }
    
    func testDecapsulate() {
        let full = try! Multiaddr("/ip4/1.2.3.4/tcp/80")
        let m1 = try! Multiaddr("/tcp/80")
        let m2 = try! Multiaddr("/ip4/1.2.3.4")
        
        XCTAssertEqual(full.decapsulate(m1), m2)
        
        let m3 = try! Multiaddr("/dns4/foo.com/tcp/80/http/bar/baz.jpg")
        let decapsulated = m3.decapsulate(m1)
        XCTAssertEqual(decapsulated, try Multiaddr("/dns4/foo.com"))
    }
    
    func testCreateMultiaddrFromString_FailsWithInvalidStrings() {
        let addresses = ["notAProtocol",
                   "/ip4/tcp/alsoNotAProtocol",
                   "////ip4/tcp/21432141///",
                   "////ip4///////tcp////"]
        
        for addr in addresses {
            XCTAssertThrowsError(try Multiaddr(addr)) { error in
                print("\(addr) was invalid")
            }
        }
    }

    func testBinaryPackedReturnsCorrectValue_For16BitProtocolPort() {
        let expected = "0601bb"
        let m = try! Multiaddr("/tcp/443")
        let actual = try! m.binaryPacked().hexString()
        XCTAssertEqual(actual, expected)
    }
    
    func testBinaryPackedReturnsCorrectValue_ForIPv4Address() {
        let expected = "04c000022a"
        let m = try! Multiaddr("/ip4/192.0.2.42")
        let actual = try! m.binaryPacked().hexString()
        XCTAssertEqual(actual, expected)
    }
    
    func testBinaryPackedThrowsError_ForInvalidIPv4Address() {
        XCTAssertThrowsError(try Multiaddr("/ip4/555.55.55.5").binaryPacked()) { error in
            XCTAssertEqual(error as! MultiaddrError, MultiaddrError.parseIPv4AddressFail)
        }
    }
    
    func testBinaryPacked_ForOnionAddress_EncodesCorrectly() {
        let expected = "bc039a18087306369043091f0050"
        let m = try! Multiaddr("/onion/timaq4ygg2iegci7:80")
        let actual = try! m.binaryPacked().hexString()
        XCTAssertEqual(actual, expected)
    }
    
    func testBinaryPacked_ForP2PAddress_EncodesCorrectly() {
        let expected = "a503221220d52ebb89d85b02a284948203a62ff28389c57c9f42beec4ec20db76a68911c0b"
        let m = try! Multiaddr("/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        let actual = try! m.binaryPacked().hexString()
        XCTAssertEqual(actual, expected)
    }
    
    func testIPv4FromBytes() throws {
        let addy = try Address(addrProtocol: .ip4, addressData: BaseEncoding.decode("c0a80001", as: .base16).data)
        XCTAssertEqual(addy.description, "/ip4/192.168.0.1")
    }

    func testIPv6FromBytes() throws {
        let addy = try Address(addrProtocol: .ip6, addressData: BaseEncoding.decode("abcd0000000100020003000400050006", as: .base16).data)
        XCTAssertEqual(addy.description, "/ip6/abcd:0:1:2:3:4:5:6")
    }

    func testIPv6FromString() throws {
        let addy = try Address(addrProtocol: .ip6, address: "ABCD::1:2:3:4:5:6")
        XCTAssertEqual(try IPv6.data(for: addy.address!).asString(base: .base16Upper), "ABCD0000000100020003000400050006")
    }

    func testIPv4FromString() throws {
        let addy = try Address(addrProtocol: .ip4, address: "192.168.0.1")
        XCTAssertEqual(try IPv4.data(for: addy.address!).asString(base: .base16), "c0a80001")
    }

    func testIPv4InvalidString() throws {
        XCTAssertThrowsError( try Multiaddr(.ip4, address: "555.168.0.1") )
        //XCTAssertThrowsError( Address(addrProtocol: .ip4, address: "555.168.0.1") ) // Direct Address Instantiation doesn't throw an error here...
    }

    func testIPv6InvalidString() throws {
        XCTAssertThrowsError( try Multiaddr(.ip6, address: "FFFF::GGGG") )
    }
    
    func testDecodeEmbeddedCerthashFromBytes() throws {
        let addy1Bytes = Data(hex: "046883835291020fa1cd03d103d203221220a78c594f830726e17fba30224d448d5c4a4434e9e5a14f24b3822d14da46d19bd203221220855beff35231e37b3c4970b3e16e0e100eba09adc3e1ad5473a16c97f258b61e")
        
        let ma = try Multiaddr(addy1Bytes)
        print(ma)
        
        let addy1Packed = try ma.binaryPacked()
        XCTAssertEqual(addy1Bytes, addy1Packed)
    }
    
    func testConstructCerthashMultiaddr() throws {
        let ma1 = try Multiaddr("/ip4/104.131.131.82/udp/4001/quic-v1/webtransport/certhash/f1220a78c594f830726e17fba30224d448d5c4a4434e9e5a14f24b3822d14da46d19b/certhash/f1220855beff35231e37b3c4970b3e16e0e100eba09adc3e1ad5473a16c97f258b61e")
        let expectedPackedAddress1 = Data(hex: "046883835291020fa1cd03d103d203221220a78c594f830726e17fba30224d448d5c4a4434e9e5a14f24b3822d14da46d19bd203221220855beff35231e37b3c4970b3e16e0e100eba09adc3e1ad5473a16c97f258b61e")
        XCTAssertEqual(try ma1.binaryPacked(), expectedPackedAddress1)
        let unpacked1 = try Multiaddr(expectedPackedAddress1)
        XCTAssertEqual(ma1, unpacked1)
        XCTAssertEqual(try ma1.binaryPacked(), try unpacked1.binaryPacked())
        
        let ma2 = try Multiaddr("/ip4/127.0.0.1/udp/1234/quic-v1/webtransport/certhash/b2uaraocy6yrdblb4sfptaddgimjmmpy")
        let expectedPackedAddress2 = Data(hex: "047f000001910204d2cd03d103d20313d501103858f62230ac3c915f300c664312c63f")
        XCTAssertEqual(try ma2.binaryPacked(), expectedPackedAddress2)
        let unpacked2 = try Multiaddr(expectedPackedAddress2)
        XCTAssertEqual(ma2, unpacked2)
        XCTAssertEqual(try ma2.binaryPacked(), try unpacked2.binaryPacked())
        
        let ma3 = try Multiaddr("/ip4/127.0.0.1/udp/1234/quic-v1/webtransport/certhash/b2uaraocy6yrdblb4sfptaddgimjmmpy/certhash/zQmbWTwYGcmdyK9CYfNBcfs9nhZs17a6FQ4Y8oea278xx41")
        let expectedPackedAddress3 = Data(hex: "047f000001910204d2cd03d103d20313d501103858f62230ac3c915f300c664312c63fd203221220c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2")
        XCTAssertEqual(try ma3.binaryPacked(), expectedPackedAddress3)
        let unpacked3 = try Multiaddr(expectedPackedAddress3)
        XCTAssertEqual(ma3, unpacked3)
        XCTAssertEqual(try ma3.binaryPacked(), try unpacked3.binaryPacked())
    }
    
    func testFailesWithInvalidCerthash() throws {
        XCTAssertThrowsError(try Multiaddr("/ip4/127.0.0.1/udp/1234/quic-v1/webtransport/certhash"))
        XCTAssertThrowsError(try Multiaddr("/ip4/127.0.0.1/udp/1234/quic-v1/webtransport/certhash/b2uaraocy6yrdblb4sfptaddgimjmmp"))
    }

    static var allTests = [
        ("testDump", testDump),
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testCreateMultiaddrFromString", testCreateMultiaddrFromString),
        ("testCreateMultiaddrFromString_LeadingSlashRequired", testCreateMultiaddrFromString_LeadingSlashRequired),
        ("testCreateMultiaddrFromString_WithoutAddressValue", testCreateMultiaddrFromString_WithoutAddressValue),
        ("testCreateMultiaddrFromString_AddressValueHasMultipleSlashes", testCreateMultiaddrFromString_AddressValueHasMultipleSlashes),
        ("testCreateMultiaddrFromString_AddressValueHasColons", testCreateMultiaddrFromString_AddressValueHasColons),
        ("testCreateMultiaddrFromString_FailsWithInvalidStrings", testCreateMultiaddrFromString_FailsWithInvalidStrings),
        ("testEncapsulated_BasedOnStringEquality", testEncapsulated_BasedOnStringEquality),
        ("testEncapsulated_BasedOnObjectEquality", testEncapsulated_BasedOnObjectEquality),
        ("testDecapsulate", testDecapsulate),
        ("testCreateMultiaddrFromString_FailsWithInvalidStrings", testCreateMultiaddrFromString_FailsWithInvalidStrings),
        ("testBinaryPackedReturnsCorrectValue_For16BitProtocolPort", testBinaryPackedReturnsCorrectValue_For16BitProtocolPort),
        ("testBinaryPackedReturnsCorrectValue_ForIPv4Address", testBinaryPackedReturnsCorrectValue_ForIPv4Address),
        ("testBinaryPackedThrowsError_ForInvalidIPv4Address", testBinaryPackedThrowsError_ForInvalidIPv4Address),
        ("testBinaryPacked_ForOnionAddress_EncodesCorrectly", testBinaryPacked_ForOnionAddress_EncodesCorrectly),
        ("testBinaryPacked_ForP2PAddress_EncodesCorrectly", testBinaryPacked_ForP2PAddress_EncodesCorrectly),
        ("testCreateMultiaddrFromBytes_IPv4", testCreateMultiaddrFromBytes_IPv4),
        ("testCreateMultiaddrFromBytes_TcpAddress", testCreateMultiaddrFromBytes_TcpAddress),
        ("testCreateMultiaddrFromBytes_Onion", testCreateMultiaddrFromBytes_Onion),
        ("testCreateMultiaddrFromBytes_IpfsAddress", testCreateMultiaddrFromBytes_IpfsAddress),
        ("testDnsSerialization", testDnsSerialization),
        ("testIPv4FromBytes", testIPv4FromBytes),
        ("testIPv6FromBytes", testIPv6FromBytes),
        ("testIPv4FromString", testIPv4FromString),
        ("testIPv6FromString", testIPv6FromString),
        ("testIPv4InvalidString", testIPv4InvalidString),
        ("testIPv6InvalidString", testIPv6InvalidString),
        ("testHashable", testHashable),
        ("testContainsEquatable", testContainsEquatable),
        ("testSwapMultiaddrFromString", testSwapMultiaddrFromString),
        ("testSwapMultiaddrFromStringMutating", testSwapMultiaddrFromStringMutating),
        ("testDecodeEmbeddedCerthashFromBytes", testDecodeEmbeddedCerthashFromBytes),
        ("testConstructCerthashMultiaddr", testConstructCerthashMultiaddr),
        ("testFailesWithInvalidCerthash", testFailesWithInvalidCerthash),
    ]
    
    /// Credit: https://oleb.net/blog/2017/03/keeping-xctest-in-sync/
    func testLinuxTestSuiteIncludesAllTests() {
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
        let thisClass = type(of: self)
        let linuxCount = thisClass.allTests.count
        #if swift(>=4.0)
        let darwinCount = thisClass
            .defaultTestSuite.testCaseCount
        #else
        let darwinCount = Int(thisClass
            .defaultTestSuite().testCaseCount)
        #endif
        XCTAssertEqual(linuxCount, darwinCount,
                       "\(darwinCount - linuxCount) tests are missing from allTests")
        #endif
    }
}
