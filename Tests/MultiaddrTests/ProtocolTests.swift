import XCTest
@testable import Multiaddr
import Multibase
import Multicodec

class ProtocolsTests: XCTestCase {

    func testVarIntEncoding() {
        let proto1 = MultiaddrProtocol.ip6
        let expectedPackedValueAsHex1 = "29"
        let varIntEncodedBytes1 = proto1.packedCode().hexString()
        XCTAssertEqual(varIntEncodedBytes1, expectedPackedValueAsHex1)

        let proto2 = MultiaddrProtocol.ip4
        let expectedPackedValueAsHex2 = "04"
        let varIntEncodedBytes2 = proto2.packedCode().hexString()
        XCTAssertEqual(varIntEncodedBytes2, expectedPackedValueAsHex2)
    }
    
//    it('create multiaddr', () => {
//        udpAddr = multiaddr('/ip4/127.0.0.1/udp/1234')
//        expect(udpAddr instanceof multiaddr).to.equal(true)
//      })
    func testCreateMultiaddr() throws {
        XCTAssertNoThrow(try Multiaddr("/ip4/127.0.0.1/udp/1234"))
    }
    
//    it('clone multiaddr', () => {
//        const udpAddrClone = multiaddr(udpAddr)
//        expect(udpAddrClone !== udpAddr).to.equal(true)
//      })
    func testClone() throws {
        var m1 = try Multiaddr("/ip4/127.0.0.1")
        var cloned = m1
        XCTAssertEqual(m1, cloned)
        
        let m2 = try Multiaddr("/udp/1234")
        cloned = cloned.encapsulate(m2)
        XCTAssertNotEqual(m1, cloned)
        
        m1 = m1.encapsulate(m2)
        let expected = try Multiaddr("/ip4/127.0.0.1/udp/1234")
        XCTAssertEqual(m1, expected)
        XCTAssertEqual(cloned, expected)
    }

//      it('reconstruct with buffer', () => {
//        expect(multiaddr(udpAddr.bytes).bytes === udpAddr.bytes).to.equal(false)
//        expect(multiaddr(udpAddr.bytes).bytes).to.deep.equal(udpAddr.bytes)
//      })
    func testCreateFromBuffer() throws {
        let udpAddr = try Multiaddr("/ip4/127.0.0.1/udp/1234")
        let fromBytes = try Multiaddr(udpAddr.binaryPacked())
        XCTAssertEqual(udpAddr, fromBytes)
    }
    
    func testCreateFromString() throws {
        let udpAddr = try Multiaddr("/ip4/127.0.0.1/udp/1234")
        let fromString = try Multiaddr(udpAddr.description)
        XCTAssertEqual(udpAddr, fromString)
    }
    
    /// - TODO: Support empty Multiaddr initialization
//    func testCreateFromEmptyString() throws {
//        let emptyAddr = try? Multiaddr("/")
//        XCTAssertNotNil(emptyAddr)
//        dump(emptyAddr)
//    }
    
    func testCreateBasic() throws {
//        const udpAddrStr = '/ip4/127.0.0.1/udp/1234'
//        const udpAddrBuf = uint8ArrayFromString('047f000001910204d2', 'base16')
//        const udpAddr = multiaddr(udpAddrStr)
//
//        expect(udpAddr.toString()).to.equal(udpAddrStr)
//        expect(udpAddr.bytes).to.deep.equal(udpAddrBuf)
//
//        expect(udpAddr.protoCodes()).to.deep.equal([4, 273])
//        expect(udpAddr.protoNames()).to.deep.equal(['ip4', 'udp'])
//        expect(udpAddr.protos()).to.deep.equal([multiaddr.protocols.codes[4], multiaddr.protocols.codes[273]])
//        expect(udpAddr.protos()[0] === multiaddr.protocols.codes[4]).to.equal(false)
//
//        const udpAddrbytes2 = udpAddr.encapsulate('/udp/5678')
//        expect(udpAddrbytes2.toString()).to.equal('/ip4/127.0.0.1/udp/1234/udp/5678')
//        expect(udpAddrbytes2.decapsulate('/udp').toString()).to.equal('/ip4/127.0.0.1/udp/1234')
//        expect(udpAddrbytes2.decapsulate('/ip4').toString()).to.equal('/')
//        expect(function () { udpAddr.decapsulate('/').toString() }).to.throw()
//        expect(multiaddr('/').encapsulate(udpAddr).toString()).to.equal(udpAddr.toString())
//        expect(multiaddr('/').decapsulate('/').toString()).to.equal('/')
        let udpAddrStr = "/ip4/127.0.0.1/udp/1234"
        let udpAddrBuf = try BaseEncoding.decode("047f000001910204d2", as: .base16).data
        
        let udpAddr = try Multiaddr(udpAddrStr)
        XCTAssertNotNil(udpAddr)
        
        /// Expect the string description to equal our udp addr string
        XCTAssertEqual(udpAddr.description, udpAddrStr)
        
        /// Expect the data representation to equal the hex data above
        XCTAssertEqual(try udpAddr.binaryPacked(), udpAddrBuf)
        
        /// Protocols
        XCTAssertEqual(udpAddr.protocols(),  [ .ip4,  .udp])
        XCTAssertEqual(udpAddr.protoNames(), ["ip4", "udp"])
        XCTAssertEqual(udpAddr.protoCodes(), [    4,   273])
        
        /// Decapsulation via new Multiaddress
        let udpAddrBytes2 = try udpAddr.encapsulate("/udp/5678")
        XCTAssertEqual(udpAddrBytes2.description, "/ip4/127.0.0.1/udp/1234/udp/5678")
        XCTAssertEqual(udpAddrBytes2.decapsulate(try Multiaddr("/udp/5678")).description, "/ip4/127.0.0.1/udp/1234") // TODO: Should Support just "/udp"
        XCTAssertEqual(udpAddrBytes2.decapsulate(try Multiaddr("/ip4/127.0.0.1")).description, "/") //TODO: Should Support just "/ip4"
        
        /// Decapsulation via String Protocol
        let udpAddrBytes3 = try udpAddr.encapsulate("/udp/5678")
        XCTAssertEqual(udpAddrBytes3.description, "/ip4/127.0.0.1/udp/1234/udp/5678")
        XCTAssertEqual(udpAddrBytes3.decapsulate("/udp").description, "/ip4/127.0.0.1/udp/1234")
        XCTAssertEqual(udpAddrBytes3.decapsulate("/udp").decapsulate("/udp").description, "/ip4/127.0.0.1") //Decapsulate isn't mutating so it must be called twice...
        XCTAssertEqual(udpAddrBytes3.decapsulate("/ip4").description, "/")
        
        /// Decapsulation via MultiaddrProtocol (akak Codec)
        let udpAddrBytes4 = try udpAddr.encapsulate(proto: .udp, address: "5678")
        XCTAssertEqual(udpAddrBytes4.description, "/ip4/127.0.0.1/udp/1234/udp/5678")
        XCTAssertEqual(udpAddrBytes4.decapsulate(.udp).description, "/ip4/127.0.0.1/udp/1234")
        XCTAssertEqual(udpAddrBytes4.decapsulate(.udp).decapsulate(.udp).description, "/ip4/127.0.0.1") //Decapsulate isn't mutating so it must be called twice...
        XCTAssertEqual(udpAddrBytes4.decapsulate(.ip4).description, "/")
        
        /// - TODO: Support Instantiating with a single "/"
        //XCTAssertEqual(try Multiaddr("/").encapsulate(udpAddr).description, udpAddrStr)
    }
    
    func testIPFSAddress() throws {
        let ipfsAddr = try Multiaddr("/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        let ip6Addr  = try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
        let tcpAddr  = try Multiaddr("/tcp/8000")
        let wsAddr   = try Multiaddr("/ws")
        
        XCTAssertEqual(
            ip6Addr.encapsulate(tcpAddr)
                .encapsulate(wsAddr)
                .encapsulate(ipfsAddr).description,
            [ip6Addr, tcpAddr, wsAddr, ipfsAddr].map { "\($0)" }.joined())
        
        XCTAssertEqual(
            ip6Addr.encapsulate(tcpAddr)
                .encapsulate(wsAddr)
                .encapsulate(ipfsAddr)
                //.decapsulate("/ipfs").description,
                .decapsulate(.ipfs).description,
            [ip6Addr, tcpAddr, wsAddr].map { "\($0)" }.joined())
        
        XCTAssertEqual(
            ip6Addr.encapsulate(tcpAddr)
                .encapsulate(ipfsAddr)
                .encapsulate(wsAddr)
                .decapsulate(.ws).description,
            [ip6Addr, tcpAddr, ipfsAddr].map { "\($0)" }.joined())
    }
    
    func testIP4() throws {
        let str = "/ip4/127.0.0.1"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1"))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2"))
    }
    
    func testIP6() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096"))
    }
    
    func testIP4_TCP() throws {
        let str = "/ip4/127.0.0.1/tcp/5000"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/tcp/5000"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "5000"))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2").encapsulate(proto: .tcp, address: "5000"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "5001"))
    }
    
    func testIP6_TCP() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/5000"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/5000"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095").encapsulate(proto: .tcp, address: "5000"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096").encapsulate(proto: .tcp, address: "5000"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095").encapsulate(proto: .tcp, address: "5001"))
    }
    
    func testIP4_UDP() throws {
        let str = "/ip4/127.0.0.1/udp/5000"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/udp/5000"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .udp, address: "5000"))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2").encapsulate(proto: .udp, address: "5000"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .udp, address: "5001"))
    }

    func testIP6_UDP() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/5000"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/5000"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095").encapsulate(proto: .udp, address: "5000"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096").encapsulate(proto: .udp, address: "5000"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095").encapsulate(proto: .udp, address: "5001"))
    }

    func testIP4_P2P_TCP() throws {
        let str = "/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1")
                        .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                        .encapsulate(proto: .tcp, address: "1234"))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                            .encapsulate(proto: .tcp, address: "1234"))
        // Different PeerID
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKD")
                            .encapsulate(proto: .tcp, address: "1234"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                            .encapsulate(proto: .tcp, address: "1235"))
    }
    
    /// We need support for ipfs in order to support pre p2p protocols
    func testIP4_IPFS_TCP() throws {
        let str = "/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1")
                        .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                        .encapsulate(proto: .tcp, address: "1234"))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2")
                            .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                            .encapsulate(proto: .tcp, address: "1234"))
        // Different PeerID
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1")
                            .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKD")
                            .encapsulate(proto: .tcp, address: "1234"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1")
                            .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                            .encapsulate(proto: .tcp, address: "1235"))
    }

    func testIP6_P2P_TCP() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/tcp/1234"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                        .encapsulate(proto: .tcp, address: "1234"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                            .encapsulate(proto: .tcp, address: "1234"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
                            .encapsulate(proto: .tcp, address: "1235"))
        // Different PeerID
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKD")
                            .encapsulate(proto: .tcp, address: "1234"))
    }
    
    func testIP4_UDP_UTP() throws {
        let str = "/ip4/127.0.0.1/udp/5000/utp"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/udp/5000/utp"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .udp, address: "5000").encapsulate(proto: .utp, address: nil))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2").encapsulate(proto: .udp, address: "5000").encapsulate(proto: .utp, address: nil))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .udp, address: "5001").encapsulate(proto: .utp, address: nil))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.utp).description, "/ip4/127.0.0.1/udp/5000")
        //Decapsulating udp drops both udp and utp protos
        XCTAssertEqual(addr.decapsulate(.udp).description, "/ip4/127.0.0.1")
    }

    func testIP6_UDP_UTP() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/5000/utp"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/5000/utp"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095").encapsulate(proto: .udp, address: "5000").encapsulate(proto: .utp, address: ""))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096").encapsulate(proto: .udp, address: "5000").encapsulate(proto: .utp, address: ""))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095").encapsulate(proto: .udp, address: "5001").encapsulate(proto: .utp, address: ""))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.utp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/5000")
        //Decapsulating udp drops both udp and utp protos
        XCTAssertEqual(addr.decapsulate(.udp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }
    
    func testIP4_TCP_HTTP() throws {
        let str = "/ip4/127.0.0.1/tcp/8000/http"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/tcp/8000/http"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "8000").encapsulate(proto: .http, address: ""))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2").encapsulate(proto: .tcp, address: "8000").encapsulate(proto: .http, address: ""))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "8001").encapsulate(proto: .http, address: ""))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.http).description, "/ip4/127.0.0.1/tcp/8000")
        //Decapsulating udp drops both udp and http protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip4/127.0.0.1")
    }

    func testIP4_TCP_UNIX() throws {
        let str = "/ip4/127.0.0.1/tcp/80/unix/a/b/c/d/e/f"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/tcp/80/unix/a/b/c/d/e/f"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "80").encapsulate(proto: .unix, address: "a/b/c/d/e/f"))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2").encapsulate(proto: .tcp, address: "80").encapsulate(proto: .unix, address: "a/b/c/d/e/f"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "81").encapsulate(proto: .unix, address: "a/b/c/d/e/f"))
        // Different Unix Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "80").encapsulate(proto: .unix, address: "a/b/c/d/e/g"))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.unix).description, "/ip4/127.0.0.1/tcp/80")
        //Decapsulating udp drops both udp and http protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip4/127.0.0.1")
    }

    func testIP6_TCP_HTTP() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/http"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/http"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .tcp, address: "8000")
                        .encapsulate(proto: .http, address: ""))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .tcp, address: "8000")
                            .encapsulate(proto: .http, address: ""))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .tcp, address: "8001")
                            .encapsulate(proto: .http, address: ""))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.http).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000")
        //Decapsulating udp drops both udp and utp protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }

    func testIP6_TCP_UNIX() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/unix/a/b/c/d/e/f"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/unix/a/b/c/d/e/f"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .tcp, address: "8000")
                        .encapsulate(proto: .unix, address: "a/b/c/d/e/f"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .tcp, address: "8000")
                            .encapsulate(proto: .unix, address: "a/b/c/d/e/f"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .tcp, address: "8001")
                            .encapsulate(proto: .unix, address: "a/b/c/d/e/f"))
        // Different Unix Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .tcp, address: "8000")
                            .encapsulate(proto: .unix, address: "a/b/c/d/e/g"))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.unix).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000")
        //Decapsulating udp drops both udp and utp protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }
    
//      it('ip4 + tcp + https', () => {
//        const str = '/ip4/127.0.0.1/tcp/8000/https'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testIP4_TCP_HTTPS() throws {
        let str = "/ip4/127.0.0.1/tcp/8000/https"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/tcp/8000/https"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "8000").encapsulate(proto: .https, address: nil))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2").encapsulate(proto: .tcp, address: "8000").encapsulate(proto: .https, address: nil))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "8001").encapsulate(proto: .https, address: nil))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.https).description, "/ip4/127.0.0.1/tcp/8000")
        //Decapsulating udp drops both udp and http protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip4/127.0.0.1")
    }
    
//      it('ip6 + tcp + https', () => {
//        const str = '/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/https'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testIP6_TCP_HTTPS() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/https"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/https"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .tcp, address: "8000")
                        .encapsulate(proto: .https, address: ""))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .tcp, address: "8000")
                            .encapsulate(proto: .https, address: ""))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .tcp, address: "8001")
                            .encapsulate(proto: .https, address: ""))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.https).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000")
        //Decapsulating udp drops both udp and utp protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }
    
//      it('ip4 + tcp + websockets', () => {
//        const str = '/ip4/127.0.0.1/tcp/8000/ws'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testIP4_TCP_WS() throws {
        let str = "/ip4/127.0.0.1/tcp/8000/ws"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip4/127.0.0.1/tcp/8000/ws"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "8000").encapsulate(proto: .ws, address: ""))
        // Different IP4 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.2").encapsulate(proto: .tcp, address: "8000").encapsulate(proto: .ws, address: ""))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip4, address: "127.0.0.1").encapsulate(proto: .tcp, address: "8001").encapsulate(proto: .ws, address: ""))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.ws).description, "/ip4/127.0.0.1/tcp/8000")
        //Decapsulating udp drops both udp and http protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip4/127.0.0.1")
    }
    
//      it('ip6 + tcp + websockets', () => {
//        const str = '/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testIP6_TCP_WS() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .tcp, address: "8000")
                        .encapsulate(proto: .ws, address: ""))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .tcp, address: "8000")
                            .encapsulate(proto: .ws, address: ""))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .tcp, address: "8001")
                            .encapsulate(proto: .ws, address: ""))
        //Decapsulating utp
        XCTAssertEqual(addr.decapsulate(.ws).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000")
        //Decapsulating udp drops both udp and utp protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }
    
//      it('ip6 + tcp + websockets + ipfs', () => {
//        const str = '/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str.replace('/ipfs/', '/p2p/'))
//      })
    func testIP6_TCP_WS_IPFS() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .tcp, address: "8000")
                        .encapsulate(proto: .ws, address: "")
                        .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .tcp, address: "8000")
                            .encapsulate(proto: .ws, address: "")
                            .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .tcp, address: "8001")
                            .encapsulate(proto: .ws, address: "")
                            .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        //Decapsulating ws
        XCTAssertEqual(addr.decapsulate(.ws).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000")
        //Decapsulating tcp drops both tcp, ws and ipfs protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }
    
//      it('ip6 + tcp + websockets + p2p', () => {
//        const str = '/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testIP6_TCP_WS_P2P() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000/ws/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .tcp, address: "8000")
                        .encapsulate(proto: .ws, address: "")
                        .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .tcp, address: "8000")
                            .encapsulate(proto: .ws, address: "")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .tcp, address: "8001")
                            .encapsulate(proto: .ws, address: "")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        //Decapsulating ws
        XCTAssertEqual(addr.decapsulate(.ws).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/tcp/8000")
        //Decapsulating tcp drops both tcp, ws and ipfs protos
        XCTAssertEqual(addr.decapsulate(.tcp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }
    
//      it('ip6 + udp + quic + ipfs', () => {
//        const str = '/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/4001/quic/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str.replace('/ipfs/', '/p2p/'))
//      })
    func testIP6_UDP_QUIC_IPFS() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/4001/quic/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/4001/quic/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .udp, address: "4001")
                        .encapsulate(proto: .quic, address: "")
                        .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .udp, address: "4001")
                            .encapsulate(proto: .quic, address: "")
                            .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .udp, address: "4000")
                            .encapsulate(proto: .quic, address: "")
                            .encapsulate(proto: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        //Decapsulating quic
        XCTAssertEqual(addr.decapsulate(.quic).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/4001")
        //Decapsulating udp drops both udp, quic and ipfs protos
        XCTAssertEqual(addr.decapsulate(.udp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }
    
//      it('ip6 + udp + quic + p2p', () => {
//        const str = '/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/4001/quic/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
//
    func testIP6_UDP_QUIC_P2P() throws {
        let str = "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/4001/quic/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        // Two Multiaddresses initialized with the same string should be equal
        XCTAssertEqual(addr, try Multiaddr("/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/4001/quic/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Built via encapsulation
        XCTAssertEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                        .encapsulate(proto: .udp, address: "4001")
                        .encapsulate(proto: .quic, address: "")
                        .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Different IP6 Address
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7096")
                            .encapsulate(proto: .udp, address: "4001")
                            .encapsulate(proto: .quic, address: "")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        // Different Port
        XCTAssertNotEqual(addr, try Multiaddr(.ip6, address: "2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
                            .encapsulate(proto: .udp, address: "4000")
                            .encapsulate(proto: .quic, address: "")
                            .encapsulate(proto: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"))
        //Decapsulating quic
        XCTAssertEqual(addr.decapsulate(.quic).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095/udp/4001")
        //Decapsulating udp drops both udp, quic and p2p protos
        XCTAssertEqual(addr.decapsulate(.udp).description, "/ip6/2001:8a0:7ac5:4201:3ac9:86ff:fe31:7095")
    }
    
//      it('unix', () => {
//        const str = '/unix/a/b/c/d/e'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testUNIX() throws {
        let str = "/unix/a/b/c/d/e"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
    }
    
//      it('p2p', () => {
//        const str = '/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testP2P_Multihash_Initialization() throws {
        let str = "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [try Address(addrProtocol: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")])
    }
    
//      it('p2p', () => {
//        const str = '/p2p/bafzbeidt255unskpefjmqb2rc27vjuyxopkxgaylxij6pw35hhys4vnyp4'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal('/p2p/QmW8rAgaaA6sRydK1k6vonShQME47aDxaFidbtMevWs73t')
//      })
    /// - TODO: Support B32 P2P/IPFS Instantiation
    func testP2P_CID_Initialization() throws {
        let str = "/p2p/bafzbeidt255unskpefjmqb2rc27vjuyxopkxgaylxij6pw35hhys4vnyp4"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, "/p2p/bafzbeidt255unskpefjmqb2rc27vjuyxopkxgaylxij6pw35hhys4vnyp4")
        XCTAssertEqual(addr.addresses, [try Address(addrProtocol: .p2p, address: "QmW8rAgaaA6sRydK1k6vonShQME47aDxaFidbtMevWs73t")])
    }
    
//      it('ipfs', () => {
//        const str = '/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str.replace('/ipfs/', '/p2p/'))
//      })
    /// IPFS Overload no longer exists (these should no longer be equal)
    /// - Note: https://github.com/multiformats/multicodec/pull/283
    func testIPFS() throws {
        let str = "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [try Address(addrProtocol: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")])
        XCTAssertEqual(addr.addresses, [try Address(addrProtocol: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")])
    }
    
//      it('onion', () => {
//        const str = '/onion/timaq4ygg2iegci7:1234'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testOnion() throws {
        let str = "/onion/timaq4ygg2iegci7:1234"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [try Address(addrProtocol: .onion, address: "timaq4ygg2iegci7:1234")])
    }
    
//      it('onion bad length', () => {
//        const str = '/onion/timaq4ygg2iegci:80'
//        expect(() => multiaddr(str)).to.throw()
//      })
    func testOnion_BadLength() throws {
        let str = "/onion/timaq4ygg2iegci:80"
        // Throws with bad Onion Length Error
        XCTAssertThrowsError( try Multiaddr(str) )
    }
    
//      it('onion bad port', () => {
//        const str = '/onion/timaq4ygg2iegci7:-1'
//        expect(() => multiaddr(str)).to.throw()
//      })
    func testOnion_BadPort() throws {
        let str = "/onion/timaq4ygg2iegci7:-1"
        // Throws with bad Onion Port Error
        XCTAssertThrowsError( try Multiaddr(str) )
    }
    
//      it('onion no port', () => {
//        const str = '/onion/timaq4ygg2iegci7'
//        expect(() => multiaddr(str)).to.throw()
//      })
    func testOnion_NoPort() throws {
        let str = "/onion/timaq4ygg2iegci7"
        // Throws with bad Onion Port Error
        XCTAssertThrowsError( try Multiaddr(str) )
    }
    
//      it('onion3', () => {
//        const str = '/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    /// - TODO: Support Onion3 Address Instantiation
    func testOnion3() throws {
        let str = "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [try Address(addrProtocol: .onion3, address: "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234")])
    }
    
//      it('onion3 bad length', () => {
//        const str = '/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopyyd:1234'
//        expect(() => multiaddr(str)).to.throw()
//      })
    func testOnion3_BadLength() throws {
        let str = "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopyyd:1234"
        XCTAssertThrowsError( try Multiaddr(str) )
    }
    
//      it('onion3 bad port', () => {
//        const str = '/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:-1'
//        expect(() => multiaddr(str)).to.throw()
//      })
    func testOnion3_BadPort() throws {
        let str = "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopyyd:-1"
        XCTAssertThrowsError( try Multiaddr(str) )
    }
    
//      it('onion3 no port', () => {
//        const str = '/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd'
//        expect(() => multiaddr(str)).to.throw()
//      })
    func testOnion3_NoPort() throws {
        let str = "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopyyd"
        XCTAssertThrowsError( try Multiaddr(str) )
    }
    
//      it('p2p-circuit', () => {
//        const str = '/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    /// - TODO: Support P2P_Curcuit Protocol
    func testP2PCircuit() throws {
        let str = "/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [
            try Address(addrProtocol: .p2p_circuit, address: nil),
            try Address(addrProtocol: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        ])
    }
    
//      it('p2p-circuit p2p', () => {
//        const str = '/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testP2P_P2PCircuit() throws {
        let str = "/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [
            try Address(addrProtocol: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"),
            try Address(addrProtocol: .p2p_circuit, address: "")
        ])
    }
    
//      it('p2p-circuit ipfs', () => {
//        const str = '/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str.replace('/ipfs/', '/p2p/'))
//      })
    func testIPFS_P2PCircuit() throws {
        let str = "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC/p2p-circuit"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [
            try Address(addrProtocol: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"),
            try Address(addrProtocol: .p2p_circuit, address: "")
        ])
    }
    
//      it('p2p-webrtc-star', () => {
//        const str = '/ip4/127.0.0.1/tcp/9090/ws/p2p-webrtc-star/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testIP4_TCP_WEBRTCSTAR_P2P() throws {
        let str = "/ip4/127.0.0.1/tcp/9090/ws/p2p-webrtc-star/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [
            try Address(addrProtocol: .ip4, address: "127.0.0.1"),
            try Address(addrProtocol: .tcp, address: "9090"),
            try Address(addrProtocol: .ws, address: ""),
            try Address(addrProtocol: .p2p_webrtc_star, address: ""),
            try Address(addrProtocol: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        ])
    }
    
//      it('p2p-webrtc-star ipfs', () => {
//        const str = '/ip4/127.0.0.1/tcp/9090/ws/p2p-webrtc-star/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str.replace('/ipfs/', '/p2p/'))
//      })
    func testIP4_TCP_WEBRTCSTAR_IPFS() throws {
        let str = "/ip4/127.0.0.1/tcp/9090/ws/p2p-webrtc-star/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [
            try Address(addrProtocol: .ip4, address: "127.0.0.1"),
            try Address(addrProtocol: .tcp, address: "9090"),
            try Address(addrProtocol: .ws, address: ""),
            try Address(addrProtocol: .p2p_webrtc_star, address: ""),
            try Address(addrProtocol: .ipfs, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        ])
    }
    
    func testIP4_TCP_WEBRTCSTAR_IPFS_CID() throws {
        let str = "/ip4/127.0.0.1/tcp/9090/ws/p2p-webrtc-star/ipfs/bafzbeidt255unskpefjmqb2rc27vjuyxopkxgaylxij6pw35hhys4vnyp4"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, "/ip4/127.0.0.1/tcp/9090/ws/p2p-webrtc-star/ipfs/bafzbeidt255unskpefjmqb2rc27vjuyxopkxgaylxij6pw35hhys4vnyp4")
        XCTAssertEqual(addr.addresses, [
            try Address(addrProtocol: .ip4, address: "127.0.0.1"),
            try Address(addrProtocol: .tcp, address: "9090"),
            try Address(addrProtocol: .ws, address: ""),
            try Address(addrProtocol: .p2p_webrtc_star, address: ""),
            try Address(addrProtocol: .ipfs, address: "QmW8rAgaaA6sRydK1k6vonShQME47aDxaFidbtMevWs73t")
        ])
    }
//      it('p2p-webrtc-direct', () => {
//        const str = '/ip4/127.0.0.1/tcp/9090/http/p2p-webrtc-direct'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testIP4_TCP_HTTP_WEBRTCDIRECT() throws {
        let str = "/ip4/127.0.0.1/tcp/9090/http/p2p-webrtc-direct"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [
            try Address(addrProtocol: .ip4, address: "127.0.0.1"),
            try Address(addrProtocol: .tcp, address: "9090"),
            try Address(addrProtocol: .http, address: ""),
            try Address(addrProtocol: .p2p_webrtc_direct, address: "")
        ])
    }
    
//      it('p2p-websocket-star', () => {
//        const str = '/ip4/127.0.0.1/tcp/9090/ws/p2p-websocket-star'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
    func testIP4_TCP_WS_WEBSOCKETSTAR() throws {
        let str = "/ip4/127.0.0.1/tcp/9090/ws/p2p-websocket-star"
        let addr = try Multiaddr(str)
        // Description should equal initialization string
        XCTAssertEqual(addr.description, str)
        XCTAssertEqual(addr.addresses, [
            try Address(addrProtocol: .ip4, address: "127.0.0.1"),
            try Address(addrProtocol: .tcp, address: "9090"),
            try Address(addrProtocol: .ws, address: ""),
            try Address(addrProtocol: .p2p_websocket_star, address: "")
        ])
    }
    
//      it('memory + p2p', () => {
//        const str = '/memory/test/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC'
//        const addr = multiaddr(str)
//        expect(addr).to.have.property('bytes')
//        expect(addr.toString()).to.equal(str)
//      })
//    func testMEMORY_TEST_P2P() throws {
//        let str = "/memory/test/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC"
//        let addr = try Multiaddr(str)
//        // Description should equal initialization string
//        XCTAssertEqual(addr.description, str)
//        XCTAssertEqual(addr.addresses, [
//            Address(addrProtocol: .memory, address: ""),
//            Address(addrProtocol: .test, address: ""),
//            Address(addrProtocol: .p2p, address: "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
//        ])
//    }
    
    /// - MARK: PeerID Extraction Tests
    
    func testGetPeerID_P2P() throws {
        let ma = try Multiaddr("/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        XCTAssertEqual(ma.getPeerID(), "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
    }

    func testGetPeerID_P2PCircuit() throws {
        let ma = try Multiaddr("/ip4/0.0.0.0/tcp/8080/p2p/QmZR5a9AAXGqQF2ADqoDdGS8zvqv8n3Pag6TDDnTNMcFW6/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        XCTAssertEqual(ma.getPeerID(), "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
    }

    func testGetPeerID_IPFS() throws {
        let ma = try Multiaddr("/p2p-circuit/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        XCTAssertEqual(ma.getPeerID(), "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
    }

    func testGetPeerID_P2P_CIDv1_BASE32() throws {
        let ma = try Multiaddr("/p2p-circuit/p2p/bafzbeigweq4zr4x4ky2dvv7nanbkw6egutvrrvzw6g3h2rftp7gidyhtt4")
        XCTAssertEqual(ma.getPeerID(), "bafzbeigweq4zr4x4ky2dvv7nanbkw6egutvrrvzw6g3h2rftp7gidyhtt4")
    }

    func testGetPeerID_P2P_CIDv1_BASE32_Nonb58_chars() throws {
        let ma = try Multiaddr("/p2p-circuit/p2p/bafzbeidt255unskpefjmqb2rc27vjuyxopkxgaylxij6pw35hhys4vnyp4")
        XCTAssertEqual(ma.getPeerID(), "bafzbeidt255unskpefjmqb2rc27vjuyxopkxgaylxij6pw35hhys4vnyp4")
    }

    func testGetPeerID_From_Address_Without_A_PeerID() throws {
        let ma = try Multiaddr("/ip4/0.0.0.0/tcp/1234/utp")
        XCTAssertNil(ma.getPeerID())
    }
    
    /// - MARK: Path Extraction Tests
//    it('should return a path for unix', () => {
//      expect(
//        multiaddr('/unix/tmp/p2p.sock').getPath()
//      ).to.eql('/tmp/p2p.sock')
//    })
    func testGetPathForUnix() throws {
        let ma = try Multiaddr("/unix/tmp/p2p.sock")
        XCTAssertEqual(ma.getPath(), "/tmp/p2p.sock")
    }
//
//    it('should return a path for unix when other protos exist', () => {
//      expect(
//        multiaddr('/ip4/0.0.0.0/tcp/1234/unix/tmp/p2p.sock').getPath()
//      ).to.eql('/tmp/p2p.sock')
//    })
    func testGetPathForUnix_Multiple_Protos() throws {
        let ma = try Multiaddr("/ip4/0.0.0.0/tcp/1234/unix/tmp/p2p.sock")
        XCTAssertEqual(ma.getPath(), "/tmp/p2p.sock")
    }
//
//    it('should not return a path when no path proto exists', () => {
//      expect(
//        multiaddr('/ip4/0.0.0.0/tcp/1234/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC').getPath()
//      ).to.eql(null)
//    })
    func testGetPathForUnix_No_Path() throws {
        let ma = try Multiaddr("/ip4/0.0.0.0/tcp/1234/p2p-circuit/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC")
        XCTAssertNil(ma.getPath())
    }
    
    static var allTests = [
        ("testVarIntEncoding", testVarIntEncoding),
        ("testCreateMultiaddr", testCreateMultiaddr),
        ("testClone", testClone),
        ("testCreateFromBuffer", testCreateFromBuffer),
        ("testCreateFromString", testCreateFromString),
        ("testCreateBasic", testCreateBasic),
        ("testIPFSAddress", testIPFSAddress),
        ("testIP4", testIP4),
        ("testIP6", testIP6),
        ("testIP4_TCP", testIP4_TCP),
        ("testIP6_TCP", testIP6_TCP),
        ("testIP4_UDP", testIP4_UDP),
        ("testIP6_UDP", testIP6_UDP),
        ("testIP4_P2P_TCP", testIP4_P2P_TCP),
        ("testIP4_IPFS_TCP", testIP4_IPFS_TCP),
        ("testIP6_P2P_TCP", testIP6_P2P_TCP),
        ("testIP4_UDP_UTP", testIP4_UDP_UTP),
        ("testIP6_UDP_UTP", testIP6_UDP_UTP),
        ("testIP4_TCP_HTTP", testIP4_TCP_HTTP),
        ("testIP4_TCP_UNIX", testIP4_TCP_UNIX),
        ("testIP6_TCP_HTTP", testIP6_TCP_HTTP),
        ("testIP6_TCP_UNIX", testIP6_TCP_UNIX),
        ("testIP4_TCP_HTTPS", testIP4_TCP_HTTPS),
        ("testIP6_TCP_HTTPS", testIP6_TCP_HTTPS),
        ("testIP4_TCP_WS", testIP4_TCP_WS),
        ("testIP6_TCP_WS", testIP6_TCP_WS),
        ("testIP6_TCP_WS_IPFS", testIP6_TCP_WS_IPFS),
        ("testIP6_TCP_WS_P2P", testIP6_TCP_WS_P2P),
        ("testIP6_UDP_QUIC_IPFS", testIP6_UDP_QUIC_IPFS),
        ("testIP6_UDP_QUIC_P2P", testIP6_UDP_QUIC_P2P),
        ("testUNIX", testUNIX),
        ("testP2P_Multihash_Initialization", testP2P_Multihash_Initialization),
        ("testP2P_CID_Initialization", testP2P_CID_Initialization),
        ("testIPFS", testIPFS),
        ("testOnion", testOnion),
        ("testOnion_BadLength", testOnion_BadLength),
        ("testOnion_BadPort", testOnion_BadPort),
        ("testOnion_NoPort", testOnion_NoPort),
        ("testOnion3", testOnion3),
        ("testOnion3_BadLength", testOnion3_BadLength),
        ("testOnion3_BadPort", testOnion3_BadPort),
        ("testOnion3_NoPort", testOnion3_NoPort),
        ("testP2PCircuit", testP2PCircuit),
        ("testP2P_P2PCircuit", testP2P_P2PCircuit),
        ("testIPFS_P2PCircuit", testIPFS_P2PCircuit),
        ("testIP4_TCP_WEBRTCSTAR_P2P", testIP4_TCP_WEBRTCSTAR_P2P),
        ("testIP4_TCP_WEBRTCSTAR_IPFS", testIP4_TCP_WEBRTCSTAR_IPFS),
        ("testIP4_TCP_WEBRTCSTAR_IPFS_CID", testIP4_TCP_WEBRTCSTAR_IPFS_CID),
        ("testIP4_TCP_HTTP_WEBRTCDIRECT", testIP4_TCP_HTTP_WEBRTCDIRECT),
        ("testIP4_TCP_WS_WEBSOCKETSTAR", testIP4_TCP_WS_WEBSOCKETSTAR),
        ("testGetPeerID_P2P", testGetPeerID_P2P),
        ("testGetPeerID_P2PCircuit", testGetPeerID_P2PCircuit),
        ("testGetPeerID_IPFS", testGetPeerID_IPFS),
        ("testGetPeerID_P2P_CIDv1_BASE32", testGetPeerID_P2P_CIDv1_BASE32),
        ("testGetPeerID_P2P_CIDv1_BASE32_Nonb58_chars", testGetPeerID_P2P_CIDv1_BASE32_Nonb58_chars),
        ("testGetPeerID_From_Address_Without_A_PeerID", testGetPeerID_From_Address_Without_A_PeerID),
        ("testGetPathForUnix", testGetPathForUnix),
        ("testGetPathForUnix_Multiple_Protos", testGetPathForUnix_Multiple_Protos),
        ("testGetPathForUnix_No_Path", testGetPathForUnix_No_Path),
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
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

extension Data {
    func hexString() -> String {
        return map { String(format:"%02x", $0) }.joined()
    }
}
