//
//  Address.swift
//
//  Created by Luke Reichold
//  Modified by Brandon Toms on 5/1/22.
//

import Foundation
import VarInt
import Multicodec
import Multihash
import CID

public struct Address: Equatable {
    let addrProtocol: MultiaddrProtocol
    var address: String?
    
    init(addrProtocol: MultiaddrProtocol, addressData: Data) {
        self.addrProtocol = addrProtocol
        guard !addressData.isEmpty else { self.address = nil; return }
        self.address = try? unpackAddress(addressData)
    }
    
    init(addrProtocol: MultiaddrProtocol, address: String? = nil) {
        self.addrProtocol = addrProtocol
        guard let address = address, !address.isEmpty else { self.address = nil; return }
        switch addrProtocol {
        case .p2p, .ipfs:
            //Ensure addy is a valid CID or Multihash compliant String and store it as a b58 String if so...
            self.address = (try? CID(address).multihash.b58String) ?? (try? Multihash(multihash: address).b58String)
        default:
            self.address = address
        }
    }
    
    func binaryPacked() throws -> Data {
        let bytes = [addrProtocol.packedCode(), try binaryPackedAddress()].compactMap{$0}.flatMap{$0}
        return Data(bytes: bytes, count: bytes.count)
    }
    
    public static func == (lhs: Address, rhs: Address) -> Bool {
        switch (lhs.addrProtocol, rhs.addrProtocol) {
        case (.certhash, .certhash):
            do {
                guard let leftAddress = lhs.address, let rightAddress = rhs.address else { return false }
                return try Multihash(multihash: leftAddress).value == Multihash(multihash: rightAddress).value
            } catch {
                return false
            }
        default:
            return lhs.addrProtocol == rhs.addrProtocol && lhs.address == rhs.address
        }
    }
}

extension Address {
    
    private func unpackAddress(_ addressData: Data) throws -> String? {
        switch addrProtocol {
        case .ip4:
            return try IPv4.string(for: addressData)
        case .ip6:
            return try IPv6.string(for: addressData)
        case .tcp, .udp, .dccp, .sctp:
            guard addressData.count == 2 else { throw MultiaddrError.parseAddressFail }
            return String(addressData.uint16.bigEndian)
        case .onion:
            return try Onion.string(for: addressData)
        case .onion3:
            return try Onion3.string(for: addressData)
        case .p2p, .ipfs:
            return try IPFS.string(for: addressData)
        case .dns4, .dns6, .dnsaddr, .unix:
            return try DNS.string(for: addressData)
        case .http, .https, .utp, .udt, .ws, .wss, .quic, .p2p_circuit:
            return nil
        case .certhash:
            guard !addressData.isEmpty else { throw MultiaddrError.parseAddressFail }
            let varInt = VarInt.uVarInt(addressData.bytes)
            guard Int(varInt.value) + varInt.bytesRead == addressData.count else { throw MultiaddrError.parseAddressFail }
            return try Multihash(multihash: addressData.dropFirst(varInt.bytesRead)).asMultibase(.base16)
        default:
            throw MultiaddrError.parseAddressFail
        }
    }
    
    private func binaryPackedAddress() throws -> Data? {
        guard let address = address else { return nil }
        switch addrProtocol {
        case .tcp, .udp, .dccp, .sctp:
            guard let port = UInt16(address) else { throw MultiaddrError.invalidPortValue }
            var bigEndianPort = port.bigEndian
            return Data(bytes: &bigEndianPort, count: MemoryLayout<UInt16>.size)
        case .ip4:
            return try IPv4.data(for: address)
        case .ip6:
            return try IPv6.data(for: address)
        case .onion:
            return try Onion.data(for: address)
        case .onion3:
            return try Onion3.data(for: address)
        case .p2p, .ipfs:
            return try IPFS.data(for: address)
        case .dns4, .dns6, .dnsaddr, .unix:
            return DNS.data(for: address)
        case .http, .https, .utp, .udt, .ws, .wss, .quic, .p2p_circuit:
            return nil
        case .certhash:
            let mh = try Multihash(multihash: address)
            return Data(VarInt.putUVarInt(UInt64(mh.value.count)) + mh.value)
        default:
            throw MultiaddrError.parseAddressFail
        }
    }
    
    static func byteSizeForAddress(_ proto: MultiaddrProtocol, buffer: [UInt8]) -> Int {
        switch proto.size() {
        case .fixed(let bits):
            return bits / 8
        case .variable:
            let (sizeValue, bytesRead) = VarInt.uVarInt(buffer) //Varint.readUVarInt(from: buffer)
            return Int(sizeValue) + bytesRead
        case .zero:
            return 0
        }
    }
}

extension Address: CustomStringConvertible {
    public var description: String {
        return "/" + [addrProtocol.name, address].compactMap{$0}.joined(separator: "/")
    }
    
    public var codec:MultiaddrProtocol {
        return addrProtocol
    }
    
    public var addr:String? {
        return address
    }
}
