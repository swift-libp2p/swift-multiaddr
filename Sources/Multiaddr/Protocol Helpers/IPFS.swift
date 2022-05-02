//
//  IPFS.swift
//
//  Created by Luke Reichold
//  Modified by Brandon Toms on 5/1/22.
//

import Foundation
import VarInt
import Multibase
import Multihash
import CID

struct IPFS {
    static func data(for address: String) throws -> Data {
//        let raw = try? BaseEncoding.decode(address, as: .base58btc)
//        print(raw)
//        let raw2 = try? BaseEncoding.decode(address) //36 bytes
//        print(raw2)
//        print("Checking if address is a valid multihash: \(address)")
//        let mh = try Multihash(multihash: address)
//        print(mh.b58String)
//        return Data(mh.digest!)
        
        let addressBytes = Array(try BaseEncoding.decode(address, as: .base58btc).data) //Base58.bytesFromBase58(address)
        let sizeBytes = UInt64(addressBytes.count).varIntData()
        let combined = [Array(sizeBytes), addressBytes].flatMap { $0 }
        return Data(bytes: combined, count: combined.count)
    }
    
    static func string(for data: Data) throws -> String {
//        print("Checking if data is a valid multihash")
//        return try Multihash(multihash: data).b58String
        
        let buffer = Array(data)
        let decodedVarint = VarInt.uVarInt(buffer) //Varint.readUVarInt(from: buffer)
        //let expectedSize = decodedVarint.value

        let addressBytes = Array(buffer[decodedVarint.bytesRead...])
        
        // Commenting out this check due to using CID / Multihash Init as verification...
        //guard addressBytes.count == expectedSize else { throw MultiaddrError.ipfsAddressLengthConflict }
        
        //Ensure addressBytes is a valid CID or Multihash compliant buffer and store it as a b58 String if so...
        guard let str = (try? CID(addressBytes).multihash.b58String) ?? (try? Multihash(addressBytes).b58String) else {
            throw MultiaddrError.ipfsAddressLengthConflict
        }
        return str
        
        //return addressBytes.asString(base: .base58btc) //Base58.base58FromBytes(addressBytes)
    }
}
