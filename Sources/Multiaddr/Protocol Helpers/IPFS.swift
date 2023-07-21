//
//  IPFS.swift
//
//  Created by Luke Reichold
//  Modified by Brandon Toms on 5/1/22.
//

import Foundation
import Multihash
import VarInt
import CID

struct P2P {
    static func data(for address: String) throws -> Data {
        let multihash = try (try? CID(address).multihash) ?? Multihash(multihash: address)
        return Data(putUVarInt(UInt64(multihash.value.count)) + multihash.value)
    }
    
    static func string(for data: Data) throws -> String {
        let varInt = uVarInt(data.bytes)
        guard varInt.bytesRead + Int(varInt.value) == data.count else { throw MultiaddrError.invalidFormat }
        return try Multihash(multihash: data.dropFirst(varInt.bytesRead)).b58String
    }
}
