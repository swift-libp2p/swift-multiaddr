//
//  Garlic.swift
//
//  Modified by Brandon Toms on 5/1/22.
//

import BaseX
import Foundation
import Multibase
import VarInt

struct Garlic32 {
    static func data(for string: String) throws -> Data {
        if string.count < 55 && string.count != 52 { throw MultiaddrError.invalidGarlicAddress }
        let padded = string + String(repeating: "=", count: string.count % 8)
        let decoded = try BaseEncoding.decode(padded, as: .base32Pad).data // BaseX.decode(string, as: .custom(Garlic32.alphabet))
        if decoded.count < 35 && decoded.count != 32 { throw MultiaddrError.invalidGarlicAddress }
        return Data(VarInt.putUVarInt(UInt64(decoded.count)) + decoded)
    }

    static func string(for data: Data) throws -> String {
        if data.count < 35 && data.count != 32 { throw MultiaddrError.invalidGarlicAddress }
        var encoded = data.asString(base: .base32Pad) //BaseX.encode(data, into: .custom(Garlic32.alphabet))
        while encoded.last == "=" { encoded.removeLast() }
        if encoded.count < 55 && encoded.count != 52 { throw MultiaddrError.invalidGarlicAddress }
        return encoded
    }
}

struct Garlic64 {
    static let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

    static func data(for string: String) throws -> Data {
        guard string.count >= 516 && string.count <= 616 else { throw MultiaddrError.invalidGarlicAddress }
        let decoded = try BaseX.decode(string, as: .custom(Garlic64.alphabet))
        guard decoded.count >= 386 else { throw MultiaddrError.invalidGarlicAddress }
        return Data(VarInt.putUVarInt(UInt64(decoded.count)) + decoded)
    }

    static func string(for data: Data) throws -> String {
        guard data.count >= 386 else { throw MultiaddrError.invalidGarlicAddress }
        let encoded = BaseX.encode(data, into: .custom(Garlic64.alphabet))
        guard encoded.count >= 516 && encoded.count <= 616 else { throw MultiaddrError.invalidGarlicAddress }
        return encoded
    }
}
