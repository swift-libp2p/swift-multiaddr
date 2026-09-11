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
//
//  Created by Luke Reichold
//  Modified by Brandon Toms on 5/1/22.
//

import CID
import Foundation
import Multibase
import Multihash
import VarInt

struct P2P {
    /// The `Multihash` a `p2p`/`ipfs` address component names.
    ///
    /// A peer id is written either as a CID or as a bare base58btc Multihash, which carries no
    /// multibase prefix, so the base is named explicitly rather than read off the string.
    static func multihash(for address: String) throws -> Multihash {
        if let cid = try? CID(address) { return cid.multihash }
        return try Multihash(BaseEncoding.decode(address, as: .base58btc))
    }

    static func data(for address: String) throws -> Data {
        let multihash = try P2P.multihash(for: address)
        return Data(UInt64(multihash.value.count).varIntBytes + multihash.value)
    }

    static func string(for data: Data) throws -> String {
        guard let (length, end) = try? VarInt.decode(data) else { throw MultiaddrError.invalidFormat }
        let multihashBytes = data[end...]
        guard Int(length) == multihashBytes.count else { throw MultiaddrError.invalidFormat }
        return try Multihash(multihashBytes).asString(base: .base58btc)
    }
}
