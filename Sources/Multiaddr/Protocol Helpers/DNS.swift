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

import Foundation
import VarInt

struct DNS {
    static func data(for address: String) -> Data {
        let addressBytes = Data(address.utf8)
        return Data(UInt64(addressBytes.count).varIntBytes) + addressBytes
    }

    static func string(for data: Data) throws -> String? {
        guard let (expectedSize, end) = try? VarInt.decode(data) else { throw MultiaddrError.parseAddressFail }

        let addressBytes = data[end...]
        guard addressBytes.count == expectedSize else { throw MultiaddrError.parseAddressFail }

        return String(data: Data(addressBytes), encoding: .utf8)
    }
}
