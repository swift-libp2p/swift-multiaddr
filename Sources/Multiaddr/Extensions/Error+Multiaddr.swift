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

public enum MultiaddrError: Error {
    case invalidFormat
    case parseAddressFail
    case parseIPv4AddressFail
    case parseIPv6AddressFail
    case invalidPortValue
    case invalidOnionHostAddress
    case invalidGarlicAddress
    case unknownProtocol
    case ipfsAddressLengthConflict
    case unknownCodec
}
