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

extension MultiaddrError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidFormat:
            return "Multiaddr string/bytes are not in a valid format."
        case .parseAddressFail:
            return "Failed to parse the address component of the multiaddr."
        case .parseIPv4AddressFail:
            return "Failed to parse a valid IPv4 address."
        case .parseIPv6AddressFail:
            return "Failed to parse a valid IPv6 address."
        case .invalidPortValue:
            return "Port value is missing or outside the valid range (1...65535)."
        case .invalidOnionHostAddress:
            return "Onion host address is malformed or has an invalid length."
        case .invalidGarlicAddress:
            return "Garlic (I2P) address is malformed or has an invalid length."
        case .unknownProtocol:
            return "Encountered a protocol name that is not a valid multiaddr protocol."
        case .ipfsAddressLengthConflict:
            return "The declared IPFS address length does not match the provided data."
        case .unknownCodec:
            return "The requested codec was not found in this multiaddr."
        }
    }
}

extension MultiaddrError: LocalizedError {
    public var errorDescription: String? { description }
}
