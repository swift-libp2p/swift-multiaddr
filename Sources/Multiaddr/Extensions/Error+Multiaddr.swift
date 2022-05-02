//
//  Error+Multiaddr.swift
//  
//  Created by Luke Reichold
//  Modified by Brandon Toms on 5/1/22.
//

import Foundation

enum MultiaddrError: Error {
    case invalidFormat
    case parseAddressFail
    case parseIPv4AddressFail
    case parseIPv6AddressFail
    case invalidPortValue
    case invalidOnionHostAddress
    case unknownProtocol
    case ipfsAddressLengthConflict
}
