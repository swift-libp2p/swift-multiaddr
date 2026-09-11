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
import Multihash
import VarInt

public struct Multiaddr: Equatable, Sendable {

    public private(set) var addresses: [Address] = []

    public init(_ string: String) throws {
        guard !string.isEmpty else { throw MultiaddrError.invalidFormat }
        addresses = try createAddresses(from: string)
        guard !self.addresses.isEmpty else { throw MultiaddrError.parseAddressFail }
        try validate()
    }

    public init(_ bytes: Data) throws {
        guard !bytes.isEmpty else { throw MultiaddrError.invalidFormat }
        self.addresses = try createAddresses(fromData: bytes)
        guard !self.addresses.isEmpty else { throw MultiaddrError.parseAddressFail }
        try validate()
    }

    public init(_ proto: MultiaddrProtocol, address: String?) throws {
        var addrStr = "/\(proto.name)"
        if let addr = address, !addr.isEmpty { addrStr.append(addr.hasPrefix("/") ? addr : "/\(addr)") }
        try self.init(addrStr)
    }

    init(_ addresses: [Address]) {
        self.addresses = addresses
    }

    /// Returns the `Multiaddr` as data
    public func binaryPacked() throws -> Data {
        let bytes = try addresses.flatMap { try $0.binaryPacked() }
        return Data(bytes)
    }

    /// Returns a list of `Protocol` elements contained by this `Multiaddr`, ordered from left-to-right.
    public func protocols() -> [MultiaddrProtocol] {
        addresses.map { $0.addrProtocol }
    }

    /// Returns a list of `Protocol` elements contained by this `Multiaddr`, ordered from left-to-right.
    public func protoNames() -> [String] {
        addresses.map { $0.addrProtocol.name }
    }

    /// Returns a list of `Protocol` elements contained by this `Multiaddr`, ordered from left-to-right.
    public func protoCodes() -> [UInt64] {
        addresses.map { $0.addrProtocol.code }
    }

    /// Wraps this `Multiaddr` with another and returns the combination.
    public func encapsulate(_ other: Multiaddr) -> Multiaddr {
        Multiaddr(addresses + other.addresses)
    }

    public func encapsulate(_ other: String) throws -> Multiaddr {
        encapsulate(try Multiaddr(other))
    }

    public func encapsulate(proto: MultiaddrProtocol, address: String?) throws -> Multiaddr {
        encapsulate(try Multiaddr(proto, address: address))
    }

    /// Returns a new `Multiaddr`, removing the last occurance of the specified `Multiaddr` and all subsequent addresses.
    public func decapsulate(_ other: Multiaddr) -> Multiaddr {
        guard let first = other.addresses.first else { return self }
        if let lastMatch = addresses.lastIndex(where: { $0 == first }) {
            return Multiaddr(Array(addresses[..<lastMatch]))
        } else {
            return self
        }
    }

    /// Returns a new `Multiaddr`, removing the last occurance of the protocol and all subsequent addresses.
    public func decapsulate(_ other: String) -> Multiaddr {
        let protoName = other.hasPrefix("/") ? String(other.dropFirst()) : other
        if let lastMatch = addresses.lastIndex(where: { $0.addrProtocol.name == protoName }) {
            return Multiaddr(Array(addresses[..<lastMatch]))
        } else {
            return self
        }
    }

    /// Returns a new `Multiaddr`, removing the last occurance of the protocol and all subsequent addresses.
    public func decapsulate(_ other: MultiaddrProtocol) -> Multiaddr {
        if let lastMatch = addresses.lastIndex(where: { $0.addrProtocol == other }) {
            return Multiaddr(Array(addresses[..<lastMatch]))
        } else {
            return self
        }
    }

    /// Removes and returns the last `Address` of this `Multiaddr`.
    public mutating func pop() -> Address? {
        addresses.popLast()
    }

    /// Extracts a PeerID's String representation from the Multiaddress if one exists, otherwise returns nil
    public func getPeerIDString() -> String? {
        self.addresses.last(where: {
            ($0.addrProtocol == .p2p || $0.addrProtocol == .ipfs)
        })?.address
    }

    /// Extracts a Unix Path from the Multiaddress if one exists, otherwise returns nil
    /// - Note: We append a `/` to the returned path
    public func getPath() -> String? {
        if let path = self.addresses.last(where: {
            $0.addrProtocol == .unix
        })?.address {
            return "/" + path
        } else {
            return nil
        }
    }

    public func getFirstAddress(forCodec codec: MultiaddrProtocol) -> Address? {
        self.addresses.first(where: { $0.codec.isEqual(codec) })
    }

    public func getAddresses(forCodec codec: MultiaddrProtocol) -> [Address] {
        self.addresses.compactMap { if $0.codec.isEqual(codec) { return $0 } else { return nil } }
    }

    /// Returns a new Multiaddr replacing the Address associated with the specified codec
    ///
    /// - Parameters:
    ///   - newAddress: The address to swap the current one with
    ///   - codec: The Codec of the address to swap
    /// - Returns: A new Multiaddr with the specified Codec Address swapped
    public func swap(address newAddress: String, forCodec codec: MultiaddrProtocol) throws -> Multiaddr {
        let matchIndex = self.addresses.firstIndex { $0.codec == codec }

        /// If we found a match, replace it's Address
        if let idx = matchIndex {
            var newAddresses = self.addresses
            newAddresses[idx] = try Address(addrProtocol: codec, address: newAddress)
            let newMA = Multiaddr(newAddresses)
            try newMA.validate()
            return newMA
        } else {
            return self
        }
    }

    /// Mutates the Multiaddr if the specified Codec is found by replacing the address with the provided new address
    ///
    /// - Parameters:
    ///   - newAddress: The address to swap the current one with
    ///   - codec: The Codec of the address to swap
    public mutating func mutatingSwap(address newAddress: String, forCodec codec: MultiaddrProtocol) throws {
        let matchIndex = self.addresses.firstIndex { $0.codec == codec }

        /// If we found a match, replace it's Address
        if let idx = matchIndex {
            self.addresses[idx] = try Address(addrProtocol: codec, address: newAddress)
        } else {
            throw MultiaddrError.unknownCodec
        }
        /// Ensure the change is valid...
        try validate()
    }
}

extension Multiaddr: CustomStringConvertible {
    public var description: String {
        guard !addresses.isEmpty else { return "/" }
        return addresses.map { $0.description }.joined()
    }
}

extension Multiaddr {
    /// In order to support unix style addresses we can't simply split
    func createAddresses(from string: String) throws -> [Address] {
        var fullString = string
        guard !fullString.isEmpty, fullString.removeFirst() == "/" else { throw MultiaddrError.invalidFormat }
        var components = fullString.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        var addresses = [Address]()
        while !components.isEmpty {
            let current = components.removeFirst()

            guard !current.isEmpty else { throw MultiaddrError.invalidFormat }
            guard current.isMultiaddrProtocol() else { throw MultiaddrError.unknownProtocol }

            var addressElements = [String]()
            while let next = components.first, !next.isMultiaddrProtocol() {
                components.removeFirst()
                addressElements.append(next)
            }
            let newAddress = try Address(
                addrProtocol: MultiaddrProtocol(name: current),
                address: addressElements.combined()
            )
            addresses.append(newAddress)
        }
        return addresses
    }

    func createAddresses(fromData data: Data) throws -> [Address] {
        var buffer = Array(data)
        var addresses = [Address]()

        while !buffer.isEmpty {
            // A malformed varint throws rather than reading zero bytes, so the loop always
            // makes forward progress and can't spin indefinitely.
            guard let (code, end) = try? VarInt.decode(buffer) else { throw MultiaddrError.invalidFormat }

            buffer.removeFirst(end)

            guard let proto = try? MultiaddrProtocol(code: code) else { throw MultiaddrError.unknownProtocol }

            if case .zero = proto.size() {
                addresses.append(try Address(addrProtocol: proto))
                continue
            }

            let addressSize = Address.byteSizeForAddress(proto, buffer: buffer)
            guard addressSize > 0, buffer.count >= addressSize else { throw MultiaddrError.invalidFormat }
            let addressBytes = Data(buffer.prefix(addressSize))
            let address = try Address(addrProtocol: proto, addressData: addressBytes)
            addresses.append(address)

            buffer.removeFirst(addressSize)
        }

        return addresses
    }

    /// If we're able to serialize the `Multiaddr` created from a string without error, consider it valid.
    func validate() throws {
        _ = try binaryPacked()
    }
}

extension Multiaddr: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(try? self.binaryPacked())
    }
}

extension Array where Element == String {
    func combined() -> String? {
        guard !isEmpty else { return nil }
        return joined(separator: "/")
    }
}

// MARK: - Codable

extension Multiaddr: Codable {
    /// Decodes a `Multiaddr` from its human-readable string representation (e.g. `/ip4/127.0.0.1/tcp/4001`).
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        try self.init(string)
    }

    /// Encodes a `Multiaddr` as its human-readable string representation.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.description)
    }
}

// MARK: - Collection

extension Multiaddr: RandomAccessCollection {
    public var startIndex: Int { addresses.startIndex }
    public var endIndex: Int { addresses.endIndex }
    public subscript(position: Int) -> Address { addresses[position] }
    public func index(after i: Int) -> Int { addresses.index(after: i) }
    public func index(before i: Int) -> Int { addresses.index(before: i) }
}

// MARK: - Typed accessors

extension Multiaddr {
    /// Extracts the PeerID from the multiaddr as a `Multihash`, if a `p2p`/`ipfs` component exists.
    ///
    /// Handles both raw multihash strings and CID-encoded peer ids (returning the underlying multihash).
    public func getPeerIDMultihash() -> Multihash? {
        guard let peerIDString = getPeerIDString() else { return nil }
        return try? P2P.multihash(for: peerIDString)
    }
}
