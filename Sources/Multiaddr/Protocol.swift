//
//  Protocol.swift
//
//  Created by Luke Reichold
//  Modified by Brandon Toms on 5/1/22.
//

import Foundation
import Multicodec

public typealias MultiaddrProtocol = Codecs

enum BitSize {
    case fixed(bits: Int)
    case variable
    case zero
}

extension MultiaddrProtocol {
    func isMultiaddrProtocol() -> Bool {
        switch self {
        case .ip4, .tcp, .udp, .dccp, .ip6, .ip6zone, .dns4, .dns6, .dnsaddr, .sctp, .udt, .utp, .unix, .p2p, .ipfs, .http,
             .https, .onion, .onion3, .garlic64, .garlic32, .quic, .ws, .wss, .p2p_websocket_star, .p2p_webrtc_star, .p2p_webrtc_direct, .p2p_circuit:
            return true
        //case .p2pWebsocketStar, .p2pWebrtcStar, .p2pWebrtcDirect, .p2pCircuit, .memory:
        //    return true
        default:
            return false
        }
    }
    
    /// The number of bits that an address of this protocol will consume.
    func size() -> BitSize {
        switch self {
        case .ip4:
            return .fixed(bits: 32)
        case .tcp, .udp, .dccp, .sctp:
            return .fixed(bits: 16)
        case .ip6:
            return .fixed(bits: 128)
        case .onion:
            return .fixed(bits: 96)
        case .onion3:
            return .fixed(bits: 296)
        case .ipfs, .dns4, .dns6, .unix, .p2p:
            return .variable
        default:
            return .zero
        }
    }
    
    func packedCode() -> Data {
        return code.varIntData()
    }
}

// MARK: - Helpers

extension String {
    func isMultiaddrProtocol() -> Bool {
        return (try? Codecs(self).isMultiaddrProtocol()) ?? false
        //return MultiaddrProtocol.allCases.map{$0.rawValue}.contains(self)
    }
}
