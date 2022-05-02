//
//  Data+Multiaddr.swift
//  
//  Created by Luke Reichold
//  Modified by Brandon Toms on 5/1/22.
//

import Foundation

extension Data {
    var uint16: UInt16 {
        return withUnsafeBytes {
            $0.load(as: UInt16.self)
        }
    }
}
