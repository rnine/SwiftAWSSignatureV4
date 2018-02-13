//
//  Extensions.swift
//  SwiftAWSSignatureV4PackageDescription
//
//  Created by Dimitar Ostoich on 13.02.18.
//

import Foundation

extension DateFormatter {
    public static let ISO8601 : DateFormatter = {
        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZ"
        return dateFormatter
    }()
    
    public static let ISO8601UTC : DateFormatter = {
        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZ"
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
        return dateFormatter
    }()
    
    public static let RFC2822 : DateFormatter = {
        let rfcDateFormat = DateFormatter()
        rfcDateFormat.locale = Locale(identifier: "en_US_POSIX")
        rfcDateFormat.dateFormat = "EEE, dd MMM yyyy HH:mm:ss ZZZZ"
        return rfcDateFormat
    }()
    
    public static let RFC2822UTC : DateFormatter = {
        let rfcDateFormat = DateFormatter()
        rfcDateFormat.locale = Locale(identifier: "en_US_POSIX")
        rfcDateFormat.dateFormat = "EEE, dd MMM yyyy HH:mm:ss ZZZZ"
        rfcDateFormat.timeZone = TimeZone(secondsFromGMT: 0)
        return rfcDateFormat
    }()
    
    public static let RFC2822UTCShort : DateFormatter = {
        let rfcDateFormat = DateFormatter()
        rfcDateFormat.locale = Locale(identifier: "en_US_POSIX")
        rfcDateFormat.timeZone = TimeZone(secondsFromGMT: 0)
        rfcDateFormat.dateFormat = "yyyyMMdd"
        return rfcDateFormat
    }()
}


struct HTTPDate {
    static func long(fromDate date:Date) -> String {
        return DateFormatter.RFC2822UTC.string(from: date)
    }
    
    static func short(fromDate date:Date) -> String {
        return DateFormatter.RFC2822UTCShort.string(from: date)
    }
}
