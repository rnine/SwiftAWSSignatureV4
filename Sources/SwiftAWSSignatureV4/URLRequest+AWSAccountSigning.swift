//
//  AmazonS3.swift
//
//  Created by Ben Spratling on 3/30/17.
//
//

import Foundation
import Dispatch
import Cryptor


//Based on http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html


extension UInt8 {
	private static let hexChars:[String] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
	var hex:String {
		let lowBits:UInt8 = self & 0x0F
		let highBits:UInt8 = (self >> 4)
		return UInt8.hexChars[Int(highBits)] + UInt8.hexChars[Int(lowBits)]
	}
}


extension URLRequest {
	
	///adds an Authorization header
	/// uses chunking if a chunk size is specified, or if the httpBody is a stream.
	/// sends as a single chunk if the body is Data and the chunk
	/// chunking is ignored on non-apple platforms
	public mutating func sign(for account:AWSAccount, signPayload:Bool = false, chunkSize:Int? = nil) {
		let now:Date = Date()
		sign(for: account, now: now, signPayload:signPayload, chunkSize:chunkSize)
	}
	
	///primarily for testing
	mutating func sign(for account:AWSAccount, now:Date, signPayload:Bool = false, chunkSize:Int? = nil) {
#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
		if let chunkSize = chunkSize {
			if let dataBody = httpBody {
				httpBodyStream = InputStream(data: dataBody)
				httpBody = nil
			}
			signChunkingRequest(for: account, date: now, chunkSize: chunkSize)
			return
		} else if httpBodyStream != nil {
			signChunkingRequest(for: account, date: now, chunkSize:URLRequest.minimumAWSChunkSize)	//default chunk size
			return
		}
#endif
		//add some headers
		addPreAuthHeaders(date:now, signPayload:signPayload)
		//auth header
		let header = newAuthorizationHeader(account: account, now: now, signPayload:signPayload)
		setValue(header, forHTTPHeaderField: "Authorization")
	}
	
	
	///create headers which should be added before auth signing happens
	mutating func addPreAuthHeaders(date:Date, signPayload:Bool = false) {
		//credential
		//setValue(AWSAccount.credentialString(now:nowComponents), forHTTPHeaderField: "x-amz-credential")
		setValue(HTTPDate.long(fromDate: date), forHTTPHeaderField: "Date")
		if let _ = httpBody {
			if signPayload {
				//TODO: verify me
				setValue(sha256HashedBody?.map{$0.hex}.joined(), forHTTPHeaderField: "x-amz-content-sha256")
			} else {
				setValue("UNSIGNED-PAYLOAD", forHTTPHeaderField: "x-amz-content-sha256")
			}
		} else {
			//the hash of an empty string
			setValue("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", forHTTPHeaderField: "x-amz-content-sha256")
		}
	}
	
	///returns sorted key-value tuples
	func canonicalHeaders()->[(String, String)] {
		let allHeaders = allHTTPHeaderFields ?? [:]
		var headerValues:[(String,String)] = allHeaders.map { (key, value) -> (String, String) in
			return (key.lowercased(), value.trimmingCharacters(in: .whitespaces))
		}
		headerValues = headerValues.filter({ (key0, _) -> Bool in
			return key0 == "host"
				|| key0 == "content-type"
				|| key0.hasPrefix("x-amz-")
		})
		if allHeaders["Host"] == nil, let host:String = url?.host {
			headerValues.append(("host",host))
		}
		headerValues.sort { $0.0 < $1.0 }
		return headerValues
		
	}
	
	
	func canonicalRequestBeforePayload() -> (request: String, signedHeaders: String)? {
		let verb = httpMethod ?? "GET"

        guard let uriString = url?.path else { return nil }
        guard let encodedURI = uriString.aws_uriEncoded(encodeSlash: false) else { return nil }

        var queryString = url?.query

        if let queryLongString = queryString, !queryLongString.isEmpty {
            let queryItems = queryLongString.components(separatedBy: "&").sorted()

            let reconstituted = queryItems.map {
				$0.components(separatedBy: "=")
					.compactMap { $0.aws_uriEncoded(encodeSlash: true) }
					.joined(separator: "=")
            }

			queryString = reconstituted.joined(separator: "&")
		}
		
		let headerValues = canonicalHeaders()

        let headers = headerValues
            .map { "\($0):\($1)" }
            .joined(separator: "\n")
            .appending("\n")

        let signedHeaders = headerValues
            .map { $0.0 }
            .joined(separator: ";")
		
		return ([verb, encodedURI, queryString ?? "", headers, signedHeaders].joined(separator: "\n"), signedHeaders)
	}
	
	
	func canonicalRequest(signPayload:Bool)->(request:String, signedHeaders:String)? {
		guard let (beforePayload, signedHeaders) = canonicalRequestBeforePayload() else { return nil }
		let hashedBody:String = signPayload ? sha256HashedBody.map { CryptoUtils.hexString(from: $0).uppercased() }
			?? "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" : "UNSIGNED-PAYLOAD"
		return (beforePayload + "\n" + hashedBody, signedHeaders)
	}
	
	
	var sha256HashedBody:[UInt8]? {
		if let bodyData = httpBody {
			return Digest(using: .sha256).update(data: bodyData)?.final()
		} else {
			return Digest(using: .sha256).update(string: "")?.final()
		}
	}
	
	
	func stringToSign(account:AWSAccount, now:Date, signPayload:Bool)->(string:String, signedHeaders:String)? {
		let timeString:String = HTTPDate.long(fromDate: now)
		guard let (request, signedHeaders) = canonicalRequest(signPayload:signPayload) else { return nil }
		//print("canonical request = \(request)")
		let hashOfCanonicalRequest:[UInt8] = Digest(using: .sha256).update(string: request)?.final() ?? []
		let hexHash:String = CryptoUtils.hexString(from: hashOfCanonicalRequest)
		
		return ("AWS4-HMAC-SHA256\n" + timeString + "\n" + account.scope(now: now) + "\n" + hexHash, signedHeaders)
	}
	
	
	func newAuthorizationHeader(account:AWSAccount, now:Date, signPayload:Bool = false)->String? {
		guard let signingKey:[UInt8] = account.keyForSigning(now:now)
			,let (string, signedHeaders) = stringToSign(account:account, now:now, signPayload:signPayload)
			else { return nil }
		//print("string to sign = \(string)")
		let signature:[UInt8] = HMAC(using:HMAC.Algorithm.sha256, key: Data(signingKey)).update(byteArray: CryptoUtils.byteArray(from:string))!.final()
		let signatureHex:String = CryptoUtils.hexString(from: signature)
		
		return "AWS4-HMAC-SHA256 Credential=\(account.credentialString(now:now)),SignedHeaders=\(signedHeaders),Signature=\(signatureHex)"
	}
	
}

