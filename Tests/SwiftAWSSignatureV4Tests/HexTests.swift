@testable import SwiftAWSSignatureV4
import XCTest

class HexTests : XCTestCase {
	
	func testHexInts() {
		let cases:[(UInt64, String)] = [
			(0, "0000000000000000")
			,(1, "0000000000000001")
			,(65536, "0000000000010000")
			,(1147797409030816545, "0FEDCBA987654321")
		]
		
		for (int, string) in cases {
			XCTAssertEqual(int.bytesAsHex, string)
		}
	}
	
    func testAuth() {
        let account = AWSAccount(serviceName: "s3", region: "eu-central-1", accessKeyID: "AKIAIQCZHUPNYQHPNYCA", secretAccessKey: "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")
        
        var r = URLRequest(url: URL(string:"https://cryptoalerts-data.s3.amazonaws.com/CryptoCompare/SymbolsInfo.json")!)
        r.httpBody = Data()
        r.sign(for: account)
        //print(r.allHTTPHeaderFields)
        let ex = expectation(description: "")
        URLSession.shared.dataTask(with: r) { (data, res, err) in
            print(res)
            print(data)
            ex.fulfill()
        }.resume()
        waitForExpectations(timeout: 1000) { (error) in
            
        }
    }
    
}
