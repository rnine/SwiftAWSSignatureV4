//3.1
import PackageDescription
let package = Package(
	name: "SwiftAWSSignatureV4"
	,dependencies:[
	.Package(url:"https://github.com/IBM-Swift/BlueCryptor.git", Version("0.8.9"))
	]
)
