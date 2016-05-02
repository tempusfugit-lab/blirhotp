# blirhotp

HOTP implementation by JavaScript.

## Installation

Read in a script block.

example:
````
<script src="blirhotp.min.js"></script>
````

## Usage

````
// create a secret key from hex strings.
var secret = Hmac.xk("3132333435363738393031323334353637383930");
// or create a secret key from Base32 strings.
// var secret = Hotp.decodeBase32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

// generate an HOTP value with the key and count 0.
var hotpNumber = Hotp.generate(secret, 0);

console.log(hotpNumber); // 755224
````

## Documentation

## API

## License

See LICENSE file.
