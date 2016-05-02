# blirhotp

HOTP implementation by JavaScript

## Installation

Read in script block.

example:
````
<script src="blirhotp.min.js"></script>
````

## Usage

````
// create secret key by hex strings.
var secret = Hmac.xk("3132333435363738393031323334353637383930");
// generate HOTP with the key and count 0.
var hotpNumber = Hotp.generate(secret, 0);

console.log(hotpNumber); // 755224
````

## Documentation

## API

## License

See LICENSE file.
