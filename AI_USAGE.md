## Tools
We used an AI assistant to discuss edge cases for Unicode NFC normalization, bidi control character filtering, and secure scrypt parameter parsing in Python 3.12.

## What AI got wrong
The AI initially suggested loose checks for `size_bytes` that accepted booleans and floats, and missed edge cases in scrypt salt and hash length decoding checks.

## In my own words
1. Why does get_document return 404 rather than 403 when a client asks for another client's contract?
Returning 404 instead of 403 prevents tenant enumeration and information disclosure, ensuring unauthorized users cannot verify the existence of resources belonging to other clients.

2. Why must verify_password refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?
Refusing a short hash prevents prefix-truncation attacks where an attacker could manipulate stored credentials to force partial-byte comparisons and bypass full authentication verification.
