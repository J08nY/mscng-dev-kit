Sample program for adding a new hash algorithm to CNG.

This sample uses CNG's Crypto Config APIs to register a
new hash algorithm. After registering the new hash algorithm,
it calls the BCrypt APIs to test the new hash algorithm in a
HMAC setting.
