# Test Vectors for CipherSaber
Copyright &copy; 2015 Bart Massey

These test vectors are taken from the original
CipherSaber [documentation](http://ciphersaber.gurus.org/).

* `cstest1.cs1`: Plaintext "This is a test of CipherSaber."
  with no newline. Key "asdfg".

* `cstest2.cs1`: Plaintext of the Fourth Amendment to the
  U.S. Constitution. Key "SecretMessageforCongress" (note
  lowercase "f").

* `cknight.cs1`: Plaintext is GIF image of CipherKnight
  certificate. Key "ThomasJefferson". You must write your
  own CipherSaber implementation to claim this certificate.

* `cstest.cs2`: Plaintext "This is a test of CipherSaber-2."
  with no newline. Ten rounds of key scheduling. Key
  "asdfg".

[This website](http://www.cypherspace.org/adam/csvec/)
describes some human-memorable test vectors for
CipherSaber-2 with 20-round key scheduling and provides
software to generate more. My favorite is the ciphertext
input "Al Dakota guts" with key "Al", which corresponds
to the plaintext "held".
