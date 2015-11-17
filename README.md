# ciphersaber2
Copyright © 2015 Bart Massey

This package provides a Haskell library and driver program
implementing [CipherSaber-2](http://ciphersaber.gurus.org/)(CS2)
stream encryption based on the
[RC4](http://en.wikipedia.org/wiki/RC4) stream encryption
algorithm. This implementation has been tested against and
is compatible with existing CipherSaber implementations.

## CS2

The documentation for CS2 is a bit out-of-date and
scattered.

### History

CS2 is based on the RC4 stream cipher.  Wikipedia
has a nice
[history](http://en.wikipedia.org/wiki/RC4#History) of RC4
as well as current reports on its
[cryptanalysis](http://en.wikipedia.org/wiki/RC4#Security).

In 1999, Arnold Reinhold suggested using RC4 as the basis
for citizens to learn to build their own encryption
software, along the lines of Jedi Light Sabers. Reinhold
proposed a stream protocol for RC4 ciphertext that he called
[CipherSaber](http://ciphersaber.gurs.org) (Note that the CipherSaber
website is mostly abandoned and in some state of disrepair.)

In 2003, after cryptographic attacks were found against RC4
as used in CipherSaber, Reinhold modified the CipherSaber
protocol to produce a new parameterized family of protocols
known as CS2: the original CipherSaber is a
special case of CS2, and is often referred to as
CipherSaber-1.

### Algorithm

Pseudocode for CS2 is available from a variety of
places. The pseudocode given here attempts to be clear and
normative.

CS2 encryption and decryption both require an RC4
implementation that has been modified to iterate the key
schedule a given number of times.

<!-- This pseudocode translated from rc4.pseu by pseuf -->

>   
> --&nbsp;Produce an RC4 keystream of length&nbsp;*n*&nbsp;with  
> --&nbsp;*r*&nbsp;rounds of key scheduling given key&nbsp;*k*  
> *rc4*(*n*,&nbsp;*r*,&nbsp;*k*):  
> &nbsp;&nbsp;&nbsp;&nbsp;*l*&nbsp;&#8592;&nbsp;**length**&nbsp;*k*  
> &nbsp;&nbsp;&nbsp;&nbsp;--&nbsp;Initialize&nbsp;the&nbsp;array.  
> &nbsp;&nbsp;&nbsp;&nbsp;*S*&nbsp;&#8592;&nbsp;zero-based array of 256 bytes  
> &nbsp;&nbsp;&nbsp;&nbsp;**for**&nbsp;*i*&nbsp;**in**&nbsp;0..255  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*S*[*i*]&nbsp;&#8592;&nbsp;*i*  
> &nbsp;&nbsp;&nbsp;&nbsp;--&nbsp;Do&nbsp;key&nbsp;scheduling.  
> &nbsp;&nbsp;&nbsp;&nbsp;*j*&nbsp;&#8592;&nbsp;0  
> &nbsp;&nbsp;&nbsp;&nbsp;**repeat**&nbsp;*r*&nbsp;**times**  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**for**&nbsp;*i*&nbsp;**in**&nbsp;0..255  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*j*&nbsp;&#8592;&nbsp;(*j*&nbsp;+&nbsp;*S*[*i*]&nbsp;+&nbsp;*k*[*i*&nbsp;**mod**&nbsp;*l*])&nbsp;**mod**&nbsp;256  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*S*[*i*]&nbsp;&#8596;&nbsp;*S*[*j*]  
> &nbsp;&nbsp;&nbsp;&nbsp;--&nbsp;Finally,&nbsp;produce&nbsp;the&nbsp;stream.  
> &nbsp;&nbsp;&nbsp;&nbsp;*keystream*&nbsp;&#8592;&nbsp;zero-based array of&nbsp;*n*&nbsp;bytes  
> &nbsp;&nbsp;&nbsp;&nbsp;*j*&nbsp;&#8592;&nbsp;0  
> &nbsp;&nbsp;&nbsp;&nbsp;**for**&nbsp;*i*&nbsp;**in**&nbsp;0..n-1  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;i'&nbsp;&#8592;&nbsp;(*i*&nbsp;+&nbsp;1)&nbsp;**mod**&nbsp;256  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*j*&nbsp;&#8592;&nbsp;(*j*&nbsp;+&nbsp;*S*[i'])&nbsp;**mod**&nbsp;256  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*S*[i']&nbsp;&#8596;&nbsp;*S*[*j*]  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*keystream*[*i*]&nbsp;&#8592;&nbsp;*S*[(*S*[i']&nbsp;+&nbsp;*S*[*j*])&nbsp;**mod**&nbsp;256]  
> &nbsp;&nbsp;&nbsp;&nbsp;**return**&nbsp;*keystream*  

<!-- End of pseuf translation of rc4.pseu -->


CS2 encryption requires a plaintext message (treated as a
bytestream), a key with a recommended maximum size of 53
bytes and a required maximum size of 256 bytes, and an
"initial value"
([IV](http://en.wikipedia.org/wiki/Initialization_vector))
of 10 bytes. The IV is a
[nonce](http://en.wikipedia.org/wiki/Cryptographic_nonce)
that must be different for each message sent: it should be
chosen randomly if possible, but may be chosen
pseudo-randomly or even just counted if necessary.

<!-- This pseudocode translated from encrypt.pseu by pseuf -->

>   
> --&nbsp;Ciphersaber-2 encrypt message&nbsp;*m*&nbsp;with key&nbsp;*k*&nbsp;and  
> --&nbsp;*r*&nbsp;rounds of key scheduling  
> *encrypt*(*m*,&nbsp;*r*,&nbsp;*k*):  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*n*&nbsp;&#8592;&nbsp;**length**&nbsp;*m*  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*iv*&nbsp;&#8592;&nbsp;appropriately-chosen 10-byte IV  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;k'&nbsp;&#8592;&nbsp;prepend&nbsp;*k*&nbsp;**to**&nbsp;*iv*  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*keystream*&nbsp;&#8592;&nbsp;*rc4*(*n*,&nbsp;*r*,&nbsp;k')  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ciphertext&nbsp;&#8592;&nbsp;zero-based array of&nbsp;*n*&nbsp;+&nbsp;10&nbsp;bytes  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**for**&nbsp;*i*&nbsp;**in**&nbsp;0..9  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ciphertext[*i*]&nbsp;&#8592;&nbsp;*iv*[*i*]  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**for**&nbsp;*i*&nbsp;**in**&nbsp;0..*n*  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ciphertext[*i*&nbsp;+&nbsp;10]&nbsp;&#8592;&nbsp;*m*[*i*]&nbsp;**xor**&nbsp;*keystream*[*i*]  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**return**&nbsp;ciphertext  

<!-- End of pseuf translation of encrypt.pseu -->

CS2 decryption requires ciphertext and the encryption key
used to produce the ciphertext.

<!-- This pseudocode translated from decrypt.pseu by pseuf -->

>   
> --&nbsp;Ciphersaber-2 decrypt ciphertext&nbsp;*m*&nbsp;with key&nbsp;*k*&nbsp;and  
> --&nbsp;*r*&nbsp;rounds of key scheduling  
> *decrypt*(*m*,&nbsp;*r*,&nbsp;*k*):  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*n*&nbsp;&#8592;&nbsp;**length**&nbsp;*m*  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*iv*&nbsp;&#8592;&nbsp;*m*[0..9]  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;delete the first 10 characters of&nbsp;*m*  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;k'&nbsp;&#8592;&nbsp;prepend&nbsp;*k*&nbsp;**to**&nbsp;*iv*  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*keystream*&nbsp;&#8592;&nbsp;*rc4*(*n*&nbsp;-&nbsp;10,&nbsp;*r*,&nbsp;k')  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;plaintext&nbsp;&#8592;&nbsp;zero-based array of&nbsp;*n*&nbsp;-&nbsp;10&nbsp;bytes  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**for**&nbsp;*i*&nbsp;**in**&nbsp;0..n-10  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;plaintext[*i*]&nbsp;&#8592;&nbsp;*m*[*i*]&nbsp;**xor**&nbsp;*keystream*[*i*]  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**return**&nbsp;plaintext  

<!-- End of pseuf translation of decrypt.pseu -->

## Library

The `CipherSaber2` library provides a relatively straightforward
`ByteString` interface. See the `haddock` documentation
for details.

## Driver

The program `cs2` uses the `CipherSaber2` library to encrypt
or decrypt `stdin` to `stdout`. Say "`cs2 --help`" for usage
information.

## License

This work is licensed under the "MIT License".  Please
see the file LICENSE in the source distribution of this
software for license terms.

