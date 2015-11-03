-- Copyright © 2015 Bart Massey

-- | Implementation of the "CipherSaber-2" RC4 encryption
-- format. Also provides raw RC4 keystream generators and
-- a CipherSaber-1 implementation.
--
-- This work is made available under the "MIT License".  See
-- the file LICENSE in this distribution for license terms.
module CipherSaber2 (rc4, rc4dropN, encryptDropN, decryptDropN,
                     encrypt1, decrypt1, encrypt, decrypt,
                     toBytes, fromBytes) where

import Control.Monad
import Control.Monad.ST.Safe
import Data.Array.ST
import Data.Bits
import Data.Char
import Data.Word

-- | Number of bytes of IV to use in CipherSaber encryption/decryption
-- below. The standard CipherSaber IV size is 10 bytes.
ivLength :: Int
ivLength = 10

-- | Generate an RC4 keystream. CipherSaber recommends
-- a key of less than 54 bytes for best mixing. At most,
-- the first 256 bytes of the key are even used.
--
-- This code takes a length of keystream to generate, which
-- is un-Haskellike but hard to avoid given the strictness
-- of 'STUArray'. An alternative would be to pass the
-- plaintext in and combine it here, but this interface was
-- chosen as "simpler". The performance implications of this
-- choice need to be explored.
rc4 :: Int -> [Word8] -> [Word8]
rc4 keystreamLength key =
    runST $ do
      -- Create and initialize the state.
      s <- newListArray (0, 255) [0..255] :: ST s (STUArray s Word8 Word8)
      -- One step of the key schedule
      let schedStep j i = do
            si <- readArray s i
            let keyByte = key !! (fromIntegral i `mod` length key)
            let j' = j + si + keyByte
            sj <- readArray s j'
            writeArray s i sj
            writeArray s j' si
            return j'
      -- Do the key scheduling.
      foldM_ schedStep 0 [0..255]
      -- Do the keystream generation.
      let keystream 0 _ _ = return []
          keystream n i j = do
            let i' = i + 1
            si <- readArray s i'
            let j' = j + si
            sj <- readArray s j'
            writeArray s i' sj
            writeArray s j' si
            sk <- readArray s (si + sj)
            ks <- keystream (n - 1) i' j'
            return $ sk : ks
      -- Get the keystream.
      keystream keystreamLength 0 0

-- | RC4 with the first n keystream elements
-- dropped. Dropping 20 or more elements provides increased
-- resistance against known attacks.
rc4dropN :: Int -> Int -> [Word8] -> [Word8]
rc4dropN nDrop keystreamLength key =
  drop nDrop $ rc4 (keystreamLength + 200) key

-- | Convert a 'String' to a list of bytes.
toBytes :: String -> [Word8]
toBytes s = map (fromIntegral . ord) s

-- | Convert a list of bytes to a 'String'.
fromBytes :: [Word8] -> String
fromBytes bs = map (chr . fromIntegral) bs

-- | CipherSaber requires using a 10-byte initial value (IV) to
-- protect against keystream recovery. Given the key and IV,
-- this code will turn a plaintext message into a sequence
-- of ciphertext bytes.
encryptDropN :: Int -> [Word8] -> [Word8] -> [Word8] -> [Word8]
encryptDropN nDrop key iv plaintext
    | length iv == ivLength =
        let keystream = rc4dropN nDrop (length plaintext) (key ++ iv) in
        iv ++ zipWith xor keystream plaintext
    | otherwise = error $ "expected IV length " ++ show ivLength

-- | CipherSaber recovers the IV from the start of the ciphertext.
-- Given the key, this code will turn a sequence of
-- ciphertext bytes into a plaintext 'String' message. (Yes,
-- the type is a little weird.)
decryptDropN :: Int -> [Word8] -> [Word8] -> [Word8]
decryptDropN nDrop key ciphertext0 =
    let (iv, ciphertext) = splitAt ivLength ciphertext0
        keystream = rc4dropN nDrop (length ciphertext) (key ++ iv) in
    zipWith xor keystream ciphertext

-- | CipherSaber-1 encryption has no drops.
encrypt1 :: [Word8] -> [Word8] -> [Word8] -> [Word8]
encrypt1 key iv ciphertext =
    encryptDropN 0 key iv ciphertext

-- | CipherSaber-1 decryption has no drops.
decrypt1 :: [Word8] -> [Word8] -> [Word8]
decrypt1 key ciphertext =
    decryptDropN 0 key ciphertext

-- | CipherSaber-2 encryption drops 20 bytes.
encrypt :: [Word8] -> [Word8] -> [Word8] -> [Word8]
encrypt key iv ciphertext =
    encryptDropN 20 key iv ciphertext

-- | CipherSaber-2 decryption drops 20 bytes.
decrypt :: [Word8] -> [Word8] -> [Word8]
decrypt key ciphertext =
    decryptDropN 20 key ciphertext
