{-# LANGUAGE CPP, FlexibleContexts #-}
-- Copyright © 2015 Bart Massey

-- | Implementation of the "CipherSaber-2" RC4 encryption
-- format. Also provides a raw RC4 keystream generator.
--
-- This work is licensed under the "MIT License".  Please
-- see the file LICENSE in the source distribution of this
-- software for license terms.
module Data.CipherSaber2 (
  ByteString, rc4, encrypt, decrypt,
  toByteString, fromByteString, ivLength )
  where

import Control.Monad
#if __GLASGOW_HASKELL__ < 710
import Control.Monad.ST.Safe
#else
import Control.Monad.ST
#endif
import Data.Array
import Data.Array.ST
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Word

-- | Number of bytes of IV to use in CipherSaber encryption/decryption
-- below. The standard CipherSaber IV size is 10 bytes.
ivLength :: Int
ivLength = 10

-- | Generate an RC4 keystream. CipherSaber recommends
-- a key of less than 54 bytes for best mixing. At most,
-- the first 256 bytes of the key are even used.
--
-- This function takes a parameter for the number of times
-- to repeat the key mixing loop ala "CipherSaber-2". It
-- should probably be set to at least 20.
-- 
-- This function takes a length of keystream to generate,
-- which is un-Haskellike but hard to avoid given the
-- strictness of 'STUArray'. An alternative would be to pass
-- the plaintext in and combine it here, but this interface
-- was chosen as "simpler". Another choice would be to leave
-- whole rc4 function in the 'ST' monad, but that seemed
-- obnoxious. The performance and usability implications of
-- these choices need to be explored.
rc4 :: Int -> Int -> ByteString -> ByteString
rc4 scheduleReps keystreamLength key =
    B.pack $ runST $ do
      let nKey = fromIntegral $ B.length key :: Word8
      let key' = listArray (0, fromIntegral (nKey - 1)) $ B.unpack key ::
                 Array Word8 Word8
      -- Create and initialize the state.
      s <- newListArray (0, 255) [0..255] :: ST s (STUArray s Word8 Word8)
      -- One step of the key schedule
      let schedStep j i = do
            si <- readArray s i
            let keyByte = key' ! (i `mod` nKey)
            let j' = j + si + keyByte
            sj <- readArray s j'
            writeArray s i sj
            writeArray s j' si
            return j'
      -- Do the key scheduling.
      foldM_ schedStep 0 $ concat $ replicate scheduleReps [0..255]
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

-- | Convert a 'String' to a 'ByteString'.
toByteString :: String -> ByteString
toByteString s = BC.pack s

-- | Convert a 'ByteString' to a 'String'.
fromByteString :: ByteString -> String
fromByteString bs = BC.unpack bs

-- | CipherSaber requires using a 10-byte initial value (IV)
-- to protect against keystream recovery. Given the key and
-- IV, this code will turn a a sequence of plaintext message
-- bytes into a sequence of ciphertext bytes.
encrypt :: Int -> ByteString -> ByteString -> ByteString -> ByteString
encrypt scheduleReps key iv plaintext
    | B.length iv == ivLength =
        let keystream = rc4 scheduleReps
                        (B.length plaintext)
                        (B.append key iv) in
        B.append iv $ B.pack $ B.zipWith xor keystream plaintext
    | otherwise = error $ "expected IV length " ++ show ivLength

-- | CipherSaber recovers the 10-byte IV from the start of the
-- ciphertext.  Given the key, this code will turn a
-- sequence of ciphertext bytes into a sequence of plaintext
-- bytes.
decrypt :: Int -> ByteString -> ByteString -> ByteString
decrypt scheduleReps key ciphertext0 =
    let (iv, ciphertext) = B.splitAt ivLength ciphertext0
        keystream = rc4 scheduleReps
                    (B.length ciphertext)
                    (B.append key iv) in
    B.pack $ B.zipWith xor keystream ciphertext
