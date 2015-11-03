-- Copyright © 2015 Bart Massey
-- [This work is licensed under the "MIT License"]
-- Please see the file LICENSE in the source
-- distribution of this software for license terms.

-- CipherSaber driver for UNIX-like systems with "/dev/random".

import Control.Monad
import qualified Data.ByteString.Char8 as BS
import System.Console.ParseArgs
import System.IO

import CipherSaber2

data ArgInd = ArgEncrypt | ArgDecrypt | ArgKey | ArgReps
     deriving (Ord, Eq, Show)

argd :: [ Arg ArgInd ]
argd = [
  Arg {
     argIndex = ArgEncrypt,
     argName = Just "encrypt",
     argAbbr = Just 'e',
     argData = Nothing,
     argDesc = "Use decryption mode."
  },
  Arg {
     argIndex = ArgDecrypt,
     argName = Just "decrypt",
     argAbbr = Just 'd',
     argData = Nothing,
     argDesc = "Use encryption mode."
  },
  Arg {
     argIndex = ArgReps,
     argName = Just "reps",
     argAbbr = Just 'r',
     argData = argDataDefaulted "number" ArgtypeInt 20,
     argDesc = "Number of key scheduling reps " ++
               "(use 1 for CipherSaber-1, default 20)."
  },
  Arg {
     argIndex = ArgKey,
     argName = Nothing,
     argAbbr = Nothing,
     argData = argDataRequired "key" ArgtypeString,
     argDesc = "Encryption or decryption key."
  } ]

makeIV :: IO BS.ByteString
makeIV = 
  withBinaryFile "/dev/urandom" ReadMode $ \h ->
  do
    hSetBuffering h NoBuffering
    BS.hGet h 10

main :: IO ()
main = do
  hSetBinaryMode stdin True
  hSetBinaryMode stdout True
  argv <- parseArgsIO ArgsComplete argd
  let k = toByteString $ getRequiredArg argv ArgKey
  let e = gotArg argv ArgEncrypt
  let d = gotArg argv ArgDecrypt
  let r = getRequiredArg argv ArgReps :: Int
  unless ((e && not d) || (d && not e)) $
    usageError argv "Exactly one of -e or -d is required."
  case e of
    True -> do
      iv <- makeIV
      BS.interact (encrypt r k iv)
    False -> do
      BS.interact (decrypt r k)
