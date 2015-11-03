-- Copyright © 2015 Bart Massey
-- [This work is licensed under the "MIT License"]
-- Please see the file LICENSE in the source
-- distribution of this software for license terms.

-- CipherSaber driver for UNIX-like systems with "/dev/random".

import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Char
import Data.Word
import System.Console.ParseArgs
import System.IO

import CipherSaber2

data ArgInd = ArgEncrypt | ArgDecrypt | ArgKey | ArgVersion
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
     argIndex = ArgKey,
     argName = Nothing,
     argAbbr = Nothing,
     argData = argDataRequired "key" ArgtypeString,
     argDesc = "Encryption or decryption key."
  },
  Arg {
     argIndex = ArgVersion,
     argName = Just "version",
     argAbbr = Just 'v',
     argData = argDataDefaulted "number" ArgtypeInt 2,
     argDesc = "CipherSaber version (1 or 2, default 1)."
  } ]

makeIV :: IO [Word8]
makeIV = 
  withBinaryFile "/dev/urandom" ReadMode $ \h ->
  do
    hSetBuffering h NoBuffering
    ivs <- BS.hGet h 10
    BS.hPut stdout ivs
    return $ BS.unpack ivs

main :: IO ()
main = do
  hSetBinaryMode stdin True
  hSetBinaryMode stdout True
  argv <- parseArgsIO ArgsComplete argd
  let k = toBytes $ getRequiredArg argv ArgKey
  let e = gotArg argv ArgEncrypt
  let d = gotArg argv ArgDecrypt
  let v = getRequiredArg argv ArgVersion :: Int
  unless ((e && not d) || (d && not e)) $
    usageError argv "Exactly one of -e or -d is required."
  let (ec, dc) =
          case v of
            1 -> (encrypt1, decrypt1)
            2 -> (encrypt, decrypt)
            _ -> usageError argv "Unknown CipherSaber version."
  case e of
    True -> do
      iv <- makeIV
      BS.interact (BS.pack . ec k iv . map (fromIntegral . ord) . BSC.unpack)
    False -> do
      BS.interact (BSC.pack . map (chr . fromIntegral) . dc k . BS.unpack)
