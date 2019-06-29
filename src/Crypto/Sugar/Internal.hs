module Crypto.Sugar.Internal
  ( makelen
  ) where

import qualified ByteString


makelen :: Int -> ByteString -> ByteString
makelen n (ByteString.take n -> bytes) =
  if padlen > 0
    then bytes <> ByteString.replicate padlen 0
    else bytes

  where
    padlen :: Int
    padlen =
      n - ByteString.length bytes
