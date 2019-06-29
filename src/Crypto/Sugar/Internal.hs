module Crypto.Sugar.Internal
  ( makeLengthExactly
  , makeLengthWithin
  ) where

import qualified ByteString


makeLengthExactly :: Int -> ByteString -> ByteString
makeLengthExactly n =
  makeLengthWithin n n

makeLengthWithin :: Int -> Int -> ByteString -> ByteString
makeLengthWithin n m =
  pad n . ByteString.take m

-- | Pad to at least the given length.
pad :: Int -> ByteString -> ByteString
pad n bytes =
  if padlen > 0
    then bytes <> ByteString.replicate padlen 0
    else bytes

  where
    padlen :: Int
    padlen =
      n - ByteString.length bytes
