{-# LANGUAGE AllowAmbiguousTypes #-}
{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module Crypto.Sugar.Cipher
  ( aes128
  , aes192
  , aes256
  , blowfish
  , blowfish64
  , blowfish128
  , blowfish256
  , cast5
  ) where

import Crypto.Sugar.Internal (makeLengthExactly, makeLengthWithin)

import qualified Crypto.Cipher.AES as Cryptonite
import qualified Crypto.Cipher.Blowfish as Cryptonite
import qualified Crypto.Cipher.CAST5 as Cryptonite
import qualified Crypto.Cipher.Types as Cryptonite
import qualified Crypto.Error as Cryptonite
import qualified ByteString


aes128
  :: ByteString
  -> ByteString
  -> ByteString
aes128 =
  ctr @Cryptonite.AES128 . makeLengthExactly 16

aes192
  :: ByteString
  -> ByteString
  -> ByteString
aes192 =
  ctr @Cryptonite.AES192 . makeLengthExactly 24

aes256
  :: ByteString
  -> ByteString
  -> ByteString
aes256 =
  ctr @Cryptonite.AES256 . makeLengthExactly 32

-- not sure yet if allowing any <=56 byte keys is a bug in cryptonite,
-- https://github.com/haskell-crypto/cryptonite/issues/282

blowfish
  :: ByteString
  -> ByteString
  -> ByteString
blowfish =
  ctr @Cryptonite.Blowfish . ByteString.take 56

blowfish64
  :: ByteString
  -> ByteString
  -> ByteString
blowfish64 =
  ctr @Cryptonite.Blowfish64 . ByteString.take 56

blowfish128
  :: ByteString
  -> ByteString
  -> ByteString
blowfish128 =
  ctr @Cryptonite.Blowfish128 . ByteString.take 56

blowfish256
  :: ByteString
  -> ByteString
  -> ByteString
blowfish256 =
  ctr @Cryptonite.Blowfish256 . ByteString.take 56

cast5
  :: ByteString
  -> ByteString
  -> ByteString
cast5 =
  ctr @Cryptonite.CAST5 . makeLengthWithin 5 16

ctr
  :: forall cipher.
     Cryptonite.BlockCipher cipher
  => ByteString
  -> ByteString
  -> ByteString
ctr key =
  case Cryptonite.cipherInit @cipher key of
    Cryptonite.CryptoPassed cipher ->
      Cryptonite.ctrCombine cipher Cryptonite.nullIV
