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
  ) where

import Crypto.Sugar.Internal (makeLengthExactly)

import qualified Crypto.Cipher.AES as Cryptonite
import qualified Crypto.Cipher.Blowfish as Cryptonite
import qualified Crypto.Cipher.Types as Cryptonite
import qualified Crypto.Error as Cryptonite
import qualified ByteString


aes128
  :: ByteString
  -> ByteString
  -> ByteString
aes128 key =
  case Cryptonite.cipherInit @Cryptonite.AES128 (makeLengthExactly 16 key) of
    Cryptonite.CryptoPassed cipher ->
      Cryptonite.ctrCombine cipher Cryptonite.nullIV

aes192
  :: ByteString
  -> ByteString
  -> ByteString
aes192 key =
  ctr @Cryptonite.AES192 (makeLengthExactly 24 key)

aes256
  :: ByteString
  -> ByteString
  -> ByteString
aes256 key =
  ctr @Cryptonite.AES256 (makeLengthExactly 32 key)

blowfish
  :: ByteString
  -> ByteString
  -> ByteString
blowfish key =
  ctr @Cryptonite.Blowfish (ByteString.take 56 key)

blowfish64
  :: ByteString
  -> ByteString
  -> ByteString
blowfish64 key =
  ctr @Cryptonite.Blowfish64 (ByteString.take 56 key)

blowfish128
  :: ByteString
  -> ByteString
  -> ByteString
blowfish128 key =
  ctr @Cryptonite.Blowfish128 (ByteString.take 56 key)

blowfish256
  :: ByteString
  -> ByteString
  -> ByteString
blowfish256 key =
  ctr @Cryptonite.Blowfish256 (ByteString.take 56 key)

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
