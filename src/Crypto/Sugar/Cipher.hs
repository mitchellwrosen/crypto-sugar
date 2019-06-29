{-# OPTIONS_GHC -fno-warn-incomplete-patterns #-}

module Crypto.Sugar.Cipher
  ( aes128
  , aes192
  , aes256
  ) where

import Crypto.Sugar.Internal (makelen)

import qualified Crypto.Cipher.AES as Cryptonite
import qualified Crypto.Cipher.Types as Cryptonite
import qualified Crypto.Error as Cryptonite


aes128
  :: ByteString
  -> ByteString
  -> ByteString
aes128 key =
  case Cryptonite.cipherInit @Cryptonite.AES128 (makelen 16 key) of
    Cryptonite.CryptoPassed cipher ->
      Cryptonite.ctrCombine cipher Cryptonite.nullIV

aes192
  :: ByteString
  -> ByteString
  -> ByteString
aes192 key =
  case Cryptonite.cipherInit @Cryptonite.AES192 (makelen 24 key) of
    Cryptonite.CryptoPassed cipher ->
      Cryptonite.ctrCombine cipher Cryptonite.nullIV

aes256
  :: ByteString
  -> ByteString
  -> ByteString
aes256 key =
  case Cryptonite.cipherInit @Cryptonite.AES256 (makelen 32 key) of
    Cryptonite.CryptoPassed cipher ->
      Cryptonite.ctrCombine cipher Cryptonite.nullIV
