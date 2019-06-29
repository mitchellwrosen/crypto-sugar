{-# LANGUAGE AllowAmbiguousTypes #-}

module Crypto.Sugar.Cipher
  ( encryptAES128
  , encryptAES192
  , encryptAES256
  , encryptBlowfish
  , encryptBlowfish64
  , encryptBlowfish128
  , encryptBlowfish256
  , encryptBlowfish448
  , encryptCAST128
  , encryptCamellia
  ) where

import Crypto.Sugar.Internal (makeLengthExactly, makeLengthWithin, pad)

import Control.Exception (throw)
import Control.Monad.Morph (hoist)
import Control.Monad.Trans.State.Strict
import Data.Functor.Of (Of(..))

import qualified Crypto.Cipher.AES as Cryptonite
import qualified Crypto.Cipher.Blowfish as Cryptonite
import qualified Crypto.Cipher.CAST5 as Cryptonite
import qualified Crypto.Cipher.Camellia as Cryptonite
import qualified Crypto.Cipher.Types as Cryptonite
import qualified Crypto.Error as Cryptonite
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Streaming as Q
import qualified Data.ByteString.Streaming.Internal as Q (ByteString(..))


data Cipher
  = AES128
  | AES192
  | AES256
  | Blowfish
  | Blowfish64
  | Blowfish128
  | Blowfish256
  | Blowfish448
  | CAST128
  | Camellia
  deriving stock (Eq, Show)

withCipher
  :: forall m r s.
     Monad m
  => Cipher
  -> ByteString
  -> ByteString
  -> Q.ByteString m r
  -> ( forall cipher.
       Cryptonite.BlockCipher cipher
    => cipher
    -> Cryptonite.IV cipher
    -> Q.ByteString m r
    -> s
     )
  -> s
withCipher cipher key iv inputStream k =
  case cipher of
    AES128      -> go @Cryptonite.AES128      (makeLengthExactly 16)
    AES192      -> go @Cryptonite.AES192      (makeLengthExactly 24)
    AES256      -> go @Cryptonite.AES256      (makeLengthExactly 32)
    -- not sure yet if allowing any <=56 byte keys is a bug in cryptonite,
    -- https://github.com/haskell-crypto/cryptonite/issues/282
    Blowfish    -> go @Cryptonite.Blowfish    (ByteString.take 56)
    Blowfish64  -> go @Cryptonite.Blowfish64  (ByteString.take 56)
    Blowfish128 -> go @Cryptonite.Blowfish128 (ByteString.take 56)
    Blowfish256 -> go @Cryptonite.Blowfish256 (ByteString.take 56)
    Blowfish448 -> go @Cryptonite.Blowfish448 (ByteString.take 56)
    CAST128     -> go @Cryptonite.CAST5       (makeLengthWithin 5 16)
    Camellia    -> go @Cryptonite.Camellia128 (makeLengthExactly 16)

  where
    go
      :: forall cipher.
         Cryptonite.BlockCipher cipher
      => (ByteString -> ByteString)
      -> s
    go adjustKey =
      k
        cryptoniteCipher
        (makeIV @cipher (makeLengthExactly blockSize iv))
        (chunksOf (fromIntegral blockSize) inputStream)

      where
        cryptoniteCipher :: cipher
        cryptoniteCipher =
          cipherInit @cipher (adjustKey key)

        blockSize :: Int
        blockSize =
          Cryptonite.blockSize cryptoniteCipher

-- | Initialize a cipher.
--
-- Precondition: the key is an appropriate length for the cipher.
cipherInit
  :: forall cipher.
     Cryptonite.Cipher cipher
  => ByteString
  -> cipher
cipherInit key =
  case Cryptonite.cipherInit @cipher (makeLengthExactly 16 key) of
    Cryptonite.CryptoPassed cipher ->
      cipher

    Cryptonite.CryptoFailed x ->
      throw x

-- | Make an IV.
--
-- Precondition: the iv is an appropriate length for the cipher.
makeIV
  :: forall cipher.
     Cryptonite.BlockCipher cipher
  => ByteString
  -> Cryptonite.IV cipher
makeIV bytes =
  fromJust (Cryptonite.makeIV @_ @cipher bytes)

-- | Encrypt a stream of bytes in Cipher Block Chaining (CBC) mode.
encrypt
  :: Monad m
  => Cipher
  -> ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encrypt cipher key iv inputStream =
  withCipher cipher key iv inputStream encrypt_

encrypt_
  :: ( Cryptonite.BlockCipher cipher
     , Monad m
     )
  => cipher
  -> Cryptonite.IV cipher
  -> Q.ByteString m r
  -> Q.ByteString m r
encrypt_ cipher iv =
  (`evalStateT` iv)
    . Q.distribute
    . Q.chunkMapM (encryptChunk cipher)
    . hoist lift

encryptChunk
  :: forall cipher m.
     ( Cryptonite.BlockCipher cipher
     , Monad m
     )
  => cipher
  -> ByteString
  -> StateT (Cryptonite.IV cipher) m ByteString
encryptChunk cipher plaintext = do
  iv <- get

  let
    ciphertext :: ByteString
    ciphertext =
      Cryptonite.ecbEncrypt cipher (ByteArray.xor iv paddedPlaintext)

  -- Annoying that IV constructor is not exposed
  put (fromJust (Cryptonite.makeIV ciphertext))

  pure ciphertext

  where
    paddedPlaintext :: ByteString
    paddedPlaintext =
      pad blockSize plaintext

    blockSize :: Int
    blockSize =
      Cryptonite.blockSize cipher

chunksOf
  :: Monad m
  => Int64
  -> Q.ByteString m r
  -> Q.ByteString m r
chunksOf n input = do
  x :> xs <- lift (Q.toStrict (Q.splitAt n input))
  Q.chunk x
  if ByteString.length x < fromIntegral n
    then xs
    else chunksOf n xs

encryptAES128
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptAES128 =
  encrypt AES128

encryptAES192
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptAES192 =
  encrypt AES192

encryptAES256
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptAES256 =
  encrypt AES256

encryptBlowfish
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptBlowfish =
  encrypt Blowfish

encryptBlowfish64
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptBlowfish64 =
  encrypt Blowfish64

encryptBlowfish128
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptBlowfish128 =
  encrypt Blowfish128

encryptBlowfish256
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptBlowfish256 =
  encrypt Blowfish256

encryptBlowfish448
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptBlowfish448 =
  encrypt Blowfish448

-- | https://en.wikipedia.org/wiki/CAST-128
encryptCAST128
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptCAST128 =
  encrypt CAST128

-- | https://en.wikipedia.org/wiki/Camellia_(cipher)
encryptCamellia
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptCamellia =
  encrypt Camellia
