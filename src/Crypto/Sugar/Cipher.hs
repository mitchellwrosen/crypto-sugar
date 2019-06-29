{-# LANGUAGE AllowAmbiguousTypes #-}

module Crypto.Sugar.Cipher
  ( -- * AES
    encryptAES128
  , encryptAES192
  , encryptAES256
  , decryptAES128
  , decryptAES192
  , decryptAES256
    -- * Blowfish
  , encryptBlowfish
  , encryptBlowfish64
  , encryptBlowfish128
  , encryptBlowfish256
  , encryptBlowfish448
  , decryptBlowfish
  , decryptBlowfish64
  , decryptBlowfish128
  , decryptBlowfish256
  , decryptBlowfish448
    -- * CAST-128
  , encryptCAST128
  , decryptCAST128
    -- * Camellia
  , encryptCamellia
  , decryptCamellia
    -- * DES
  , encryptDES
  , decryptDES
    -- * 3DES
  , encrypt3DES
  , decrypt3DES
    -- * Twofish
  , encryptTwofish128
  , encryptTwofish192
  , encryptTwofish256
  , decryptTwofish128
  , decryptTwofish192
  , decryptTwofish256
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
import qualified Crypto.Cipher.DES as Cryptonite
import qualified Crypto.Cipher.TripleDES as Cryptonite
import qualified Crypto.Cipher.Twofish as Cryptonite
import qualified Crypto.Cipher.Types as Cryptonite
import qualified Crypto.Error as Cryptonite
import qualified Data.ByteArray as ByteArray
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Streaming as Q
import qualified Data.ByteString.Streaming.Internal as Q (ByteString(..))


-- TODO ChaCha, RC4, Salsa, XSalsa

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
  | DES
  | TDES
  | Twofish128
  | Twofish192
  | Twofish256
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
    DES         -> go @Cryptonite.DES         (makeLengthExactly 8)
    TDES        -> go @Cryptonite.DES_EDE3    (makeLengthExactly 24)
    Twofish128  -> go @Cryptonite.Twofish128  (makeLengthExactly 16)
    Twofish192  -> go @Cryptonite.Twofish192  (makeLengthExactly 24)
    Twofish256  -> go @Cryptonite.Twofish256  (makeLengthExactly 32)

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

-- | Decrypt a stream of bytes in Cipher Block Chaining (CBC) mode.
decrypt
  :: Monad m
  => Cipher
  -> ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decrypt cipher key iv inputStream =
  withCipher cipher key iv inputStream decrypt_

decrypt_
  :: ( Cryptonite.BlockCipher cipher
     , Monad m
     )
  => cipher
  -> Cryptonite.IV cipher
  -> Q.ByteString m r
  -> Q.ByteString m r
decrypt_ cipher iv =
  (`evalStateT` iv)
    . Q.distribute
    . Q.chunkMapM (decryptChunk cipher)
    . hoist lift

decryptChunk
  :: forall cipher m.
     ( Cryptonite.BlockCipher cipher
     , Monad m
     )
  => cipher
  -> ByteString
  -> StateT (Cryptonite.IV cipher) m ByteString
decryptChunk cipher ciphertext = do
  iv <- get

  let
    plaintext :: ByteString
    plaintext =
      ByteArray.xor iv (Cryptonite.ecbDecrypt cipher paddedCiphertext)

  -- Annoying that IV constructor is not exposed
  put (fromJust (Cryptonite.makeIV ciphertext))

  pure plaintext

  where
    paddedCiphertext :: ByteString
    paddedCiphertext =
      pad blockSize ciphertext

    blockSize :: Int
    blockSize =
      Cryptonite.blockSize cipher

-- | Break a byte stream into chunks of the given length. The last chunk may be
-- short.
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


--------------------------------------------------------------------------------
-- Smart constructors
--------------------------------------------------------------------------------

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

encryptDES
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptDES =
  encrypt DES

encrypt3DES
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encrypt3DES =
  encrypt TDES

encryptTwofish128
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptTwofish128 =
  encrypt Twofish128

encryptTwofish192
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptTwofish192 =
  encrypt Twofish192

encryptTwofish256
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
encryptTwofish256 =
  encrypt Twofish256

decryptAES128
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptAES128 =
  decrypt AES128

decryptAES192
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptAES192 =
  decrypt AES192

decryptAES256
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptAES256 =
  decrypt AES256

decryptBlowfish
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptBlowfish =
  decrypt Blowfish

decryptBlowfish64
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptBlowfish64 =
  decrypt Blowfish64

decryptBlowfish128
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptBlowfish128 =
  decrypt Blowfish128

decryptBlowfish256
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptBlowfish256 =
  decrypt Blowfish256

decryptBlowfish448
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptBlowfish448 =
  decrypt Blowfish448

-- | https://en.wikipedia.org/wiki/CAST-128
decryptCAST128
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptCAST128 =
  decrypt CAST128

-- | https://en.wikipedia.org/wiki/Camellia_(cipher)
decryptCamellia
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptCamellia =
  decrypt Camellia

decryptDES
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptDES =
  decrypt DES

decrypt3DES
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decrypt3DES =
  decrypt TDES

decryptTwofish128
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptTwofish128 =
  decrypt Twofish128

decryptTwofish192
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptTwofish192 =
  decrypt Twofish192

decryptTwofish256
  :: Monad m
  => ByteString
  -> ByteString
  -> Q.ByteString m r
  -> Q.ByteString m r
decryptTwofish256 =
  decrypt Twofish256
