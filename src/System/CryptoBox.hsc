-- Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TupleSections              #-}

module System.CryptoBox
    ( Result    (..)
    , SID       (..)
    , Prekey    (..)
    , PrekeyId  (..)
    , Vector
    , Box
    , Session
    , withVector
    , copyBytes
    , open
    , newPrekey
    , isPrekey
    , session
    , sessionFromPrekey
    , sessionFromMessage
    , close
    , save
    , delete
    , encrypt
    , decrypt
    , remoteFingerprint
    , localFingerprint
    , randomBytes
    ) where

import Control.Applicative
import Control.Concurrent
import Control.Exception (finally)
import Data.ByteString (ByteString)
import Data.Hashable
import Data.HashMap.Strict (HashMap)
import Data.IORef
import Foreign hiding (void, copyBytes)
import Foreign.C
import Prelude

import qualified Data.ByteString        as Bytes
import qualified Data.ByteString.Unsafe as Bytes
import qualified Data.HashMap.Strict    as Map

#include <cbox.h>

data Result a
    = Success !a
    | StorageError
    | NoSession
    | DecodeError
    | RemoteIdentityChanged
    | InvalidSignature
    | InvalidMessage
    | DuplicateMessage
    | TooDistantFuture
    | OutdatedMessage
    | Utf8Error
    | NulError
    | EncodeError
    | IdentityError
    | NoPrekey
    | Panic
    | Unknown !Int
    deriving (Eq, Ord, Show, Functor)

data Box = Box
    { sessions  :: !(IORef (HashMap SID Session))
    , cboxmutex :: !(MVar ())
    , cboxptr   :: !(ForeignPtr ())
    }

data Session = Session
    { sessid    :: !SID
    , sessmutex :: !(MVar ())
    , sessptr   :: !(ForeignPtr ())
    }

newtype Vector   = Vector   { vec      :: ForeignPtr () }
newtype Prekey   = Prekey   { prekey   :: Vector        }
newtype PrekeyId = PrekeyId { prekeyId :: Word16        }
newtype SID      = SID      { sid      :: ByteString    } deriving (Eq, Hashable)

instance Show Vector  where show = const "Vector"
instance Show Box     where show = const "Box"
instance Show Prekey  where show = const "Prekey"
instance Show Session where show = const "Session"
instance Show SID     where show = const "SID"

open :: FilePath -> IO (Result Box)
open p = withCString p $ \cs  ->
    alloca $ \ptr ->
    ifSuccess (cbox_file_open cs ptr) $
        Box <$> newIORef Map.empty
            <*> newMVar ()
            <*> (newForeignPtr cbox_close =<< peek ptr)

newPrekey :: Box -> Word16 -> IO (Result Prekey)
newPrekey b i = withMutex (cboxmutex b) $
    withCryptoBox b $ \cb ->
    alloca          $ \v ->
    ifSuccess (cbox_new_prekey cb (fromIntegral i) v) $
        Prekey <$> (newVector =<< peek v)

randomBytes :: Box -> Word32 -> IO (Result Vector)
randomBytes b n = withCryptoBox b $ \cb -> -- No need for mutex.
    alloca $ \v ->
    ifSuccess (cbox_random_bytes cb (fromIntegral n) v) $
        newVector =<< peek v

session :: Box -> SID -> IO (Result Session)
session b i = withMutex (cboxmutex b) $
    maybe fresh (return . Success) =<< Map.lookup i <$> readIORef (sessions b)
  where
    fresh = withCryptoBox b        $ \cb ->
        Bytes.useAsCString (sid i) $ \ip ->
        alloca                     $ \sp ->
        ifSuccess (cbox_session_load cb ip sp) $ do
            s <- Session i <$> newMVar () <*> (newForeignPtr cbox_session_close =<< peek sp)
            modifyIORef (sessions b) (Map.insert i s)
            return s

close :: Box -> Session -> IO ()
close b s = withMutex (cboxmutex b) $
    modifyIORef (sessions b) (Map.delete (sessid s))
        `finally`
    withMutex (sessmutex s) (finalizeForeignPtr (sessptr s))

delete :: Box -> SID -> IO (Result ())
delete b i = withMutex (cboxmutex b) $ do
    modifyIORef (sessions b) (Map.delete i)
    withCryptoBox b $ \cb ->
        Bytes.useAsCString (sid i) $ \ip ->
        ifSuccess (cbox_session_delete cb ip) (pure ())

isPrekey :: ByteString -> IO (Result PrekeyId)
isPrekey b =
    Bytes.unsafeUseAsCStringLen b $ \(ptr, len) ->
    alloca                        $ \result ->
    ifSuccess (cbox_is_prekey (castPtr ptr) (fromIntegral len) result)
        (PrekeyId <$> peek result)

sessionFromPrekey :: Box -> SID -> ByteString -> IO (Result Session)
sessionFromPrekey b i p = withMutex (cboxmutex b) $
    maybe fresh (return . Success) =<< Map.lookup i <$> readIORef (sessions b)
  where
    fresh = withCryptoBox b           $ \cb ->
        Bytes.useAsCString (sid i)    $ \ip ->
        Bytes.unsafeUseAsCStringLen p $ \(pp, pl) ->
        alloca                        $ \sp ->
        ifSuccess (cbox_session_init_from_prekey cb ip (castPtr pp) (fromIntegral pl) sp) $ do
            m <- newMVar ()
            x <- newForeignPtr cbox_session_close =<< peek sp
            return (Session i m x)

sessionFromMessage :: Box -> SID -> ByteString -> IO (Result (Session, Vector))
sessionFromMessage b i m = withMutex (cboxmutex b) $
    maybe fresh existing =<< Map.lookup i <$> readIORef (sessions b)
  where
    fresh = withCryptoBox b           $ \cb ->
        Bytes.useAsCString (sid i)    $ \ip ->
        Bytes.unsafeUseAsCStringLen m $ \(pp, pl) ->
        alloca                        $ \sp ->
        alloca                        $ \vp ->
        ifSuccess (cbox_session_init_from_message cb ip (castPtr pp) (fromIntegral pl) sp vp) $ do
            l <- newMVar ()
            x <- newForeignPtr cbox_session_close =<< peek sp
            v <- newVector =<< peek vp
            return (Session i l x, v)

    existing s = fmap (s, ) <$> decrypt s m

save :: Box -> Session -> IO (Result ())
save b s = withMutex (sessmutex s) $
    withCryptoBox b $ \cb ->
    withSession s   $ \sp ->
    ifSuccess (cbox_session_save cb sp) (pure ())

encrypt :: Session -> ByteString -> IO (Result Vector)
encrypt s plain = withMutex (sessmutex s) $
    withSession s                     $ \sp ->
    Bytes.unsafeUseAsCStringLen plain $ \(pp, pl) ->
    alloca                            $ \vp -> do
    ifSuccess (cbox_encrypt sp (castPtr pp) (fromIntegral pl) vp) $
        newVector =<< peek vp

decrypt :: Session -> ByteString -> IO (Result Vector)
decrypt s cipher = withMutex (sessmutex s) $
    withSession s                      $ \sp ->
    Bytes.unsafeUseAsCStringLen cipher $ \(pp, pl) ->
    alloca                             $ \vp ->
    ifSuccess (cbox_decrypt sp (castPtr pp) (fromIntegral pl) vp) $
        newVector =<< peek vp

remoteFingerprint :: Session -> IO (Result Vector)
remoteFingerprint s = withMutex (sessmutex s) $
    withSession s $ \sp ->
    alloca        $ \vp -> do
    ifSuccess (cbox_fingerprint_remote sp vp) $ newVector =<< peek vp

localFingerprint :: Box -> IO (Result Vector)
localFingerprint b = withMutex (cboxmutex b) $
    withCryptoBox b $ \cb ->
    alloca          $ \vp -> do
    ifSuccess (cbox_fingerprint_local cb vp) $ newVector =<< peek vp

withVector :: Vector -> (ByteString -> IO a) -> IO a
withVector v f = withForeignPtr (vec v) $ \vp -> do
    b <- castPtr <$> cbox_vec_data vp
    n <- fromIntegral <$> cbox_vec_len vp
    Bytes.unsafePackCStringLen (b, n) >>= \bytes -> do
        x <- f bytes
        x `seq` return x

copyBytes :: Vector -> IO ByteString
copyBytes v = withVector v (pure . Bytes.copy)

-- Helpers ------------------------------------------------------------------

ifSuccess :: (Functor m, Monad m) => m CInt -> m a -> m (Result a)
ifSuccess a b = do
    r <- a
    if r == success then Success <$> b else return (cboxError r)

withMutex :: MVar () -> IO a -> IO a
withMutex m a = withMVar m (const a)

newVector :: CBoxVec -> IO Vector
newVector ptr = Vector <$> newForeignPtr cbox_vec_free ptr

withCryptoBox :: Box -> (Ptr () -> IO a) -> IO a
withCryptoBox b = withForeignPtr (cboxptr b)

withSession :: Session -> (Ptr () -> IO a) -> IO a
withSession s = withForeignPtr (sessptr s)

cboxError :: CInt -> Result a
cboxError (#const CBOX_STORAGE_ERROR)           = StorageError
cboxError (#const CBOX_SESSION_NOT_FOUND)       = NoSession
cboxError (#const CBOX_DECODE_ERROR)            = DecodeError
cboxError (#const CBOX_REMOTE_IDENTITY_CHANGED) = RemoteIdentityChanged
cboxError (#const CBOX_INVALID_SIGNATURE)       = InvalidSignature
cboxError (#const CBOX_INVALID_MESSAGE)         = InvalidMessage
cboxError (#const CBOX_DUPLICATE_MESSAGE)       = DuplicateMessage
cboxError (#const CBOX_TOO_DISTANT_FUTURE)      = TooDistantFuture
cboxError (#const CBOX_OUTDATED_MESSAGE)        = OutdatedMessage
cboxError (#const CBOX_UTF8_ERROR)              = Utf8Error
cboxError (#const CBOX_NUL_ERROR)               = NulError
cboxError (#const CBOX_ENCODE_ERROR)            = EncodeError
cboxError (#const CBOX_IDENTITY_ERROR)          = IdentityError
cboxError (#const CBOX_PREKEY_NOT_FOUND)        = NoPrekey
cboxError (#const CBOX_PANIC)                   = Panic
cboxError cint                                  = Unknown (fromIntegral cint)

success :: CInt
success = #const CBOX_SUCCESS

type CBox        = Ptr ()
type CBoxVec     = Ptr ()
type CBoxSession = Ptr ()
type CPrekey     = Ptr CUChar
type Cipher      = Ptr CUChar

-- Foreign Declarations -----------------------------------------------------

foreign import ccall unsafe "cbox.h cbox_vec_data"
    cbox_vec_data :: CBoxVec -> IO (Ptr CUChar)

foreign import ccall unsafe "cbox.h cbox_vec_len"
    cbox_vec_len :: CBoxVec -> IO CUInt

foreign import ccall "cbox.h &cbox_vec_free"
    cbox_vec_free :: FunPtr (CBoxVec -> IO ())

foreign import ccall unsafe "cbox.h cbox_file_open"
    cbox_file_open :: CString -> Ptr CBox -> IO CInt

foreign import ccall "cbox.h &cbox_close"
    cbox_close :: FunPtr (CBox  -> IO ())

foreign import ccall unsafe "cbox.h cbox_random_bytes"
    cbox_random_bytes :: CBox -> CUInt -> Ptr CBoxVec -> IO CInt

foreign import ccall unsafe "cbox.h cbox_new_prekey"
    cbox_new_prekey :: CBox -> CUShort -> Ptr CBoxVec -> IO CInt

foreign import ccall unsafe "cbox.h cbox_session_init_from_prekey"
    cbox_session_init_from_prekey :: CBox
                                  -> CString
                                  -> CPrekey
                                  -> CUInt
                                  -> Ptr CBoxSession
                                  -> IO CInt

foreign import ccall unsafe "cbox.h cbox_session_init_from_message"
    cbox_session_init_from_message :: CBox
                                   -> CString
                                   -> Cipher
                                   -> CUInt
                                   -> Ptr CBoxSession
                                   -> Ptr CBoxVec
                                   -> IO CInt

foreign import ccall unsafe "cbox.h cbox_session_load"
    cbox_session_load :: CBox -> CString -> Ptr CBoxSession -> IO CInt

foreign import ccall unsafe "cbox.h cbox_session_save"
    cbox_session_save :: CBox -> CBoxSession -> IO CInt

foreign import ccall "cbox.h &cbox_session_close"
    cbox_session_close :: FunPtr (CBoxSession  -> IO ())

foreign import ccall "cbox.h cbox_session_delete"
    cbox_session_delete :: CBoxSession -> CString -> IO CInt

foreign import ccall unsafe "cbox.h cbox_encrypt"
    cbox_encrypt :: CBoxSession -> Ptr Word8 -> CUInt -> Ptr CBoxVec -> IO CInt

foreign import ccall unsafe "cbox.h cbox_decrypt"
    cbox_decrypt :: CBoxSession -> Ptr Word8 -> CUInt -> Ptr CBoxVec -> IO CInt

foreign import ccall unsafe "cbox.h cbox_fingerprint_local"
    cbox_fingerprint_local :: CBox -> Ptr CBoxVec -> IO CInt

foreign import ccall unsafe "cbox.h cbox_fingerprint_remote"
    cbox_fingerprint_remote :: CBoxSession -> Ptr CBoxVec -> IO CInt

foreign import ccall unsafe "cbox.h cbox_is_prekey"
    cbox_is_prekey :: Ptr Word8 -> CUInt -> Ptr Word16 -> IO CInt
