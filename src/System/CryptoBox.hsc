-- This Source Code Form is subject to the terms of
-- the Mozilla Public License, v. 2.0. If a copy of
-- the MPL was not distributed with this file, You
-- can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DeriveFunctor              #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TupleSections              #-}

module System.CryptoBox
    ( Result    (..)
    , SID       (..)
    , Prekey    (..)
    , Vector
    , Box
    , Session
    , withVector
    , copyBytes
    , open
    , newPrekey
    , session
    , sessionId
    , sessionFromPrekey
    , sessionFromMessage
    , closeSession
    , save
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

newtype Vector = Vector { vec    :: ForeignPtr () }
newtype Prekey = Prekey { prekey :: Vector        }
newtype SID    = SID    { sid    :: ByteString    } deriving (Eq, Hashable)

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

randomBytes :: Box -> Word32 -> IO Vector
randomBytes b n = withCryptoBox b $ \cb -> -- No need for mutex.
    cbox_random_bytes cb (fromIntegral n) >>= newVector

session :: Box -> SID -> IO (Result Session)
session b i = withMutex (cboxmutex b) $
    maybe fresh (return . Success) =<< Map.lookup i <$> readIORef (sessions b)
  where
    fresh = withCryptoBox b        $ \cb ->
        Bytes.useAsCString (sid i) $ \ip ->
        alloca                     $ \sp ->
        ifSuccess (cbox_session_get cb ip sp) $ do
            s <- Session i <$> newMVar () <*> (newForeignPtr cbox_session_close =<< peek sp)
            modifyIORef (sessions b) (Map.insert i s)
            return s

closeSession :: Box -> Session -> IO ()
closeSession b s = withMutex (cboxmutex b) $
    modifyIORef (sessions b) (Map.delete (sessid s))
        `finally`
    withMutex (sessmutex s) (finalizeForeignPtr (sessptr s))

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

save :: Session -> IO (Result ())
save s = withMutex (sessmutex s) $ withSession s $ \sp ->
    ifSuccess (cbox_session_save sp) (pure ())

sessionId :: Session -> IO (Result SID)
sessionId s = withMutex (sessmutex s) $ withSession s $ \sp -> do
    i <- cbox_session_id sp
    Success . SID <$> Bytes.unsafePackCString i

encrypt :: Session -> ByteString -> IO Vector
encrypt s plain = withMutex (sessmutex s) $
    withSession s                     $ \sp ->
    Bytes.unsafeUseAsCStringLen plain $ \(pp, pl) ->
    alloca                            $ \vp -> do
    cbox_encrypt sp (castPtr pp) (fromIntegral pl) vp
    newVector =<< peek vp

decrypt :: Session -> ByteString -> IO (Result Vector)
decrypt s cipher = withMutex (sessmutex s) $
    withSession s                      $ \sp ->
    Bytes.unsafeUseAsCStringLen cipher $ \(pp, pl) ->
    alloca                             $ \vp ->
    ifSuccess (cbox_decrypt sp (castPtr pp) (fromIntegral pl) vp) $
        newVector =<< peek vp

remoteFingerprint :: Session -> IO Vector
remoteFingerprint s = withMutex (sessmutex s) $
    withSession s $ \sp ->
    alloca        $ \vp -> do
    cbox_fingerprint_remote sp vp
    newVector =<< peek vp

localFingerprint :: Box -> IO Vector
localFingerprint b = withMutex (cboxmutex b) $
    withCryptoBox b $ \cb ->
    alloca          $ \vp -> do
    cbox_fingerprint_local cb vp
    newVector =<< peek vp

withVector :: Vector -> (ByteString -> IO a) -> IO a
withVector v f = withForeignPtr (vec v) $ \vp -> do
    b <- castPtr <$> cbox_vec_data vp
    n <- fromIntegral <$> cbox_vec_len vp
    Bytes.unsafePackCStringLen (b, n) >>= f

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
cboxError (#const CBOX_NO_SESSION)              = NoSession
cboxError (#const CBOX_DECODE_ERROR)            = DecodeError
cboxError (#const CBOX_REMOTE_IDENTITY_CHANGED) = RemoteIdentityChanged
cboxError (#const CBOX_INVALID_SIGNATURE)       = InvalidSignature
cboxError (#const CBOX_INVALID_MESSAGE)         = InvalidSignature
cboxError (#const CBOX_DUPLICATE_MESSAGE)       = DuplicateMessage
cboxError (#const CBOX_TOO_DISTANT_FUTURE)      = TooDistantFuture
cboxError (#const CBOX_OUTDATED_MESSAGE)        = OutdatedMessage
cboxError (#const CBOX_UTF8_ERROR)              = Utf8Error
cboxError (#const CBOX_NUL_ERROR)               = NulError
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
    cbox_random_bytes :: CBox -> CUInt -> IO CBoxVec

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

foreign import ccall unsafe "cbox.h cbox_session_get"
    cbox_session_get :: CBox -> CString -> Ptr CBoxSession -> IO CInt

foreign import ccall unsafe "cbox.h cbox_session_save"
    cbox_session_save :: CBoxSession -> IO CInt

foreign import ccall unsafe "cbox.h cbox_session_id"
    cbox_session_id :: CBoxSession -> IO CString

foreign import ccall "cbox.h &cbox_session_close"
    cbox_session_close :: FunPtr (CBoxSession  -> IO ())

foreign import ccall unsafe "cbox.h cbox_encrypt"
    cbox_encrypt :: CBoxSession -> Ptr Word8 -> CUInt -> Ptr CBoxVec -> IO ()

foreign import ccall unsafe "cbox.h cbox_decrypt"
    cbox_decrypt :: CBoxSession -> Ptr Word8 -> CUInt -> Ptr CBoxVec -> IO CInt

foreign import ccall unsafe "cbox.h cbox_fingerprint_local"
    cbox_fingerprint_local :: CBox -> Ptr CBoxVec -> IO ()

foreign import ccall unsafe "cbox.h cbox_fingerprint_remote"
    cbox_fingerprint_remote :: CBoxSession -> Ptr CBoxVec -> IO ()
