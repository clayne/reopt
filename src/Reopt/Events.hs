{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Reopt.Events
  ( ReoptLogEvent(..)
  , ReoptFailureTag(..)
  , ReoptStep(..)
  , ReoptStepTag(..)
  , ReoptEventSeverity(..)
  , isErrorEvent
    -- * Statistics
  , ReoptStats(..)
  , FnRecoveryResult(..)
  , initReoptStats
  , reportStats
  , renderFnStats
  , renderAllFailures
  , incFnResult
  , incFnFailure
  , mergeFnFailures
  , statsHeader
  , statsRows
  , ppFnEntry
  , segoffWord64
  , ppSegOff
  ) where

import           Control.Monad (when)
import qualified Data.ByteString.Char8 as BS
import           Data.List (intercalate, foldl')
import           Data.Map (Map)
import qualified Data.Map.Strict as Map
import           Data.Word
import           Numeric ( showHex )
import           Numeric.Natural ( Natural )
import           System.IO
import           Text.Printf (printf)

import           Data.Macaw.Analysis.RegisterUse (BlockInvariantMap)
import Data.Macaw.CFG
    ( MemSegmentOff,
      MemAddr(addrOffset),
      segoffAddr,
      MemWord(memWordValue) )
import           Prettyprinter (Doc, pretty, vsep, hsep, (<+>), hang, layoutPretty, defaultLayoutOptions)
import           Prettyprinter.Render.String (renderString)

-- | Identifies steps in Reopt's recompilation pipeline that may
-- generate events.
--
-- The parameter is used to represent information returned if the
-- event completes successfully.
data ReoptStep arch a where
  -- | Initial argument checking and setup for discovery.
  DiscoveryInitialization :: ReoptStep arch ()
  -- | Parse information from header file to infer function types.
  HeaderTypeInference :: ReoptStep arch ()
  -- | Parse debug information to infer function types.
  DebugTypeInference :: ReoptStep arch ()
  -- | Function discovery at given address and name.
  Discovery :: !Word64
            -> !(Maybe BS.ByteString)
            -> ReoptStep arch ()
  -- | Global function argument inference
  FunctionArgInference :: Maybe (Word64 , Maybe BS.ByteString) -> ReoptStep arch ()
  -- | Function invariant inference.
  InvariantInference :: !Word64 -> !(Maybe BS.ByteString) -> ReoptStep arch (BlockInvariantMap arch ids)
  -- | Function recovery at given address and name.
  Recovery :: !Word64 -> !(Maybe BS.ByteString) -> ReoptStep arch ()

ppFn :: Word64 -> Maybe BS.ByteString -> String
ppFn a (Just nm) = BS.unpack nm <> "(0x" <> showHex a ")"
ppFn a Nothing   = "0x" <> showHex a ""


ppStep :: ReoptStep arch a -> String
ppStep DiscoveryInitialization = "Initialization"
ppStep HeaderTypeInference = "Header Processing"
ppStep DebugTypeInference = "Debug Processing"
ppStep (Discovery a mnm) = "Discovering " <> ppFn a mnm
ppStep (FunctionArgInference Nothing) = "Argument inference"
ppStep (FunctionArgInference (Just (a, mnm))) = "Argument inference " <> ppFn a mnm
ppStep (Recovery a mnm) = "Recovering " <> ppFn a mnm
ppStep (InvariantInference a mnm) = "Analyzing " <> ppFn a mnm

data ReoptEventSeverity
   = ReoptInfo
     -- ^ Informational event used to report progress.
   | ReoptWarning
     -- ^ Warning that something was amiss that likely will affect results.

data ReoptStepTag
  = DiscoveryInitializationStepTag
  | HeaderTypeInferenceStepTag
  | DebugTypeInferenceStepTag
  | DiscoveryStepTag
  | FunctionArgInferenceStepTag
  | InvariantInferenceStepTag
  | RecoveryStepTag
  deriving (Eq, Ord, Show)

ppReoptStepTag :: ReoptStepTag -> String
ppReoptStepTag = show

-- | A specific reason a ReoptStep failed for reporting purposes/statistics.
data ReoptFailureTag
  = MacawParsedTranslateFailureTag
  | MacawClassifyFailureTag
  | MacawRegisterUseErrorTag
  | MacawCallAnalysisErrorTag
  | ReoptVarArgFnTag
  | ReoptMissingNameTag
  | ReoptMissingTypeTag
  | ReoptUnsupportedTypeTag
  | ReoptBlockPreconditionUnresolvedTag
  | ReoptUnsupportedMemOpTag
  | ReoptTypeMismatchTag
  | ReoptUnsupportedFnValueTag
  | ReoptUninitializedAssignmentTag
  | ReoptUnimplementedFeatureTag
  | ReoptUnsupportedInFnRecoveryTag
  | ReoptUnimplementedLLVMBackendFeatureTag
  | ReoptStackOffsetEscapeTag
  | ReoptRegisterEscapeTag
  | ReoptStackReadOverlappingOffsetTag
  | ReoptUninitializedPhiVarTag
  | ReoptUnresolvedReturnValTag
  | ReoptCannotRecoverFnWithPLTStubsTag
  | ReoptInvariantInferenceFailureTag
  | ReoptInternalErrorTag
  deriving (Eq, Ord, Show)

ppReoptFailureTag :: ReoptFailureTag -> String
ppReoptFailureTag = show

-- | Event passed to logger when discovering functions
data ReoptLogEvent arch
     -- | Indicates we started as step.
   = forall a. ReoptStepStarted !(ReoptStep arch a)
     -- | Log an event.
   | forall a. ReoptLogEvent !(ReoptStep arch a) !ReoptEventSeverity !String
     -- | Indicate a step failed due to the given error.
   | forall a. ReoptStepFailed !(ReoptStep arch a) !ReoptFailureTag !String
     -- | Indicate a step completed successfully.
   | forall a. ReoptStepFinished !(ReoptStep arch a) !a

segoffWord64 :: MemSegmentOff w -> Word64
segoffWord64 = memWordValue . addrOffset . segoffAddr


ppSegOff :: MemSegmentOff w -> String
ppSegOff addr = "0x" <> showHex (segoffWord64 addr) ""

-- | Human-readable name of discovered function.
ppFnEntry :: Maybe BS.ByteString -> MemSegmentOff w -> String
ppFnEntry (Just nm) addr = BS.unpack nm <> "(" <> ppSegOff addr <> ")"
ppFnEntry Nothing addr   = ppSegOff addr


--ppSeverity :: ReoptEventSeverity -> String
--ppSeverity ReoptInfo = "Info"
--ppSeverity ReoptWarning = "Warn"


instance Show (ReoptLogEvent arch) where
  show (ReoptStepStarted st) = ppStep st
  show (ReoptStepFinished _ _) = printf "  Complete."
  show (ReoptLogEvent _st _sev msg) = printf "  %s" msg
  show (ReoptStepFailed _st _tag msg) = printf "  Failed: %s" msg

-- | Should this event increase the error count?
isErrorEvent ::  ReoptLogEvent arch -> Bool
isErrorEvent =
  \case
    ReoptStepStarted{} -> False
    ReoptLogEvent _ ReoptInfo _ -> False
    ReoptLogEvent _ _ _         -> True
    ReoptStepFailed{} -> True
    ReoptStepFinished{} -> False

-------------------------------------------------------------------------------

-- | Describes the result of a function recovery attempt.
data FnRecoveryResult
  = FnDiscovered
  | FnRecovered
  | FnFailedDiscovery
  | FnFailedRecovery
  | FnFailedArgInference
  deriving (Show, Eq)

-- | Statistics summarizing our recovery efforts.
data ReoptStats =
  ReoptStats
  { statsBinary :: !FilePath
  -- ^ Which binary are these statistics for?
  , statsFnResults :: Map (Maybe BS.ByteString, Word64) FnRecoveryResult
  -- ^ Mapping of functions to the result of recovery
  , statsFnDiscoveredCount :: Natural
  -- ^ Number of discovered functions (i.e., may or may not end up being successfully recovered).
  , statsFnRecoveredCount :: Natural
  -- ^ Number of successfully recovered functions.
  , statsFnFailures :: Map ReoptStepTag (Map ReoptFailureTag Natural)
  -- ^ Number of functions which failed at some point to be analyzed and/or processed.
  , statsErrorCount :: Natural
  -- ^ Overall error count.
  }

initReoptStats :: FilePath -> ReoptStats
initReoptStats binPath =
  ReoptStats
  { statsBinary = binPath
  , statsFnResults = Map.empty
  , statsFnDiscoveredCount = 0
  , statsFnRecoveredCount = 0
  , statsFnFailures = Map.empty
  , statsErrorCount = 0
  }

statsFnFailedCount :: ReoptStats -> Natural
statsFnFailedCount stats = foldl' (+) 0 totals
  where totals = concatMap Map.elems $ Map.elems $ statsFnFailures stats


incFnResult ::
  Maybe BS.ByteString ->
  Word64 ->
  FnRecoveryResult ->
  Map (Maybe BS.ByteString, Word64) FnRecoveryResult ->
  Map (Maybe BS.ByteString, Word64) FnRecoveryResult
incFnResult mFnName fnAddress fnResult results = Map.insert (mFnName, fnAddress) fnResult results

incFnFailure ::
  ReoptStepTag ->
  ReoptFailureTag ->
  Map ReoptStepTag (Map ReoptFailureTag Natural) ->
  Map ReoptStepTag (Map ReoptFailureTag Natural)
incFnFailure stepTag failureTag = Map.alter logFail stepTag
  where incErr Nothing    = Just 1 -- if there is not an entry for the particular error, start at 1
        incErr (Just cnt) = Just $ cnt+1 -- otherwise just increment the count by 1
        logFail Nothing = Just $ Map.fromList [(failureTag, 1)] -- if there is no map for this step, start one
        logFail (Just m) = Just $ Map.alter incErr failureTag m -- otherwise just increment the particular failure

-- | Combine two maps of reopt failures, i.e., combining their respective counts.
mergeFnFailures ::
  Map ReoptStepTag (Map ReoptFailureTag Natural) ->
  Map ReoptStepTag (Map ReoptFailureTag Natural) ->
  Map ReoptStepTag (Map ReoptFailureTag Natural)
mergeFnFailures = Map.unionWith mergeStepMap
  where mergeStepMap :: Map ReoptFailureTag Natural -> Map ReoptFailureTag Natural -> Map ReoptFailureTag Natural
        mergeStepMap = Map.unionWith (+)

-- | Render the registered failures in an indented list-style Doc.
renderAllFailures' :: Map ReoptStepTag (Map ReoptFailureTag Natural) -> Doc ()
renderAllFailures' = vsep . (map renderStepFailures) . Map.toList
  where
    renderStepFailures :: (ReoptStepTag, Map ReoptFailureTag Natural) -> Doc ()
    renderStepFailures (tag, failures) =
      (pretty  $ ppReoptStepTag tag) <+> (hang 2 $ vsep $ map renderFailure $ Map.toList failures)
    renderFailure :: (ReoptFailureTag, Natural) -> Doc ()
    renderFailure (tag, cnt) = hsep [pretty $ ppReoptFailureTag tag, pretty ":", pretty $ show cnt]


renderAllFailures :: Map ReoptStepTag (Map ReoptFailureTag Natural) -> String
renderAllFailures failures = renderString $ layoutPretty defaultLayoutOptions $ renderAllFailures' failures


renderFnStats :: ReoptStats -> String
renderFnStats s =
  if statsFnDiscoveredCount s == 0 then
    "reopt discovered no functions."
   else do
    let passed :: Double = (fromIntegral $ statsFnRecoveredCount s) / (fromIntegral $  statsFnDiscoveredCount s)
        failCount = statsFnFailedCount s
        failed :: Double = (fromIntegral $ failCount) / (fromIntegral $  statsFnDiscoveredCount s)
    "reopt discovered " ++ (show (statsFnDiscoveredCount s)) ++ " functions in the binary "++(statsBinary s)++":\n"
      ++ "  recovery succeeded: " ++ (printf "%d (%.2f%%)" (statsFnRecoveredCount s) (passed * 100.0)) ++ "\n"
      ++ "  recovery failed: " ++ (printf "%d (%.2f%%)" failCount (failed * 100.0)) ++ "\n"

-- | Header row for data produced by @statsRows@
statsHeader :: [String]
statsHeader = ["binary", "fn name", "address", "recovery result"]

-- | Rows for table summary of recovery statistics; see also @statsHeader@.
statsRows :: ReoptStats -- ^ Stats to convert to rows.
          -> [[String]]
statsRows stats = map toCsvRow $ Map.toList $ statsFnResults stats
  where toCsvRow :: ((Maybe BS.ByteString, Word64), FnRecoveryResult) -> [String]
        toCsvRow ((mNm, faddr), res) =
          let name = case mNm of Nothing -> ""; Just nm -> BS.unpack nm
              hexAddr = "0x" ++ showHex faddr ""
          in [statsBinary stats, name, hexAddr, show res]

exportFnStats :: FilePath -- ^ Path to write statistics to.
              -> ReoptStats -- ^ Stats to export.
              -> IO ()
exportFnStats outPath stats = do
  let hdrStr = intercalate "," statsHeader
      rowsStr = map (intercalate ",") $ statsRows stats
  writeFile outPath $ unlines $ hdrStr:rowsStr

-- | Print and/or export statistics (if relevant flags are set) and the error count.
reportStats
  :: Bool -- ^ Whether to print statistics to stderr.
  -> Maybe FilePath -- ^ Where to export stats to.
  -> ReoptStats
  -> IO ()
reportStats printStats mStatsPath stats = do
  when printStats $ do
    hPutStrLn stderr $ renderFnStats stats
  case mStatsPath of
    Nothing -> pure ()
    Just statsPath -> exportFnStats statsPath stats
  when ((statsErrorCount stats) > 0) $ do
    hPutStrLn stderr $
      if (statsErrorCount stats) == 1 then
        "1 error occured."
       else
        show (statsErrorCount stats) ++ " errors occured."
