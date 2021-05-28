{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
-- |
-- Datatype for recording events in Reopt.
module Reopt.Events
  ( ReoptLogEvent (..),
    ReoptErrorTag (..),
    ReoptStep (..),
    ReoptGlobalStep (..),
    ReoptFunStep (..),
    ReoptStepTag (..),
    mkReoptErrorTag,
    ReoptEventSeverity (..),
    DiscoveryErrorType(..),
    FunId(..),
    funId,
    isErrorEvent,
    -- * Summary
    ReoptSummary (..),
    FnRecoveryResult (..),
    initReoptSummary,
    setSummaryFnStatus,
    -- * Statistics
    ReoptStats (..),
    initReoptStats,
    incStatsBinarySize,
    statsStepErrorCount,
    renderAllFailures,
    stepErrorCount,
--    incFnResult,
    incStepError,
    reoptStepTag,
    stepFailResult,
    mergeFnFailures,
    summaryHeader,
    summaryRows,
    ppFnEntry,
    segoffWord64,
    ppSegOff,
    -- * Exported errors (for VSCode plugin)
    ReoptExportedError(..),
    ReoptExportedErrorLocation(..),
    -- * Utilities,
    Data.Void.Void
  ) where

import qualified Data.ByteString.Char8 as BS
import Data.List (foldl')
import Data.Macaw.Analysis.RegisterUse (BlockInvariantMap)
import Data.Macaw.CFG
  ( MemAddr (addrOffset),
    MemSegmentOff,
    MemWord (memWordValue),
    segoffAddr,
  )
import Data.Macaw.Discovery (DiscoveryState)
import Data.Map (Map)
import qualified Data.Map.Strict as Map
import Data.Maybe (fromMaybe)
import Data.Void (Void, absurd)
import Data.Word (Word64)
import Numeric (showHex)
import Numeric.Natural (Natural)
import Prettyprinter
  ( Doc,
    defaultLayoutOptions,
    hang,
    hsep,
    indent,
    layoutPretty,
    pretty,
    vsep,
  )
import Prettyprinter.Render.String (renderString)
import Text.Printf (printf)

-- | Function identifier and name.
data FunId = FunId !Word64 !BS.ByteString
  deriving (Eq, Ord)

funId :: MemSegmentOff w -> Maybe BS.ByteString -> FunId
funId a mnm = FunId (memWordValue (addrOffset (segoffAddr a))) (fromMaybe BS.empty mnm)

ppFunId :: FunId -> String
ppFunId (FunId a nm)
  | BS.null nm = "0x" <> showHex a ""
  | otherwise = BS.unpack nm <> "(0x" <> showHex a ")"

-------------------------------------------------------------------------------
-- Errors exported to VSCode

-- | Location for error
data ReoptExportedErrorLocation
     -- | File offset in the input binary.
   = ReoptErrorBinaryOffset !Int
     -- | Describes a location in the control flow graph with function id,
     -- an optional block identifier and an optional index in the instruction.
   | ReoptErrorControlFlowGraph !FunId !(Maybe Word64) !(Maybe Int)
     -- | Describes a location in the function graph with function id,
     -- an optional block identifier and an optional index in the instruction.
   | ReoptFunctionGraph !FunId !(Maybe Word64) !(Maybe Int)

data ReoptExportedError = ReoptExportedError
  { errorLocation :: !ReoptExportedErrorLocation
  , errorMessage :: !String
  }

-------------------------------------------------------------------------------
--  Other

-- | Errors for discovery process.
data DiscoveryErrorType
   = DiscoveryTransError
   | DiscoveryClassError
  deriving (Eq, Ord, Show)

instance Semigroup DiscoveryErrorType where
  DiscoveryTransError <> _ = DiscoveryTransError
  DiscoveryClassError <> r = r

-- | Identifies a step in Reopt's recompilation pipeline that
-- is over all functions.
--
-- The parameter is used to represent information returned if the
-- step completes successfully.
data ReoptGlobalStep arch r e where
  -- | Initial argument checking and setup for discovery.
  DiscoveryInitialization :: ReoptGlobalStep arch (DiscoveryState arch) (ReoptErrorTag, String)
  -- | Parse information from header file to infer function types.
  HeaderTypeInference :: ReoptGlobalStep arch () (ReoptErrorTag, String)
  -- | Parse debug information to infer function types.
  DebugTypeInference :: ReoptGlobalStep arch () Void
  -- | Global function argument inference
  FunctionArgInference :: ReoptGlobalStep arch () (ReoptErrorTag, String)

ppGlobalStep :: ReoptGlobalStep arch r e -> String
ppGlobalStep DiscoveryInitialization = "Initialization"
ppGlobalStep HeaderTypeInference = "Header Processing"
ppGlobalStep DebugTypeInference = "Debug Processing"
ppGlobalStep FunctionArgInference = "Argument inference"

-- | Identifies steps in Reopt's recompilation pipeline that involves
-- a single function.
--
-- The parameter is used to represent information returned if the
-- event completes successfully.
data ReoptFunStep arch r e where
  -- | Function discovery at given address and name.
  Discovery :: ReoptFunStep arch () DiscoveryErrorType
  -- | Function invariant inference.
  InvariantInference :: ReoptFunStep arch (BlockInvariantMap arch ids) (ReoptErrorTag, String)
  -- | Function recovery at given address and name.
  Recovery :: ReoptFunStep arch () (ReoptErrorTag, String)

ppFunStep :: ReoptFunStep arch r e -> String
ppFunStep Discovery = "Discovering"
ppFunStep InvariantInference = "Analyzing"
ppFunStep Recovery = "Recovering"

-- | Identifies steps in Reopt's recompilation pipeline that may
-- generate events.
--
-- The parameter is used to represent information returned if the
-- event completes successfully.
data ReoptStep arch r e where
  -- | Global step
  GlobalStep :: !(ReoptGlobalStep arch r e) -> ReoptStep arch r e
  -- | Single function step.
  FunStep :: !(ReoptFunStep arch r e) -> !FunId -> ReoptStep arch r e

ppStep :: ReoptStep arch r e -> String
ppStep (GlobalStep s) = ppGlobalStep s
ppStep (FunStep s f) = ppFunStep s ++ " " ++ ppFunId f

data ReoptEventSeverity
  = -- | Informational event used to report progress.
    ReoptInfo
  | -- | Warning that something was amiss that likely will affect results.
    ReoptWarning

-- | Tags for reporting errors during various reopt steps.
newtype ReoptStepTag = ReoptStepTag BS.ByteString
  deriving (Eq, Ord)

ppReoptStepTag :: ReoptStepTag -> String
ppReoptStepTag (ReoptStepTag s) = BS.unpack s

-- | Returns the step tag corresponding to the given ReoptStep.
-- N.B., we combine several inference steps and just refer to
-- them as part of discovery for error reporting purposes.
reoptStepTag :: ReoptStep arch a e -> ReoptStepTag
reoptStepTag (GlobalStep s) = ReoptStepTag (BS.pack (ppGlobalStep s))
reoptStepTag (FunStep s _) = ReoptStepTag (BS.pack (ppFunStep s))

-- | A specific reason a ReoptStep failed for reporting purposes/statistics.
data ReoptErrorTag
  = MacawDiscoveryError !DiscoveryErrorType
  | MacawParsedTranslateFailureTag
  | MacawClassifyFailureTag
  | MacawRegisterUseErrorTag
  | MacawCallAnalysisErrorTag
  | ReoptVarArgFnTag
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
  | ReoptMissingVariableValue
  | ReoptWarningTag
  deriving (Eq, Ord, Show)

mkReoptErrorTag :: ReoptStep arch r e -> e -> ReoptErrorTag
mkReoptErrorTag (GlobalStep s) e =
  case s of
    DiscoveryInitialization -> fst e
    HeaderTypeInference -> fst e
    DebugTypeInference -> absurd e
    FunctionArgInference -> fst e
mkReoptErrorTag (FunStep s _) e =
  case s of
           Discovery -> MacawDiscoveryError e
           InvariantInference -> fst e
           Recovery -> fst e

ppReoptErrorTag :: ReoptErrorTag -> String
ppReoptErrorTag =
  \case
    MacawDiscoveryError e ->
      case e of
        DiscoveryTransError -> "unhandled instruction"
        DiscoveryClassError -> "unidentified control flow"
    MacawParsedTranslateFailureTag -> "block translation error"
    MacawClassifyFailureTag -> "block classification error"
    MacawRegisterUseErrorTag -> "register use error"
    MacawCallAnalysisErrorTag -> "call analysis error"
    ReoptVarArgFnTag -> "unsupported variadic function"
    ReoptUnsupportedTypeTag -> "unsupported type tag"
    ReoptBlockPreconditionUnresolvedTag -> "block precondition unresolved"
    ReoptUnsupportedMemOpTag -> "unsupported memory operation"
    ReoptTypeMismatchTag -> "type mismatch"
    ReoptUnsupportedFnValueTag -> "unsupported function value"
    ReoptUninitializedAssignmentTag -> "uninitialized assignment"
    ReoptUnimplementedFeatureTag -> "unimplemented feature"
    ReoptUnsupportedInFnRecoveryTag -> "unsupported action in function recovery"
    ReoptUnimplementedLLVMBackendFeatureTag -> "unimplemented LLVM backend feature"
    ReoptStackOffsetEscapeTag -> "stack offset escape"
    ReoptRegisterEscapeTag -> "register escape"
    ReoptStackReadOverlappingOffsetTag -> "stack read overlapping offset"
    ReoptUninitializedPhiVarTag -> "uninitialized phi variable"
    ReoptUnresolvedReturnValTag -> "unresolved return value"
    ReoptCannotRecoverFnWithPLTStubsTag -> "unexpected PLT stub"
    ReoptInvariantInferenceFailureTag -> "invariant inference failure"
    ReoptMissingVariableValue -> "missing variable value"
    ReoptWarningTag -> "warning"

-- | Event passed to logger when discovering functions
data ReoptLogEvent arch where
  -- | Indicates we started as step.
  ReoptStepStarted :: !(ReoptStep arch a e) -> ReoptLogEvent arch
  -- | Log an event.
  ReoptLogEvent :: !(ReoptStep arch a e) -> !ReoptEventSeverity -> !String -> ReoptLogEvent arch
  -- | Indicate a step failed due to the given error.
  ReoptStepFailed :: !(ReoptStep arch a e) -> !e -> ReoptLogEvent arch
  -- | Indicate a step completed successfully.
  ReoptStepFinished :: !(ReoptStep arch a e) -> !a -> ReoptLogEvent arch

segoffWord64 :: MemSegmentOff w -> Word64
segoffWord64 = memWordValue . addrOffset . segoffAddr

ppSegOff :: MemSegmentOff w -> String
ppSegOff addr = "0x" <> showHex (segoffWord64 addr) ""

-- | Human-readable name of discovered function.
ppFnEntry :: Maybe BS.ByteString -> MemSegmentOff w -> String
ppFnEntry (Just nm) addr = BS.unpack nm <> "(" <> ppSegOff addr <> ")"
ppFnEntry Nothing addr = ppSegOff addr

--ppSeverity :: ReoptEventSeverity -> String
--ppSeverity ReoptInfo = "Info"
--ppSeverity ReoptWarning = "Warn"

ppReoptError :: (ReoptErrorTag, String) -> String
ppReoptError (tag, msg) = printf "  Failed (%s): %s" (ppReoptErrorTag tag) msg


instance Show (ReoptLogEvent arch) where
  show (ReoptStepStarted st) = ppStep st
  show (ReoptStepFinished _ _) = printf "  Complete."
  show (ReoptLogEvent _st _sev msg) = printf "  %s" msg
  show (ReoptStepFailed st e) = ("  " ++) $
    case st of
      GlobalStep st' ->
        case st' of
          DiscoveryInitialization -> ppReoptError e
          HeaderTypeInference -> ppReoptError e
          DebugTypeInference -> absurd e
          FunctionArgInference -> ppReoptError e
      FunStep st' _ ->
        case st' of
           Discovery -> "Incomplete."
           InvariantInference -> ppReoptError e
           Recovery -> ppReoptError e

-- | Should this event increase the error count?
isErrorEvent :: ReoptLogEvent arch -> Bool
isErrorEvent =
  \case
    ReoptStepStarted {} -> False
    ReoptLogEvent _ ReoptInfo _ -> False
    ReoptLogEvent _ _ _ -> True
    ReoptStepFailed {} -> True
    ReoptStepFinished {} -> False

-------------------------------------------------------------------------------

-- | Describes the result of a function recovery attempt.
data FnRecoveryResult
  = FnDiscovered
  | FnRecovered
  | FnFailedDiscovery
  | FnFailedRecovery
  deriving (Show, Eq)


-- | Convert the failure of a step to the appropriate FnRecoveryResult if
-- possible along with the address and function name (if present), else return
-- Nothing.
stepFailResult :: ReoptStep arch a e -> Maybe (FnRecoveryResult, FunId)
stepFailResult =
  \case
    GlobalStep _ -> Nothing
    FunStep _ f -> Just (FnFailedDiscovery, f)

type StepErrorMap = Map ReoptStepTag (Map ReoptErrorTag Natural)

stepErrorCount :: ReoptStepTag -> ReoptStats -> Natural
stepErrorCount step stats = sum errors
  where errors = Map.findWithDefault Map.empty step (statsStepErrors stats)

incStepError ::
  ReoptStepTag ->
  ReoptErrorTag ->
  StepErrorMap ->
  StepErrorMap
incStepError stepTag failureTag = Map.alter logFail stepTag
  where incErr Nothing    = Just 1 -- if there is not an entry for the particular error, start at 1
        incErr (Just cnt) = Just $ cnt+1 -- otherwise just increment the count by 1
        logFail Nothing = Just $ Map.fromList [(failureTag, 1)] -- if there is no map for this step, start one
        logFail (Just m) = Just $ Map.alter incErr failureTag m -- otherwise just increment the particular failure

-- | Combine two maps of reopt failures, i.e., combining their respective counts.
mergeFnFailures ::
  StepErrorMap ->
  StepErrorMap ->
  StepErrorMap
mergeFnFailures = Map.unionWith mergeStepMap
  where mergeStepMap :: Map ReoptErrorTag Natural -> Map ReoptErrorTag Natural -> Map ReoptErrorTag Natural
        mergeStepMap = Map.unionWith (+)

-- | Render the registered failures in an indented list-style Doc.
renderAllFailures' :: StepErrorMap -> Doc ()
renderAllFailures' = vsep . (map renderStepFailures) . Map.toList
  where
    renderStepFailures :: (ReoptStepTag, Map ReoptErrorTag Natural) -> Doc ()
    renderStepFailures (tag, failures) =
      let hdr = hsep [pretty $ stepCount failures
                     , pretty "failures during"
                     , (pretty $ ppReoptStepTag tag) <> (pretty " step:")]
      in hang 2 $ vsep $ [hdr] ++ (map renderFailure $ Map.toList failures)
    renderFailure :: (ReoptErrorTag, Natural) -> Doc ()
    renderFailure (tag, cnt) = hsep [pretty $ show cnt, pretty $ ppReoptErrorTag tag]
    stepCount :: Map ReoptErrorTag Natural -> Natural
    stepCount = foldl' (+) 0 . Map.elems


renderAllFailures :: StepErrorMap -> String
renderAllFailures  failures =
  renderString
  $ layoutPretty defaultLayoutOptions
  $ indent 2
  $ renderAllFailures' failures

-- | Statistics summarizing Reopt
data ReoptStats = ReoptStats
  { -- | How many bytes is the binary?
    statsBinarySize :: !Int,
    -- | Number of initial entry points in the binary
    statsInitEntryPointCount :: !Int,
    -- | Number of discovered functions (i.e., may or may not end up being successfully recovered).
    statsFnDiscoveredCount :: !Int,
    -- | Number of successfully recovered functions.
    statsFnRecoveredCount :: !Int,
    -- | Errors and warnings encountered, organized by reopt step.
    statsStepErrors :: !StepErrorMap,
    -- | Overall error count.
    statsErrorCount :: !Int
  }

initReoptStats :: ReoptStats
initReoptStats = ReoptStats
    { statsBinarySize = 0,
      statsInitEntryPointCount = 0,
      statsFnDiscoveredCount = 0,
      statsFnRecoveredCount = 0,
      statsStepErrors = Map.empty,
      statsErrorCount = 0
    }

incStatsBinarySize :: Int -> ReoptStats -> ReoptStats
incStatsBinarySize sz stats = stats { statsBinarySize = statsBinarySize stats + sz }

statsStepErrorCount :: ReoptStats -> Natural
statsStepErrorCount stats = foldl' (+) 0 totals
  where totals = concatMap Map.elems $ Map.elems $ statsStepErrors stats

{-
incFnResult
  FunId ->
  FnRecoveryResult ->
  Map FunId FnRecoveryResult ->
  Map FunId FnRecoveryResult
incFnResult = Map.insert
-}

-- | Statistics summarizing our recovery efforts.
data ReoptSummary =
  ReoptSummary
  { -- | Which binary are these statistics for?
    summaryBinaryPath :: !FilePath,
    -- | Mapping of functions to the result of recovery
    summaryFnResults :: !(Map FunId FnRecoveryResult)
  }

initReoptSummary :: FilePath -> ReoptSummary
initReoptSummary binPath =
  ReoptSummary
  { summaryBinaryPath = binPath
  , summaryFnResults = Map.empty
  }

setSummaryFnStatus ::
  FunId ->
  FnRecoveryResult ->
  ReoptSummary ->
  ReoptSummary
setSummaryFnStatus f r s =
  s { summaryFnResults = Map.insert f r (summaryFnResults s) }

-- | Header row for data produced by @statsRows@
summaryHeader :: [String]
summaryHeader = ["binary", "fn name", "address", "recovery result"]

-- | Rows for table summary of recovery statistics; see also @statsHeader@.
summaryRows ::
  -- | Stats to convert to rows.
  ReoptSummary ->
  [[String]]
summaryRows stats = map toCsvRow $ Map.toList $ summaryFnResults stats
  where
    toCsvRow :: (FunId, FnRecoveryResult) -> [String]
    toCsvRow (FunId faddr nm, res) =
      let name = BS.unpack nm
          hexAddr = "0x" ++ showHex faddr ""
       in [summaryBinaryPath stats, name, hexAddr, show res]
