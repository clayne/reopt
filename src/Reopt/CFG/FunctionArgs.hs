{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Reopt.CFG.FunctionArgs
  ( functionArgs
  ) where

import           Control.Lens
import           Control.Monad.State.Strict
import           Data.Foldable as Fold (traverse_)
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Parameterized.Classes
import           Data.Parameterized.Some
import           Data.Set (Set)
import qualified Data.Set as Set
-- import           Text.PrettyPrint.ANSI.Leijen hiding ((<$>))

import           Reopt.CFG.InterpState
import           Reopt.CFG.Representation
import qualified Reopt.Machine.StateNames as N
import           Reopt.Machine.Types
import           Reopt.Utils.Debug

-- -----------------------------------------------------------------------------

-- The algorithm computes the set of direct deps (i.e., from writes)
-- and then iterates, propagating back via the register deps.  It
-- doesn't compute assignment uses (although it could) mainly to keep
-- memory use down.  We recompute assignment use later in RegisterUse.
--
-- The basic question this analysis answers is: what arguments does a
-- function require, and what results does it produce?  
--
-- There are 3 phases
-- 1. Block-local summarization
-- 2. Function-local summarization
-- 3. Global fixpoint calculation.
--
-- The first 2 phases calculate, for each function, the following information:
--
-- A. What registers are required by a function (ignoring function
--    calls)?
-- 
-- B. Given that result register {rax, rdx, xmm0} is demanded, what
--    extra register arguments are required, and what extra result
--    arguments are required?
--
-- C. Given that function f now requires argument r, what extra
--    arguments are required, and what extra result registers are
--    demanded?

type RegisterSet = Set (Some N.RegisterName)

-- | If we demand a register from a function (or block, for phase 1),
-- this results in both direct argument register demands and function
-- result demands.
data DemandSet = DemandSet { registerDemands       :: !RegisterSet
                           , functionResultDemands :: Map CodeAddr RegisterSet
                           }
                 deriving (Eq, Ord, Show)

instance Monoid DemandSet where
  mempty = DemandSet mempty mempty
  mappend ds1 ds2 =
    DemandSet (registerDemands ds1 `mappend` registerDemands ds2)
              (Map.unionWith Set.union (functionResultDemands ds1)
                                       (functionResultDemands ds2))

demandSetDifference :: DemandSet -> DemandSet -> DemandSet
demandSetDifference ds1 ds2 =
  DemandSet (registerDemands ds1 `Set.difference` registerDemands ds2)
            (Map.differenceWith setDiff (functionResultDemands ds1)
                                        (functionResultDemands ds2))
  where
    setDiff s1 s2 =
      let s' = s1 `Set.difference` s2
      in if Set.null s' then Nothing else Just s'

-- | The types of demands we can make
data DemandType =
  -- | We just want a local register (e.g., a subsequent block needs
  -- register rax)
  DemandAlways
  -- | A function requires an additional argument
  | forall cl. DemandFunctionArg CodeAddr (N.RegisterName cl)
  -- | The result of the current function.
  | forall cl. DemandFunctionResult (N.RegisterName cl)

deriving instance Show DemandType

instance Eq DemandType where
  DemandAlways == DemandAlways = True
  (DemandFunctionArg faddr1 r1) == (DemandFunctionArg faddr2 r2) =
    faddr1 == faddr2 && isJust (testEquality r1 r2)
  (DemandFunctionResult r1) == (DemandFunctionResult r2) =
    isJust (testEquality r1 r2)
  _ == _ = False

instance Ord DemandType where 
  DemandAlways `compare` DemandAlways = EQ
  DemandAlways `compare` _  = LT
  _ `compare` DemandAlways  = GT

  (DemandFunctionArg faddr1 r1) `compare` (DemandFunctionArg faddr2 r2)
    | faddr1 == faddr2 = case compareF r1 r2 of LTF -> LT
                                                EQF -> EQ
                                                GTF -> GT
    | otherwise = faddr1 `compare` faddr2

  (DemandFunctionArg {}) `compare` _ = LT
  _ `compare` (DemandFunctionArg {}) = GT

  (DemandFunctionResult r1) `compare` (DemandFunctionResult r2) =
    case compareF r1 r2 of LTF -> LT
                           EQF -> EQ
                           GTF -> GT
  
type DemandMap = Map DemandType DemandSet

demandMapUnion :: DemandMap -> DemandMap -> DemandMap
demandMapUnion = Map.unionWith mappend

type AssignmentCache = Map (Some Assignment) RegisterSet

-- Generated by phase 1, used by phase 2.
data FunctionArgsState = FAS {
  -- | Holds state about the set of registers that a block uses
  -- (required by this block).  
  _blockTransfer :: !(Map BlockLabel (Map (Some N.RegisterName) DemandSet))

  -- | If a demand d is demanded of block lbl then the block demands S, s.t.
  -- blockDemandMap ^. at lbl ^. at d = Just S
  , _blockDemandMap    :: !(Map BlockLabel DemandMap)
    
  -- | The list of predecessors for a given block
  , _blockPreds     :: !(Map BlockLabel [BlockLabel])
    
  -- | A cache of the assignments and their deps.  The key is not included
  -- in the set of deps (but probably should be).
  , _assignmentCache :: !AssignmentCache
    
  -- | The set of blocks we need to consider.    
  , _blockFrontier  :: !(Set BlockLabel)  }

initFunctionArgsState :: FunctionArgsState
initFunctionArgsState =
  FAS { _blockTransfer     = Map.empty
      , _blockDemandMap    = Map.empty
      , _blockPreds        = Map.empty
      , _assignmentCache   = Map.empty
      , _blockFrontier     = Set.empty }

blockTransfer :: Simple Lens FunctionArgsState (Map BlockLabel (Map (Some N.RegisterName) DemandSet))
blockTransfer = lens _blockTransfer (\s v -> s { _blockTransfer = v })

blockDemandMap :: Simple Lens FunctionArgsState (Map BlockLabel DemandMap)
blockDemandMap = lens _blockDemandMap (\s v -> s { _blockDemandMap = v })

blockPreds :: Simple Lens FunctionArgsState (Map BlockLabel [BlockLabel])
blockPreds = lens _blockPreds (\s v -> s { _blockPreds = v })

assignmentCache :: Simple Lens FunctionArgsState AssignmentCache
assignmentCache = lens _assignmentCache (\s v -> s { _assignmentCache = v })

blockFrontier :: Simple Lens FunctionArgsState (Set BlockLabel)
blockFrontier = lens _blockFrontier (\s v -> s { _blockFrontier = v })

-- ----------------------------------------------------------------------------------------

-- helper type to make a monad a monoid in the obvious way
newtype StateMonadMonoid s m = SMM { getStateMonadMonoid :: State s m }
                               deriving (Functor, Applicative, Monad, MonadState s)

instance Monoid m => Monoid (StateMonadMonoid s m) where
  mempty = return mempty
  mappend m m' = do mv <- m
                    mv' <- m'
                    return (mappend mv mv')

foldValueCached :: forall m tp. (Monoid m)
                   => (forall n.  NatRepr n -> Integer -> m)
                   -> (forall cl. N.RegisterName cl -> m)
                   -> (forall tp'. Assignment tp' -> m -> m)
                   -> Value tp -> State (Map (Some Assignment) m) m
foldValueCached litf initf assignf val = getStateMonadMonoid (go val)
  where
    go :: forall tp'. Value tp' -> StateMonadMonoid (Map (Some Assignment) m) m 
    go v =
      case v of
        BVValue sz i -> return $ litf sz i
        Initial r    -> return $ initf r 
        AssignedValue asgn@(Assignment _ rhs) ->
          do m_v <- use (at (Some asgn))
             case m_v of
               Just v' -> return $ assignf asgn v'
               Nothing -> 
                  do rhs_v <- goAssignRHS rhs
                     at (Some asgn) .= Just rhs_v
                     return (assignf asgn rhs_v)

    goAssignRHS :: forall tp'. AssignRhs tp' -> StateMonadMonoid (Map (Some Assignment) m) m 
    goAssignRHS v =
      case v of
        EvalApp a -> foldApp go a
        SetUndefined _w -> mempty
        Read loc
         | MemLoc addr _ <- loc -> go addr
         | otherwise            -> mempty -- FIXME: what about ControlLoc etc.
        MemCmp _sz cnt src dest rev -> mconcat [ go cnt, go src, go dest, go rev ]

-- ----------------------------------------------------------------------------------------

type FunctionArgsM a = State FunctionArgsState a

-- ----------------------------------------------------------------------------------------
-- Phase one functions

-- | This registers a block in the first phase (block discovery).
addEdge :: BlockLabel -> BlockLabel -> FunctionArgsM ()
addEdge source dest = 
  do -- record the edge
     blockPreds    %= Map.insertWith mappend dest [source]
     blockFrontier %= Set.insert dest

valueUses :: Value tp -> FunctionArgsM RegisterSet
valueUses = zoom assignmentCache .
            foldValueCached (\_ _    -> mempty)
                            (\r      -> Set.singleton (Some r))
                            (\_ regs -> regs)


-- Figure out the deps of the given registers and update the state for the current label
recordPropagation :: Ord a =>
                     Simple Lens FunctionArgsState (Map BlockLabel (Map a DemandSet))
                     -> BlockLabel
                     -> X86State Value
                     -> (forall cl. N.RegisterName cl -> a)
                     -> [Some N.RegisterName]
                     -> FunctionArgsM () -- Map (Some N.RegisterName) RegDeps
recordPropagation l lbl s mk rs = do
  let doReg (Some r) = do
        rs' <- valueUses (s ^. register r)
        return (mk r, DemandSet rs' mempty)
  vs <- mapM doReg rs
  l %= Map.insertWith (Map.unionWith mappend) lbl (Map.fromListWith mappend vs)

-- | A block requires a value, and so we need to remember which
-- registers are required.
demandValue :: BlockLabel -> Value tp -> FunctionArgsM ()
demandValue lbl v = do
  regs <- valueUses v
  blockDemandMap %= Map.insertWith demandMapUnion lbl
                        (Map.singleton DemandAlways (DemandSet regs mempty))

nextBlock :: FunctionArgsM (Maybe BlockLabel)
nextBlock = blockFrontier %%= \s -> let x = Set.maxView s in (fmap fst x, maybe s snd x)

-- -----------------------------------------------------------------------------
-- Entry point

-- | Returns the set of argument registers and result registers for each function.
functionArgs :: InterpState -> Map CodeAddr (RegisterSet, RegisterSet) -- (args, results)
functionArgs ist =
  -- debug' DFunctionArgs (ppSet (text . flip showHex "") seenFuns) $
  finalizeMap $ calculateGlobalFixpoint argDemandsMap resultDemandsMap argsMap
  where
    (argDemandsMap, resultDemandsMap, argsMap)
      = foldl doOneFunction mempty (ist ^. functionEntries)

    -- This function computes the following 3 pieces of information:
    -- 1. Initial function arguments (ignoring function calls)
    -- 2. Function arguments to function arguments
    -- 3. Function results to function arguments.
    doOneFunction acc addr =
      flip evalState initFunctionArgsState $ do
        -- Run the first phase (block summarization)
        summarizeIter ist Set.empty (Just $ mkRootBlockLabel addr)
        -- propagate back uses
        new <- use blockDemandMap

        -- debugM DFunctionArgs (">>>>>>>>>>>>>>>>>>>>>>>>" ++ (showHex addr "" ))
        -- debugM' DFunctionArgs (ppMap (text . show) (ppMap (text . show) (text . show)) new) 
        -- debugM DFunctionArgs ("------------------------" ++ (showHex addr "" ))
        -- xfer <- use blockTransfer
        -- debugM' DFunctionArgs (ppMap (text . show) (ppMap (text . show) (text . show)) xfer) 

        calculateLocalFixpoint new
        -- summary for entry block has what we want.
        -- m <- use (blockDemandMap . ix lbl0)
        -- debugM DFunctionArgs ("*************************"  ++ (showHex addr "" ))
        -- debugM' DFunctionArgs (ppMap (text . show) (text . show) m) 
        -- debugM DFunctionArgs ("<<<<<<<<<<<<<<<<<<<<<<<<<" ++ (showHex addr "" ))
        
        funDemands <- use (blockDemandMap . ix lbl0)
        return (Map.foldlWithKey' (decomposeMap addr) acc funDemands)
      where
        lbl0 = mkRootBlockLabel addr

    -- A function may demand a callee saved register as it will store
    -- it onto the stack in order to use it later.  This will get
    -- recorded as a use, which is erroneous, so we strip out any
    -- reference to them here.
    calleeDemandSet = DemandSet { registerDemands = Set.insert (Some N.rsp)
                                                    x86CalleeSavedRegisters
                                , functionResultDemands = mempty }
                                 
    decomposeMap :: CodeAddr
                 -> (Map CodeAddr (Map (Some N.RegisterName)
                                   (Map CodeAddr DemandSet))
                    , Map CodeAddr (Map (Some N.RegisterName) DemandSet)
                    , Map CodeAddr DemandSet)
                 -> DemandType -> DemandSet
                 -> (Map CodeAddr (Map (Some N.RegisterName)
                                   (Map CodeAddr DemandSet))
                    , Map CodeAddr (Map (Some N.RegisterName) DemandSet)
                    , Map CodeAddr DemandSet)    
    decomposeMap addr acc (DemandFunctionArg f r) v =
      -- FIXME: A bit of an awkward datatype ...
      acc & _1 %~ Map.insertWith (Map.unionWith (Map.unionWith mappend)) f
                        (Map.singleton (Some r) (Map.singleton addr v))
    decomposeMap addr acc (DemandFunctionResult r) v =
      acc & _2 %~ Map.insertWith (Map.unionWith mappend) addr
                        (Map.singleton (Some r) v)
    -- Strip out callee saved registers as well.
    decomposeMap addr acc DemandAlways v =
      acc & _3 %~ Map.insertWith mappend addr (v `demandSetDifference` calleeDemandSet)

    finalizeMap :: Map CodeAddr DemandSet -> Map CodeAddr (RegisterSet, RegisterSet)
    finalizeMap dm = 
      let go ds = Map.unionWith Set.union (functionResultDemands ds)
          retDemands = foldr go Map.empty dm
      in Map.mergeWithKey (\_ ds rets -> Just (registerDemands ds, rets))
                          (fmap (\ds ->  (registerDemands ds, mempty)))
                          (fmap ((,) mempty))
                          dm retDemands

-- PERF: we can calculate the return types as we go (instead of doing
-- so at the end).
calculateGlobalFixpoint :: Map CodeAddr (Map (Some N.RegisterName)
                                             (Map CodeAddr DemandSet))
                        -> Map CodeAddr (Map (Some N.RegisterName) DemandSet)
                        -> Map CodeAddr DemandSet
                        -> Map CodeAddr DemandSet
calculateGlobalFixpoint argDemandsMap resultDemandsMap argsMap
  = go argsMap argsMap
  where
    go acc new
      | Just ((fun, newDemands), rest) <- Map.maxViewWithKey new =
          let (nexts, acc') = backPropagate acc fun newDemands
          in go acc' (Map.unionWith mappend rest nexts)
      | otherwise = acc

    backPropagate acc fun (DemandSet regs rets) =
      -- We need to push rets through the corresponding functions, and
      -- notify all functions which call fun regs. 
      let goRet addr retRegs =
            mconcat [ resultDemandsMap ^. ix addr ^. ix r | r <- Set.toList retRegs ]
          retDemands = Map.mapWithKey goRet rets

          regsDemands =
            Map.unionsWith mappend [ argDemandsMap ^. ix fun ^. ix r | r <- Set.toList regs ]

          newDemands = Map.unionWith mappend regsDemands retDemands

          -- All this in newDemands but not in acc
          novelDemands = Map.differenceWith diff newDemands acc
      in (novelDemands, Map.unionWith mappend acc novelDemands )

    diff ds1 ds2 =
        let ds' = ds1 `demandSetDifference` ds2 in
        if ds' == mempty then Nothing else Just ds'

transferDemands :: Map (Some N.RegisterName) DemandSet
                   -> DemandSet -> DemandSet
transferDemands xfer (DemandSet regs funs) =
  -- Using ix here means we ignore any registers we don't know about,
  -- e.g. caller-saved registers after a function call.
  -- FIXME: is this the correct behavior?
  mconcat (DemandSet mempty funs : [ xfer ^. ix r | r <- Set.toList regs ])

calculateLocalFixpoint :: Map BlockLabel DemandMap -> FunctionArgsM ()
calculateLocalFixpoint new
  | Just ((currLbl, newDemands), rest) <- Map.maxViewWithKey new =
      -- propagate backwards any new demands to the predecessors
      do preds <- use (blockPreds . ix (rootBlockLabel currLbl))
         nexts <- filter (not . Map.null . snd) <$> mapM (doOne newDemands) preds
         calculateLocalFixpoint (Map.unionWith demandMapUnion rest
                                 (Map.fromListWith demandMapUnion nexts))
  | otherwise = return ()
  where
    doOne :: DemandMap -> BlockLabel -> FunctionArgsM (BlockLabel, DemandMap)
    doOne newDemands predLbl = do
      xfer   <- use (blockTransfer . ix predLbl)

      let demands' = transferDemands xfer <$> newDemands
          lbl' = rootBlockLabel predLbl

      -- update uses, returning value before this iteration
      seenDemands <- use (blockDemandMap . ix lbl')
      blockDemandMap . at lbl' .= Just (Map.unionWith mappend demands' seenDemands)
      -- seenDemands <- blockDemandMap . ix lbl' <<%= demandMapUnion demands'

      return (lbl', Map.differenceWith diff demands' seenDemands)

    diff ds1 ds2 =
        let ds' = ds1 `demandSetDifference` ds2 in
        if ds' == mempty then Nothing else Just ds'

-- | Explore states until we have reached end of frontier.
summarizeIter :: InterpState
                 -> Set BlockLabel
                 -> Maybe BlockLabel
                 -> FunctionArgsM ()
summarizeIter _   _     Nothing = return ()
summarizeIter ist seen (Just lbl)
  | lbl `Set.member` seen = nextBlock >>= summarizeIter ist seen
  | otherwise = do summarizeBlock ist lbl
                   lbl' <- nextBlock
                   summarizeIter ist (Set.insert lbl seen) lbl'

-- A function call is the only block type that results in the
-- generation of function call demands, so we split that aspect out
-- (callee saved are handled in summarizeBlock).
summarizeCall :: BlockLabel -> X86State Value -> Either CodeAddr (Value (BVType 64))
                 -> FunctionArgsM ()
summarizeCall lbl proc_state (Left faddr) = do
  -- If a subsequent block demands r, then we note that we want r from
  -- function faddr
  traverse_ propResult x86ResultRegisters

  -- If a function wants argument register r, then we note that this
  -- block needs the corresponding state values.  Note that we could
  -- do this for _all_ registers, but this should make the summaries somewhat smaller.
  propArgument [Some N.rax] -- special var args register.
  propArgument (Some <$> x86ArgumentRegisters)
  propArgument (Some <$> x86FloatArgumentRegisters)
  where
    -- singleton for now, but propagating back will introduce more deps.
    demandSet sr         = DemandSet mempty (Map.singleton faddr (Set.singleton sr))
    propResult sr = 
      blockTransfer %= Map.insertWith (Map.unionWith mappend) lbl
                                      (Map.singleton sr (demandSet sr))

    -- FIXME: clag from recordPropagation
    propArgument rs = recordPropagation blockDemandMap lbl proc_state (DemandFunctionArg faddr) rs

-- In the dynamic case, we just assume all arguments (FIXME: results?)
summarizeCall lbl proc_state (Right _dynaddr) = do
  demandRegisters [Some N.rip]
  demandRegisters (Some <$> x86ArgumentRegisters)
  demandRegisters (Some <$> x86FloatArgumentRegisters) -- FIXME: required?
  where
    demandRegisters = recordPropagation blockDemandMap lbl proc_state (const DemandAlways)

-- | This function figures out what the block requires 
-- (i.e., addresses that are stored to, and the value stored), along
-- with a map of how demands by successor blocks map back to
-- assignments and registers.
summarizeBlock :: InterpState 
                  -> BlockLabel
                  -> FunctionArgsM ()
summarizeBlock interp_state root_label = go root_label
  where
    go :: BlockLabel -> FunctionArgsM ()
    go lbl = do
      Just (b, m_pterm) <- return $ getClassifyBlock lbl interp_state

      let goStmt (Write (MemLoc addr _tp) v)
            = do demandValue lbl addr
                 demandValue lbl v

          goStmt _ = return ()

          -- FIXME: rsp here?
          recordSyscallPropagation proc_state = 
            recordPropagation blockTransfer lbl proc_state Some 
                              (Some N.rsp : (Set.toList x86CalleeSavedRegisters))

      case m_pterm of
        Just (ParsedBranch c x y) -> do
          traverse_ goStmt (blockStmts b)
          demandValue lbl c
          go x
          go y

        Just (ParsedCall proc_state stmts' fn m_ret_addr) -> do
          traverse_ goStmt stmts'

          summarizeCall lbl proc_state fn 

          case m_ret_addr of
            Nothing       -> return ()
            Just ret_addr -> addEdge lbl (mkRootBlockLabel ret_addr)

          recordSyscallPropagation proc_state

        Just (ParsedJump proc_state tgt_addr) -> do 
          traverse_ goStmt (blockStmts b)
          -- record all propagations
          recordPropagation blockTransfer lbl proc_state Some x86StateRegisters
          addEdge lbl (mkRootBlockLabel tgt_addr)

        Just (ParsedReturn proc_state stmts') -> do
          traverse_ goStmt stmts'
          recordPropagation blockDemandMap lbl proc_state DemandFunctionResult
                            x86ResultRegisters

        -- FreeBSD follows the C ABI for function calls, except that
        -- rax contains the system call no.
        Just (ParsedSyscall proc_state next_addr _name argRegs) -> do
            -- FIXME: we ignore the return type for now.
            traverse_ goStmt (blockStmts b)
 
            recordPropagation blockDemandMap lbl proc_state (const DemandAlways) (Some <$> argRegs)

            recordSyscallPropagation proc_state
            addEdge lbl (mkRootBlockLabel next_addr)

        Just (ParsedLookupTable _proc_state _idx _vec) -> error "LookupTable"

        Nothing -> debugM DFunctionArgs ("WARNING: No parsed block type at " ++ show lbl) >> return ()

-- -----------------------------------------------------------------------------
-- debug
