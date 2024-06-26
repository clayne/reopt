{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE UndecidableInstances #-}

module Reopt.TypeInference.Solver.Constraints where

import Data.Function (on)
import Data.Set qualified as Set
import GHC.Generics (Generic)
import Prettyprinter qualified as PP
import Reopt.CFG.FnRep (FnArchConstraints, FnAssignment, FnStmt)
import Reopt.TypeInference.Solver.RowVariables (Offset, RowExpr)
import Reopt.TypeInference.Solver.TypeVariables (TyVar)
import Reopt.TypeInference.Solver.Types (
  FreeRowVars (..),
  FreeTyVars (..),
  ITy,
 )

-- | @EqC t1 t2@ means @t1@ and @t2@ are literally the same type.
data EqC = EqC
  { eqLhs :: !TyVar
  , eqRhs :: !ITy
  , eqProv :: !ConstraintProvenance
  }
  deriving (Show, Generic)

instance Eq EqC where
  x == y = ((==) `on` eqLhs) x y && ((==) `on` eqRhs) x y

instance Ord EqC where
  compare x y = (compare `on` eqLhs) x y <> (compare `on` eqRhs) x y

prettySExp :: [PP.Doc ann] -> PP.Doc ann
prettySExp docs = PP.group $ PP.encloseSep "(" ")" " " docs

-- | This intentionally does /not/ print 'eqProv' to keep the pretty-printed
-- output relatively compact. Use 'ppEqCWithProv' if you want to include
-- 'eqProv'.
instance PP.Pretty EqC where
  pretty = ppEqCWithoutProv
  -- pretty = ppEqCWithProv

-- | Pretty-print an 'EqC', omitting its provenance.
ppEqCWithoutProv :: EqC -> PP.Doc ann
ppEqCWithoutProv (EqC l r _) = prettySExp [PP.pretty l, "=", PP.pretty r]

-- | Pretty-print an 'EqC', including its provenance.
ppEqCWithProv :: EqC -> PP.Doc ann
ppEqCWithProv eqC =
  PP.align $
    PP.vsep
      [ ppEqCWithoutProv eqC
      , PP.hang 2 $ "Provenance: " <> PP.pretty (eqProv eqC)
      ]

instance FreeTyVars EqC where
  freeTyVars (EqC t1 t2 _) = Set.union (freeTyVars t1) (freeTyVars t2)

instance FreeRowVars EqC where
  freeRowVars (EqC t1 t2 _) = Set.union (freeRowVars t1) (freeRowVars t2)

-- | Stands for: lhs = { offsets | rhs }
data EqRowC = EqRowC
  { eqRowLHS :: !RowExpr
  , eqRowRHS :: !RowExpr
  }
  deriving (Eq, Ord, Show)

instance PP.Pretty EqRowC where
  pretty (EqRowC r1 r2) = prettySExp [PP.pretty r1, "=", PP.pretty r2]

instance FreeTyVars EqRowC where
  freeTyVars (EqRowC _ _) = mempty

instance FreeRowVars EqRowC where
  freeRowVars (EqRowC r1 r2) = freeRowVars r1 `Set.union` freeRowVars r2

-- --------------------------------------------------------------------------------
-- -- Pointer addition (maybe, could be number add)

-- | What sort of constant operand we are dealing with for an
-- addition.
data OperandClass
  = -- | The second operand is not a constant
    OCSymbolic
  | -- | The second operand is a small constant, we
    -- already know it is a number (from constraint
    -- generation.)
    OCOffset Offset
  | -- | The second operand could be in an ELF segment.
    OCPointer
  deriving (Eq, Ord, Show)

instance PP.Pretty OperandClass where
  pretty c =
    case c of
      OCSymbolic -> mempty
      OCOffset offset -> prettySExp ["+", PP.pretty offset]
      OCPointer -> "?"

instance FreeTyVars OperandClass where
  freeTyVars _ = mempty

-- data PtrAddC = PtrAddC
--   { ptrAddResult :: TyVar
--   , ptrAddLHS    :: TyVar
--   -- ^ The symbolic operand.
--   , ptrAddRHS    :: TyVar
--   , ptrAddClass  :: OperandClass
--   -- ^ If an operand is a constant then this is that constant.
--   }
--   deriving (Eq, Ord, Show)

-- instance PP.Pretty PtrAddC where
--   pretty (PtrAddC resTy lTy rTy oc) =
--     prettySExp [ PP.pretty resTy, "=", PP.pretty lTy, PP.pretty rTy, PP.pretty oc]

-- instance FreeTyVars PtrAddC where
--   freeTyVars (PtrAddC resTy lTy rTy oc) = Set.fromList [resTy, lTy, rTy] <> freeTyVars oc

-- instance FreeRowVars PtrAddC where
--   freeRowVars PtrAddC {} = mempty

--------------------------------------------------------------------------------
-- SubType

data SubC t = SubC !t !t
  deriving (Eq, Ord, Show, Functor, Foldable, Traversable)

infix 5 :<:
pattern (:<:) :: a -> a -> SubC a
pattern a :<: b = SubC a b
{-# COMPLETE (:<:) #-}

type SubTypeC = SubC TyVar
type SubRowC = SubC RowExpr

instance PP.Pretty a => PP.Pretty (SubC a) where
  pretty (a :<: b) =
    prettySExp [PP.pretty a, "<:", PP.pretty b]

instance FreeTyVars a => FreeTyVars (SubC a) where
  freeTyVars (a :<: b) = freeTyVars a `Set.union` freeTyVars b

instance FreeRowVars a => FreeRowVars (SubC a) where
  freeRowVars (a :<: b) = freeRowVars a `Set.union` freeRowVars b

--------------------------------------------------------------------------------
-- ConstraintProvenance

-- | The provenance (origin) of a constraint.
data ConstraintProvenance where
  -- | A constraint arising from a @FnRep@-related value.
  FnRepProv ::
    FnArchConstraints arch =>
    FnRepProvenance arch tp ->
    ConstraintProvenance
  -- | A placeholder origin to use for @_cgenConstraintProv@ before constraints
  -- have been generated for a particular block.
  BlockProv ::
    ConstraintProvenance
  -- | A constraint arising from a conflict during type inference.
  ConflictProv ::
    ConstraintProvenance
  -- | An 'EqC' that arose during unification.
  UnificationProv ::
    TyVar ->
    TyVar ->
    ConstraintProvenance
  -- | A generic origin to use for constraints arising from 'EqRowC'
  -- constraints. We may want to refine this to include more information.
  FromEqRowCProv ::
    ConstraintProvenance
  -- | A generic origin to use for constraints arising from 'SubRowC'
  -- constraints. We may want to refine this to include more information.
  FromSubRowCProv ::
    ConstraintProvenance
  -- | A generic origin to use for constraints arising from 'SubTypeC'
  -- constraints. We may want to refine this to include more information.
  FromSubTypeCProv ::
    ConstraintProvenance
  -- | A generic origin to use for constraints arising in test suites.
  TestingProv ::
    ConstraintProvenance
  DeclaredTypeProv :: ConstraintProvenance

instance PP.Pretty ConstraintProvenance where
  pretty (FnRepProv prov) = "FnRep:" PP.<+> PP.pretty prov
  pretty BlockProv = "BlockProv"
  pretty ConflictProv = "ConflictRep"
  pretty (UnificationProv tv1 tv2) =
    "UnificationProv" PP.<+> PP.pretty tv1 PP.<+> PP.pretty tv2
  pretty FromEqRowCProv = "FromEqRowCProv"
  pretty FromSubRowCProv = "FromSubRowCProv"
  pretty FromSubTypeCProv = "FromSubTypeCProv"
  pretty TestingProv = "TestingProv"
  pretty DeclaredTypeProv = "DeclaredTypeProv"

instance Show ConstraintProvenance where
  show = show . PP.pretty

-- | The provenance (origin) of a constraint arising from something
-- @FnRep@-related.
data FnRepProvenance arch tp where
  FnAssignmentProv ::
    FnAssignment arch tp ->
    FnRepProvenance arch tp
  FnStmtProv ::
    FnStmt arch ->
    FnRepProvenance arch tp

instance FnArchConstraints arch => PP.Pretty (FnRepProvenance arch tp) where
  pretty (FnAssignmentProv rhs) = PP.pretty rhs
  pretty (FnStmtProv stmt) = PP.pretty stmt

instance FnArchConstraints arch => Show (FnRepProvenance arch tp) where
  show = show . PP.pretty
