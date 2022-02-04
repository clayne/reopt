{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module TyConstraintTests
  ( constraintTests,
  )
where

import Data.Bifunctor (bimap)
import Data.Function (on)
import Data.List (sortBy)
import qualified Data.Map as Map
import qualified Test.Tasty as T
import qualified Test.Tasty.HUnit as T
import qualified Prettyprinter as PP

import Reopt.TypeInference.Constraints
  (TyVar(..),
   RowVar(..),
   Ty(..),
   TyConstraint(..),
   ITy, FTy,
   unifyConstraints,
   eqTC,
   orTC,
   andTC,
   unknownTy,
   iRecTy,
   fRecTy)


x0,x1,x2,x3,x4,_x5  :: TyVar
x0Ty,x1Ty,x2Ty,x3Ty,x4Ty,_x5Ty  :: ITy
[(x0,x0Ty),
 (x1,x1Ty),
 (x2,x2Ty),
 (x3,x3Ty),
 (x4,x4Ty),
 (_x5,_x5Ty)] = map (\i -> (TyVar i, UnknownTy $ TyVar i))
                  [0..5]

r0,r1,_r2,_r3  :: RowVar
[r0,r1,_r2,_r3] = map RowVar [0..3]


constraintTests :: T.TestTree
constraintTests = T.testGroup "Type Constraint Tests"
  [ eqCTests,
    orCTests
  ]

num64 :: Ty tvar rvar
num64 = NumTy 64

-- Simple tests having to do with equality constraints
eqCTests :: T.TestTree
eqCTests = T.testGroup "Equality Constraint Tests"
  [ mkTest "Single eqTC var left"  [eqTC x0Ty num64] [(x0, num64)],
    mkTest "Single eqTC var right" [eqTC num64 x0Ty] [(x0, num64)],
    mkTest "Multiple eqTCs" [eqTC x0Ty num64, eqTC x1Ty (PtrTy num64)]
                            [(x0, num64), (x1, (PtrTy num64))],
    mkTest "eqTC simple transitivity 1"
     [eqTC x0Ty x1Ty, eqTC x1Ty num64]
     [(x0, num64), (x1, num64)],
    mkTest "eqTC simple Transitivity 2"
     [eqTC x1Ty num64, eqTC x0Ty x1Ty]
     [(x0, num64), (x1, num64)],
    mkTest "eqTC simple transitivity 3"
     [eqTC x1Ty x2Ty, eqTC x0Ty x1Ty, eqTC x2Ty num64]
     [(x0, num64), (x1, num64), (x2, num64)],
    mkTest "eqTC with pointers 1"
      [eqTC x1Ty x2Ty, eqTC x0Ty x1Ty, eqTC x2Ty num64, eqTC x3Ty (PtrTy x0Ty)]
      [(x0, num64), (x1, num64), (x2, num64), (x3, (PtrTy num64))],
    mkTest "eqTC with pointers 2"
      [eqTC x0Ty x2Ty, eqTC x1Ty (PtrTy x2Ty), eqTC x2Ty num64, eqTC x3Ty num64, eqTC x4Ty (PtrTy x3Ty)]
      [(x0, num64), (x1, (PtrTy num64)), (x2, num64), (x3, num64), (x4, (PtrTy num64))],
    mkTest "eqTC with pointers 3"
      [eqTC x0Ty x2Ty, eqTC x1Ty (PtrTy x2Ty), eqTC x3Ty num64, eqTC x4Ty (PtrTy x3Ty)]
      [(x0, unknownTy), (x1, (PtrTy (unknownTy))), (x2, unknownTy), (x3, num64), (x4, (PtrTy num64))],
    mkTest "eqTC with records 1"
      [eqTC x1Ty x2Ty, eqTC x0Ty x1Ty, eqTC x2Ty num64, eqTC x3Ty (iRecTy [(0, x0Ty)] r0)]
      [(x0, num64), (x1, num64), (x2, num64), (x3, (fRecTy [(0, num64)]))],
    mkTest "eqTC with records 2"
      [eqTC x1Ty x2Ty, eqTC x0Ty (PtrTy x1Ty), eqTC x2Ty num64, eqTC x3Ty (iRecTy [(0, x0Ty), (8, x1Ty)] r0)]
      [(x0, (PtrTy num64)), (x1, num64), (x2, num64), (x3, (fRecTy [(0, (PtrTy num64)), (8, num64)]))],
       -- These next tests check that record constraints are unified properly
       -- during constraint solving when there are possible unknown other fields
       -- (i.e., the row variables). This arises when we want to combine
       -- different atomic facts describing offsets from a single memory
       -- location. E.g., if we separately learn (1) at `p` there is a `num` and
       -- (2) at `p+8` there is an `ptr(num)`, these statements about `p` can be
       -- described via the following two atomic constraints: `p = {0 : num|ρ}`
       -- and `p = {8 : ptr(num)|ρ'}`. Our unification should then combine these
       -- constraints on `p` into `p = {0 : num, 8 : ptr(num)}`.
    mkTest "eqTC with records+rows 1"
      [eqTC x0Ty (iRecTy [(0, num64)] r0),
       eqTC x0Ty (iRecTy [(8, PtrTy num64)] r1)]
      [(x0, fRecTy [(0, num64), (8, PtrTy num64)])],
    mkTest "eqTC with records+rows 2"
      [eqTC x0Ty (iRecTy [(0, num64)] r0),
       eqTC x0Ty (iRecTy [(8, PtrTy num64)] r1),
       eqTC x1Ty (iRecTy [] r0),
       eqTC x2Ty (iRecTy [] r1)]
      [(x0, fRecTy [(0, num64), (8, PtrTy num64)]),
       (x1, fRecTy [(8, PtrTy num64)]),
       (x2, fRecTy [(0, num64)])],
    mkTest "eqTC with records+rows 3"
      [eqTC x0Ty (iRecTy [(0, num64), (8, PtrTy x1Ty)] r0),
       eqTC x0Ty (iRecTy [(8, PtrTy num64), (16, num64)] r1),
       eqTC x2Ty (iRecTy [] r0),
       eqTC x3Ty (iRecTy [] r1)]
      [(x0, fRecTy [(0, num64), (8, PtrTy num64), (16, num64)]),
       (x1, num64),
       (x2, fRecTy [(16, num64)]),
       (x3, fRecTy [(0, num64)])]

  ]


-- | Some (basic?) tests focusing on disjunctions.
orCTests :: T.TestTree
orCTests = T.testGroup "Disjunctive Constraint Tests"
  [ mkTest "NumTy/PtrTy or-resolution"
      [ orTC [andTC [eqTC x0Ty num64, eqTC x1Ty (PtrTy num64)],
              andTC [eqTC x1Ty num64, eqTC x0Ty (PtrTy num64)]],
        eqTC x0Ty num64]
      [(x0, num64),
       (x1, PtrTy num64)],
    mkTest "PtrTy target or-resolution"
      [ orTC [andTC [eqTC x0Ty (PtrTy x3Ty), eqTC x1Ty (PtrTy x4Ty)],
              andTC [eqTC x0Ty (PtrTy x4Ty), eqTC x1Ty (PtrTy x3Ty)]],
        eqTC x3Ty num64,
        eqTC x4Ty (PtrTy num64),
        eqTC x0Ty (PtrTy num64)]
      [(x0, (PtrTy num64)),
       (x1, PtrTy (PtrTy num64)),
       (x3, num64),
       (x4, (PtrTy num64))]

  ]


newtype TypeEnv = TypeEnv [(TyVar, FTy)]
  deriving (Eq)

instance Show TypeEnv where
  show (TypeEnv xs) = show $ bimap PP.pretty PP.pretty <$> xs

tyEnv :: [(TyVar, FTy)] -> TypeEnv
tyEnv = TypeEnv . sortBy (compare `on` fst)

mkTest :: String -> [TyConstraint] -> [(TyVar, FTy)] -> T.TestTree
mkTest name cs expected =
  let actual = Map.toList $ unifyConstraints cs
    in T.testCase name $ (tyEnv actual) T.@?= (tyEnv expected)
