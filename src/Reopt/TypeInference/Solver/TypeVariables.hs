{-# LANGUAGE OverloadedStrings #-}

module Reopt.TypeInference.Solver.TypeVariables (
  TyVar (TyVar, tyVarInt),
)
where

import Data.Function (on)
import Prettyprinter qualified as PP

import Reopt.TypeInference.Solver.UnionFindMap (UFMKeyInfo (..))

data TyVar = TyVar
  { tyVarInt :: Int
  , tyVarOrigin :: Maybe String
  -- ^ If you want to record the origin of this type variable, it will show
  -- out when you pretty-print it.  Recommended, except in the test suite
  -- where there is not much point in marking test type variables.
  }
  deriving (Show)

instance Eq TyVar where
  (==) = (==) `on` tyVarInt

instance Ord TyVar where
  compare = compare `on` tyVarInt

instance PP.Pretty TyVar where
  pretty tyv = PP.hcat ["α", PP.pretty (tyVarInt tyv), maybeOrigin (tyVarOrigin tyv)]
   where
    maybeOrigin Nothing = mempty
    maybeOrigin (Just origin) = PP.space <> PP.parens (PP.pretty origin)

instance UFMKeyInfo TyVar TyVar where
  compact _ x = x
  projectKey = id
  injectKey = id
  invertKey k _ = k
