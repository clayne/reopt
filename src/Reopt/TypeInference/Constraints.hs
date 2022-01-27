{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- Loosely based on 'TIE: Principled Reverse Engineering of Types in Binary
-- Programs' (NDSS 2011) by Jonghyup Lee, Thanassis Avgerinos, and David Brumley

-- Not clear yet how much will directly be applicable etc.
module Reopt.TypeInference.Constraints where

import Control.Lens ( over )
import Control.Monad.State
    ( when, State, gets, execState, modify' )
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Generics.Product ( field )
import GHC.Generics ( Generic )
import qualified Prettyprinter as PP
-- import Data.List.NonEmpty (NonEmpty)
-- import qualified Data.List.NonEmpty as NonEmpty

import Debug.Trace ( trace )

-- | Set to @True@ to enable tracing in unification
traceUnification :: Bool
traceUnification = False

newtype TyVar = TyVar {tyVarInt :: Int }
  deriving (Eq, Ord, Show)

instance PP.Pretty TyVar where
  pretty (TyVar n) = "α" <> (PP.pretty n)

-- | Types of values in x86 machine code (missing reg types, records/memory, functions)
data Ty
  = -- | Top type (any kind of value).
    TopTy
  | -- | Bottom type (no possible values).
    BotTy
  | -- Type unification variable.
    VarTy TyVar
  | -- | A pointer of specified bit width pointing to some type of value
    -- (i.e., on X86_64 bit width would be 64).
    PtrTy Int Ty
  | -- | Code of specified bit width (i.e., on X86_64 bit width would be 64).
    CodeTy Int
  | -- | Register type of specified bit width (i.e., any value that can fit in a register of said size).
    RegTy Int
  | -- | Integer type of specified bit width (sign or unsigned).
    NumTy Int
  | -- | Unsigned integer type of specified bit width.
    UIntTy Int
  | -- | Signed integer type of specified bit width.
    IntTy Int
  | -- | Float type of specified bit width (e.g., float32, float64).
    FloatTy Int
  | -- | Record type, mapping bit offsets to types
    RecTy (Map Int Ty)
  | -- | Type indexing operator `ReadAtTy t i` describes a type which can be read
    -- starting `i` bits into type `t`. N.B., smart constructor `readAtTy` should be
    -- used to keep types in a normal form.
    ReadAtTy Ty Int
  | -- | Type updating operator `UpdateAtTy t1 i t2` describes a type `t1` which has
    -- been updated starting `i` bits into type to contain a `t2`. N.B., smart constructor
    -- `updateAtTy` should be used to keep types in a normal form.
    UpdateAtTy Ty Int Ty
  | -- | Intersection of two or more types. Should not contain duplicates or nested intersections.
    AndTy Ty Ty [Ty]
  | -- | Union of two or more types. Should not contain duplicates or nested unions.
    OrTy Ty Ty [Ty]
  deriving (Eq, Ord, Show)

instance PP.Pretty Ty where
  pretty = \case
    TopTy -> "⊤"
    BotTy -> "⊥"
    VarTy tv -> PP.pretty tv
    PtrTy n ty -> PP.parens $ "ptr" <> (PP.pretty n) PP.<+> PP.pretty ty
    CodeTy n -> "code" <> (PP.pretty n) <> "_t"
    RegTy n -> "reg"<>(PP.pretty n)<>"_t"
    NumTy n -> "num"<>(PP.pretty n)<>"_t"
    UIntTy n -> "uint"<>(PP.pretty n)<>"_t"
    IntTy n -> "int"<>(PP.pretty n)<>"_t"
    FloatTy n -> "float"<>(PP.pretty n)<>"_t"
    RecTy flds -> PP.group $ PP.encloseSep "{" "}" ", "
                  $ map (\(off,t) -> (PP.pretty off PP.<+> ":" PP.<+> PP.pretty t))
                  $ Map.toAscList flds
    ReadAtTy t i -> PP.pretty t <> "[" <> PP.pretty i<>"]"
    UpdateAtTy t1 i t2 -> "{"<> PP.pretty t1 <> " | "<> (PP.pretty i) <>" := " <> PP.pretty t2<>"}"
    AndTy ty1 ty2 tys -> PP.parens $ "∩" PP.<+> PP.hsep (map PP.pretty (ty1:ty2:tys))
    OrTy ty1 ty2 tys ->  PP.parens $ "∪" PP.<+> PP.hsep (map PP.pretty (ty1:ty2:tys))

--- | Is this a base type? I.e., a type that can always fit in a single register.
isBaseTy :: Ty -> Bool
isBaseTy t = case t of
  TopTy -> False
  BotTy -> False
  VarTy{} -> False
  PtrTy{} -> True
  CodeTy{} -> True
  RegTy{} -> True
  NumTy{} -> True
  UIntTy{} -> True
  IntTy{} -> True
  FloatTy{} -> True
  RecTy{} -> False
  ReadAtTy{} -> False
  UpdateAtTy{} -> False
  AndTy{} -> False
  OrTy{} -> False

reg1Ty, reg8Ty, reg16Ty, reg32Ty, reg64Ty :: Ty
reg1Ty  = RegTy 1
reg8Ty  = RegTy 8
reg16Ty = RegTy 16
reg32Ty = RegTy 32
reg64Ty = RegTy 64

uint8Ty, uint16Ty, uint32Ty, uint64Ty :: Ty
uint8Ty  = UIntTy 8
uint16Ty = UIntTy 16
uint32Ty = UIntTy 32
uint64Ty = UIntTy 64

int8Ty, int16Ty, int32Ty, int64Ty :: Ty
int8Ty  = IntTy 8
int16Ty = IntTy 16
int32Ty = IntTy 32
int64Ty = IntTy 64

num8Ty, num16Ty, num32Ty, num64Ty :: Ty
num8Ty  = NumTy 8
num16Ty = NumTy 16
num32Ty = NumTy 32
num64Ty = NumTy 64

float32Ty, float64Ty :: Ty
float32Ty = FloatTy 32
float64Ty = FloatTy 64

-- Constructs a pointer type, simplifying some cases.
ptrTy :: Int -> Ty -> Ty
ptrTy _ BotTy = BotTy
ptrTy w t = PtrTy w t

-- | @readAtTy t i@ is the type which begins @i@ bits into @t@.
readAtTy :: Ty -> Int -> Ty
readAtTy t@(RecTy flds) i = Map.findWithDefault (ReadAtTy t i) i flds
readAtTy (UpdateAtTy _ i t2) j | i == j = t2
readAtTy t i = ReadAtTy t i

-- | @updateAtTy t1 i t2@ is the result up writing a @t2@ at @i@ bits into @t1@.
updateAtTy :: Ty -> Int -> Ty -> Ty
updateAtTy (RecTy flds) i iTy = recTy $ Map.insert i iTy flds
updateAtTy t1 i t2 = UpdateAtTy t1 i t2

-- Constructs an intersection type, simplifying some basic cases.
andTy :: [Ty] -> Ty
andTy = go Set.empty
  where go :: Set Ty -> [Ty] -> Ty
        go acc [] = case Set.toAscList acc of
                      [] -> TopTy
                      [t] -> t
                      t1:t2:ts -> AndTy t1 t2 ts
        go acc (TopTy:ts) = go acc ts
        go _   (BotTy:_) = BotTy
        go acc (AndTy s1 s2 ss:ts) = go acc (s1:s2:(ss++ts))
        go acc (t:ts) = go (Set.insert t acc) ts


-- Constructs a union type, simplifying some basic cases.
orTy :: [Ty] -> Ty
orTy = go Set.empty
  where go :: Set Ty -> [Ty] -> Ty
        go acc [] = case Set.toAscList acc of
                      [] -> BotTy
                      [t] -> t
                      t1:t2:ts -> OrTy t1 t2 ts
        go acc (BotTy:ts) = go acc ts
        go _   (TopTy:_) = TopTy
        go acc (OrTy s1 s2 ss:ts) = go acc (s1:s2:(ss++ts))
        go acc (t:ts) = go (Set.insert t acc) ts


-- Constructs a record type, simplifying some cases. (AMK: should we flatten
-- nested structs...?)
recTy :: Map Int Ty -> Ty
recTy flds = if any (== BotTy) (Map.elems flds) then BotTy else RecTy flds

-- Constructs a record type from an association list.
recTy' :: [(Int,Ty)] -> Ty
recTy' = recTy . Map.fromList


-- | Return the given type with all type variables replaced via the lookup function.
concretize :: Ty -> (TyVar -> Ty) -> Ty
concretize initialTy lookupVar = go initialTy
  where
    go :: Ty -> Ty
    go TopTy       = TopTy
    go BotTy       = BotTy
    go t@CodeTy{}  = t
    go t@RegTy{}   = t
    go t@NumTy{}   = t
    go t@IntTy{}   = t
    go t@UIntTy{}  = t
    go t@FloatTy{} = t
    go (VarTy x)   = lookupVar x
    go (PtrTy w t) = ptrTy w (go t)
    go (RecTy flds) = recTy $ fmap go flds
    go (ReadAtTy t i) = readAtTy (go t) i
    go (UpdateAtTy t1 i t2) = updateAtTy (go t1) i (go t2)
    go (AndTy t1 t2 ts) = andTy $ map go (t1:t2:ts)
    go (OrTy t1 t2 ts)  = orTy  $ map go (t1:t2:ts)

-- | @concretize@ except in a monadic context.
concretizeM :: forall m. Monad m => Ty -> (TyVar -> m Ty) -> m Ty
concretizeM initialTy lookupVar = go initialTy
  where
    go :: Ty -> m Ty
    go TopTy       = pure TopTy
    go BotTy       = pure BotTy
    go t@CodeTy{}  = pure t
    go t@RegTy{}   = pure t
    go t@NumTy{}   = pure t
    go t@IntTy{}   = pure t
    go t@UIntTy{}  = pure t
    go t@FloatTy{} = pure t
    go (VarTy x)   = lookupVar x
    go (PtrTy w t) = ptrTy w <$> (go t)
    go (RecTy flds) = recTy <$> traverse go flds
    go (ReadAtTy t i) = do t' <- go t
                           pure $ readAtTy t' i
    go (UpdateAtTy t1 i t2) = do t1' <- go t1
                                 t2' <- go t2
                                 pure $ updateAtTy t1' i t2'
    go (AndTy t1 t2 ts) = andTy <$> mapM go (t1:t2:ts)
    go (OrTy t1 t2 ts)  = orTy  <$> mapM go (t1:t2:ts)

-- | @subst x t1 t2@ says substitute appearances of @x@ out for @t1@ in @t2@.
subst :: TyVar -> Ty -> Ty -> Ty
subst x xTy ty = concretize ty (\y -> if x == y then xTy else (VarTy y))

-- | Customizations when calculating subtypes.
data SubtypeOptions
  = SubtypeOptions
    { -- | A function for resolving type variables on the
      --  left/lower side of the subtype inquiry.
      soResolveL :: TyVar -> Ty,
      -- | A function for resolving type variables on the
      --  right/upper side of the subtype inquiry.
      soResolveR :: TyVar -> Ty,
      -- | How to handle the fields of two record types, given a
      -- subtyping function for recursive calls.
      soRecordFields :: (Ty -> Ty -> Bool) -> (Map Int Ty) -> (Map Int Ty) -> Bool
    }

dfltSubtypeOpts :: SubtypeOptions
dfltSubtypeOpts =
  SubtypeOptions
  { soResolveL = VarTy,
    soResolveR = VarTy,
    soRecordFields = \subty flds1 flds2 ->
      all (\(fld, fldTy2) ->
            case Map.lookup fld flds1 of
              Nothing -> False
              Just fldTy1 -> subty fldTy1 fldTy2)
          $ Map.toList flds2
  }

-- | @subtype' f g s t@ computes whether `s <: t` holds, applying @f@ to resolve
-- type variables on the left and @g@ to resolve type variables on the right.
subtype' :: SubtypeOptions -> Ty -> Ty -> Bool
subtype' opts = go
  where
    go :: Ty -> Ty -> Bool
    go type1 type2 =
      case (type1,type2) of
        -- Reflexivity
        (s,t) | s == t -> True
        -- Top/Bot
        (_, TopTy) -> True
        (BotTy, _) -> True
        -- Pointer subtypes
        (PtrTy w1 s, PtrTy w2 t) -> w1 <= w2 && go s t
        -- Register subtypes
        (RegTy w1,   RegTy w2) -> w1 <= w2
        (PtrTy w1 _, RegTy w2) -> w1 <= w2
        (CodeTy w1,  RegTy w2) -> w1 <= w2
        (NumTy w1,   RegTy w2) -> w1 <= w2
        (IntTy w1,   RegTy w2) -> w1 <= w2
        (UIntTy w1,  RegTy w2) -> w1 <= w2
        -- Numeric (signed/unsigned integer) subtypes
        (NumTy w1,  NumTy w2) -> w1 <= w2
        (IntTy w1,  NumTy w2) -> w1 <= w2
        (UIntTy w1, NumTy w2) -> w1 <= w2
        -- Signed/Unsigned integer subtypes
        (IntTy w1,  IntTy w2)  -> w1 <= w2
        (UIntTy w1, UIntTy w2) -> w1 <= w2
        -- Records
        (RecTy flds1, RecTy flds2) ->
          (soRecordFields opts) go flds1 flds2
        (t1@RecTy{}, t2) -> go t1 (recTy' [(0,t2)])
        (t1, t2@RecTy{}) -> go (recTy' [(0,t1)]) t2
        -- Set-theoretic subtypes
        (AndTy s1 s2 ss, t) -> any (\s -> go s t) (s1:s2:ss)
        (OrTy s1 s2 ss, t)  -> all (\s -> go s t) (s1:s2:ss)
        (s, AndTy t1 t2 ts) -> all (go s) (t1:t2:ts)
        (s, OrTy t1 t2 ts)  -> any (go s) (t1:t2:ts)
        -- Type Variable special handling
        (VarTy x, t) -> let xTy = (soResolveL opts) x in
                          if xTy == type1
                            then False
                            else go xTy t
        (s, VarTy y) -> let yTy = (soResolveR opts) y in
                          if yTy == type2
                            then False
                            else go s yTy
        -- Type operators
        (ReadAtTy s i, ReadAtTy t j) | i == j -> go s t
        (UpdateAtTy s1 i s2, UpdateAtTy t1 j t2) | i == j-> go s1 t1 && go s2 t2
        -- Conservative base case
        (_, _) -> False

-- | Whether `s <: t` holds. This function is sound but not complete (i.e., with
-- a _syntactic_ treatment of set-theoretic types, it is _possible_ to return
-- @False@ erroneously, but @True@ is always sound).
subtype :: Ty -> Ty -> Bool
subtype = subtype' opts
  where opts = dfltSubtypeOpts

-- | Sound but possibly incomplete check if the type is uninhabited. I.e.,
-- @True@ means the type _is_ uninhabited, but @False@ could mean the type is
-- _possibly_ uninhabited (i.e., set-theoretic types can get complicated).
uninhabited :: Ty -> Bool
uninhabited = \case
  TopTy -> False
  BotTy -> True
  VarTy{} -> False
  PtrTy _ ty -> uninhabited ty
  CodeTy{} -> False
  RegTy{} -> False
  NumTy{} -> False
  UIntTy{} -> False
  IntTy{} -> False
  FloatTy{} -> False
  RecTy flds -> any uninhabited $ Map.elems flds
  ReadAtTy t _i -> uninhabited t
  UpdateAtTy t1 _j t2 -> uninhabited t1 || uninhabited t2
  AndTy t1 t2 ts -> any uninhabited (t1:t2:ts) -- may return False conservatively
  OrTy  t1 t2 ts -> all uninhabited (t1:t2:ts)

-- | `upperBound t1 t2 == t3` where `t3` is the least upper bound of two types
-- `t1` and `t2` (denoted by the “join” operator ⊔). I.e., `t3` should be the
-- "smallest" type (lowest in the subtype lattice) s.t. `t1 <: t3` and `t2 <: t3`,
-- where "smallest" is aspirational/pragmatic.
upperBound :: Ty -> Ty -> Ty
upperBound type1 type2 =
    case (type1,type2) of
    -- J-Subtype
    (s, t) | subtype s t -> t
    (s, t) | subtype t s -> s
    -- J-TypeVar
    (s@(VarTy _), t) -> orTy [s,t]
    (s, t@(VarTy _)) -> orTy [s,t]
    -- J-Ptr (N.B., TIE uses ⊓ in this rule, but I think that's a typo)
    ((PtrTy w1 s), (PtrTy w2 t)) | w1 == w2 -> ptrTy w1 (upperBound s t)
    -- J-RecBase
    -- // FIXME (?) these cases are in the TIE paper, but without more
    -- complex record upper bound calculations there arguably useless (i.e.,
    -- subtyping would already have checked the same thing, and so we likely
    -- will just get `TopTy` out as `upperBound` doesn't know what to do with
    -- two record types currently)
    (t1, t2@RecTy{}) | isBaseTy t1 -> upperBound (recTy' [(0,t1)]) t2
    (t1@RecTy{}, t2) | isBaseTy t2 -> upperBound t1 (recTy' [(0,t2)])
    -- M-Rec (not included in TIE but seems sound and useful)
    -- ((RecTy flds1), (RecTy flds2)) -> recTy $ Map.unionWith upperBound flds1 flds2
    -- J-NoRel
    (_,_) -> TopTy

-- | `lowerBound t1 t2 == t3` where `t3` is the greatest lower bound of two types
-- `t1` and `t2` (denoted by the "meet" operator ⊓). I.e., `t3` should be the
-- "largest" type (highest in the subtype lattice) s.t. `t3 <: t1` and `t3 <: t2`,
-- where "largest" is aspirational/pragmatic.
lowerBound :: Ty -> Ty -> Ty
lowerBound type1 type2 =
  case (type1,type2) of
    (s,t) | s == t -> s
    -- M-Subtype
    (s, t) | subtype s t -> s
    (s, t) | subtype t s -> t
    -- M-TypeVar
    (s@(VarTy _), t) -> andTy [s,t]
    (s, t@(VarTy _)) -> andTy [s,t]
    -- M-Ptr
    ((PtrTy w1 s), (PtrTy w2 t)) | w1 == w2 -> ptrTy w1 (lowerBound s t)
    -- M-Rec (not included in TIE but seems sound and useful)
    ((RecTy flds1), (RecTy flds2)) -> recTy $ Map.unionWith lowerBound flds1 flds2
    -- M-RecBase
    (t1, t2@RecTy{}) | isBaseTy t1 -> lowerBound (recTy' [(0,t1)]) t2
    (t1@RecTy{}, t2) | isBaseTy t2 -> lowerBound t1 (recTy' [(0,t2)])
    -- M-NoRel
    (_,_) -> BotTy

tyFreeVars :: Ty -> Set TyVar
tyFreeVars =
    \case
      TopTy -> Set.empty
      BotTy -> Set.empty
      VarTy x -> Set.singleton x
      PtrTy _ t -> tyFreeVars t
      CodeTy{} -> Set.empty
      RegTy{} -> Set.empty
      NumTy{} -> Set.empty
      IntTy{} -> Set.empty
      UIntTy{} -> Set.empty
      FloatTy{} -> Set.empty
      RecTy flds -> foldr (Set.union . tyFreeVars) Set.empty $ Map.elems flds
      ReadAtTy t _i -> tyFreeVars t
      UpdateAtTy t1 _j t2 -> Set.union (tyFreeVars t1) (tyFreeVars t2)
      AndTy t1 t2 ts -> foldr (Set.union . tyFreeVars) Set.empty (t1:t2:ts)
      OrTy t1 t2 ts  -> foldr (Set.union . tyFreeVars) Set.empty (t1:t2:ts)

-- | @occursIn x t@, does `x` appear in `t`?
occursIn :: TyVar -> Ty -> Bool
occursIn x ty = Set.member x $ tyFreeVars ty

-- | x86 type constraints
data TyConstraint
  = -- | The trivial constraint.
    TopC
  | -- | The absurd constraint.
    BotC
  |  -- | An equality constraint.
    EqC Ty Ty
  | -- | A subtype constraint.
    SubC Ty Ty
  | OrC  TyConstraint TyConstraint [TyConstraint]
  | AndC TyConstraint TyConstraint [TyConstraint]
  deriving (Eq, Ord, Show)

prettySExp :: [PP.Doc ann] -> PP.Doc ann
prettySExp docs = PP.group $ PP.encloseSep "(" ")" " " docs

instance PP.Pretty TyConstraint where
  pretty TopC = "tt"
  pretty BotC = "ff"
  pretty (EqC l r) = PP.parens $ (PP.pretty l) PP.<+> "=" PP.<+> (PP.pretty r)
  pretty (SubC l r) = PP.parens $ (PP.pretty l) PP.<+> "<:" PP.<+> (PP.pretty r)
  pretty (OrC c1 c2 cs) = prettySExp  $ "or":(map PP.pretty (c1:c2:cs))
  pretty (AndC c1 c2 cs) = prettySExp $ "and":(map PP.pretty (c1:c2:cs))

eqC :: Ty -> Ty -> TyConstraint
eqC lhs rhs = EqC lhs rhs

subC :: Ty -> Ty -> TyConstraint
subC lhs rhs = SubC lhs rhs


-- Constructs a conjunction constraint, simplifying some basic cases.
andC :: [TyConstraint] -> TyConstraint
andC = go Set.empty
  where go :: Set TyConstraint -> [TyConstraint] -> TyConstraint
        go acc [] = case Set.toAscList acc of
                      [] -> EqC TopTy TopTy
                      [c] -> c
                      c1:c2:cs -> AndC c1 c2 cs
        go _   (BotC:_) = BotC
        go acc (TopC:cs) = go acc cs
        go acc (c@EqC{}:cs) = go (Set.insert c acc) cs
        go acc (c@SubC{}:cs) = go (Set.insert c acc) cs
        go acc (AndC c1 c2 cs:cs') = go acc (c1:c2:(cs++cs'))
        go acc (c@OrC{}:cs) = go (Set.insert c acc) cs


-- Constructs a disjunction constraint, simplifying some basic cases.
orC :: [TyConstraint] -> TyConstraint
orC = go Set.empty
  where go :: Set TyConstraint -> [TyConstraint] -> TyConstraint
        go acc [] = case Set.toAscList acc of
                      [] -> EqC BotTy TopTy
                      [c] -> c
                      c1:c2:cs -> OrC c1 c2 cs
        go acc (BotC:cs) = go acc cs
        go _   (TopC:_) = TopC
        go acc (c@EqC{}:cs) = go (Set.insert c acc) cs
        go acc (c@SubC{}:cs) = go (Set.insert c acc) cs
        go acc (OrC c1 c2 cs:cs') = go acc (c1:c2:(cs++cs'))
        go acc (c@AndC{}:cs) = go (Set.insert c acc) cs

-- | Constrain the given type to be some kind of 64 bit pointer.
-- @isPtr64ToSubC t1 t2@ constrains @t1@ to be a 64bit pointer
-- to a subtype of @t2@.
isPtr64ToSubC :: Ty -> Ty -> TyConstraint
isPtr64ToSubC t1 t2 = SubC t1 (ptrTy 64 t2)

-- | Constrain the given type to be some kind of 64 bit number (i.e.,
-- non-pointer). IMPORTANT: our use of @EqC@ is tied to us not currently
-- explicitly reasoning about what _kind_ of integer types things are. If
-- we start wanting to distinguish int32/int64/uint32/uint64/etc then
-- this should be a @SubC@.
isNum64C :: Ty -> TyConstraint
isNum64C t = EqC t num64Ty

-- | @isSizedPtr64SubC sz t@ constraints @t@ to be a subtype of
-- a value that fits in a @RegTy sz@.
isSizedPtr64SubC :: Int -> Ty -> TyConstraint
isSizedPtr64SubC sz t = SubC t (ptrTy 64 (RegTy sz))

cFreeVars :: TyConstraint -> Set TyVar
cFreeVars TopC = Set.empty
cFreeVars BotC = Set.empty
cFreeVars (EqC s t) = Set.union (tyFreeVars s) (tyFreeVars t)
cFreeVars (SubC s t) = Set.union (tyFreeVars s) (tyFreeVars t)
cFreeVars (OrC c1 c2 cs) = foldr (Set.union . cFreeVars) Set.empty (c1:c2:cs)
cFreeVars (AndC c1 c2 cs) = foldr (Set.union . cFreeVars) Set.empty (c1:c2:cs)


-- cSubst :: TyVar -> Ty -> TyConstraint -> TyConstraint
-- cSubst x xTy constraint = go constraint
--   where go :: TyConstraint -> TyConstraint
--         go (EqC t1 t2)  = EqC (subst x xTy t1) (subst x xTy t2)
--         go (SubC t1 t2) = SubC (subst x xTy t1) (subst x xTy t2)
--         go (OrC cs)     = OrC (map go cs)
--         go (AndC cs)    = AndC (map go cs)


-- | @decompSubC t1 t2@ decomposes `t1 <: t2` into any implied constraints. Cf.
-- TIE's `Υ` operator from § 6.3.2.
decomposeSubC :: Ty -> Ty -> [TyConstraint]
decomposeSubC type1 type2 =
  case (type1,type2) of
    ((PtrTy w1 s), (PtrTy w2 t)) | w1 == w2 ->  [SubC s t]
    (s, (AndTy t1 t2 ts)) -> map (SubC s) (t1:t2:ts)
    ((OrTy s1 s2 ss), t) -> map (\s -> SubC s t) (s1:s2:ss)
    _ -> []

-- | Constraints and working sets. Cf. `C` and related sets/maps in TIE § 6.3. N.B., in TIE,
-- substutition is used on the entire `C` set frequently. We prefer lazily
-- performing these substitutions _as we handle constraints_, via @substEqs@
-- and the relevant @Context@.
data Context
  = Context
    { -- | Equality constraints, i.e. each `(s,t)` means `s == t`. Cf. `C` from TIE § 6.3.
      ctxEqConstraints  :: [(Ty, Ty)]
      -- | Equality constraints that were dropped.
    , ctxDroppedEqConstraints :: [(Ty, Ty)]
      -- | Occurs check failures.
    , ctxOccursCheckFailures :: [(Ty, Ty)]
    , -- | Subtype constraints, i.e. each `(s,t)` means `s <: t`. Cf. `C` from TIE § 6.3.
      ctxSubConstraints :: [(Ty, Ty)]
      -- | Constraints that were deemed to be absurd.
    , ctxAbsurdConstraints :: [TyConstraint]
    , -- | Disjunctive constraints, i.e. each `[c1,c2,...]` means `c1 ∨ c2 ∨ ...`. Cf. `C` from TIE § 6.3.
      ctxOrConstraints  :: [[TyConstraint]]
      -- | Map from type variables to their known subtypes and supertypes.
      -- Cf.`S_{<:}` from TIE § 6.3.
    , ctxSubtypeMap :: Map TyVar (Set Ty, Set Ty)
    -- | Known type for type variables. `S_{=}` from TIE § 6.3. N.B., this map
    -- is used in conjunction with `substEqs` to apply substitutions lazily.
    , ctxVarEqMap :: Map TyVar Ty
    -- | Lower and upper bounds for type variables. `B^{↓}` and `B^{↑}` from TIE § 6.3.
    , ctxVarBoundsMap :: Map TyVar (Ty, Ty)
    }
  deriving (Eq, Generic, Ord, Show)

instance PP.Pretty Context where
  pretty ctx = let binop op (l,r) = (PP.pretty l) PP.<+> op PP.<+> (PP.pretty r)
                   row title entries = title PP.<+> PP.list entries in
                  PP.vsep
                  [ row "Equalities" $ map (binop "=") $ ctxEqConstraints ctx
                  , row "Dropped Equalities" $ map (binop "=") $ ctxDroppedEqConstraints ctx
                  , row "Occurs check failures" $ map (binop "=") $ ctxOccursCheckFailures ctx
                  , row "Subtypes" $ map (binop "<:") $ ctxSubConstraints ctx
                  , row "Absurd Constraints" $ map PP.pretty $ ctxAbsurdConstraints ctx
                  , row "Ors" $ map (\cs -> prettySExp $ "or":map PP.pretty cs) $ ctxOrConstraints ctx
                  , row "S_{<:}" $ map (\(x,(ls,us)) -> (PP.encloseSep "{" "}" "," $ map PP.pretty $ Set.toList ls)
                                                      PP.<+> "<:" PP.<+> PP.pretty x PP.<+> "<:"
                                                      PP.<+> (PP.encloseSep "{" "}" "," $ map PP.pretty $ Set.toList us))
                                 $ Map.toList $ ctxSubtypeMap ctx
                  , row "S_{=}" $ map (binop "↦") $ Map.toList $ ctxVarEqMap ctx
                  , row "B^{↓}/B^{↑}" $ map (\(x,(l,u)) -> PP.pretty l PP.<+> "<:" PP.<+> PP.pretty x PP.<+> "<:" PP.<+> PP.pretty u)
                                      $ Map.toList $ ctxVarBoundsMap ctx
                  ]

-- | Does the context have any equality or subtype constraints left to process?
hasAtomicConstraints :: Context -> Bool
hasAtomicConstraints ctx =
  ctxEqConstraints ctx /= [] || ctxSubConstraints ctx /= []

dequeueEqC :: Context -> Maybe (Context, (Ty,Ty))
dequeueEqC ctx = case ctxEqConstraints ctx of
                  [] -> Nothing
                  c:cs -> Just (ctx{ctxEqConstraints=cs},c)

dequeueSubC :: Context -> Maybe (Context, (Ty,Ty))
dequeueSubC ctx = case ctxSubConstraints ctx of
                   [] -> Nothing
                   c:cs -> Just (ctx{ctxSubConstraints=cs},c)


addConstraints :: [TyConstraint] -> Context -> Context
addConstraints = flip addConstraints'

addConstraints' :: Context -> [TyConstraint] -> Context
addConstraints' = foldr go
  where
    go TopC = id
    go BotC = over (field @"ctxAbsurdConstraints") (BotC :)
    go (EqC t1 t2) = over (field @"ctxEqConstraints") ((t1, t2) :)
    go (SubC t1 t2) = over (field @"ctxSubConstraints") ((t1, t2) :)
    go (OrC c1 c2 cs') = over (field @"ctxOrConstraints") ((c1 : c2 : cs') :)
    go (AndC c1 c2 cs') = addConstraints (c1 : c2 : cs')

emptyContext :: Context
emptyContext = Context [] [] [] [] [] [] Map.empty Map.empty Map.empty

-- | Partition the constraints into the @Context@, which we use to order
-- which are handled when during unification.
initContext :: [TyConstraint] -> Context
initContext = addConstraints' emptyContext

-- | Perform the substitutions implied thus far by the @Context@'s
-- @ctxVarTypes@ map. (This is to avoid performing repeated substitutions on the
-- entire constraint set.)
substEqs :: Ty -> Context -> Ty
substEqs t ctx = concretize t lookupVar
  where lookupVar x = Map.findWithDefault (VarTy x) x (ctxVarEqMap ctx)

-- | Naive lookup for the type interval `(s,t)` for variable `x` in the given
-- bound map s.t. `s <: x <: t`. Default interval is `(⊥,⊤)`.
findTyInterval :: TyVar -> Map TyVar (Ty, Ty) -> (Ty, Ty)
findTyInterval = Map.findWithDefault (BotTy, TopTy)

-- | Naive lookup for the upper bound `t` of variable `x` in the given
-- bound map s.t. `x <: t`.
findUpperBound :: TyVar -> Map TyVar (Ty, Ty) -> Ty
findUpperBound x = snd . findTyInterval x

-- | Naive lookup for the lower bound `s` of variable `x` in the given
-- bound map s.t. `s <: x`.
findLowerBound :: TyVar -> Map TyVar (Ty, Ty) -> Ty
findLowerBound x = fst . findTyInterval x

-- | Concretize the type using any available upper bounds for type variables from
-- the current context.
upperConcretization :: Ty -> Context -> Ty
upperConcretization t ctx = concretize t lookupVar
  where lookupVar x = findUpperBound x (ctxVarBoundsMap ctx)

-- | Concretize the type using any available lower bounds for type variables from
-- the current context.
lowerConcretization :: Ty -> Context -> Ty
lowerConcretization t ctx = concretize t lookupVar
  where lookupVar x = findLowerBound x (ctxVarBoundsMap ctx)


-- | Is this subtype constraint trivial in the current context?
trivialSubC ::  Context -> Ty -> Ty -> Bool
trivialSubC ctx = subtype' opts
  where resolveVar x = Map.findWithDefault (VarTy x) x (ctxVarEqMap ctx)
        opts = dfltSubtypeOpts {soResolveL = resolveVar, soResolveR = resolveVar}

-- | @absurdSubC s t ctx@ returns @True@ if `s <: t` is an absurd constraint
-- given `ctx`. N.B., this is intended to be a conservative check s.t. if @True@
-- then the subtype constraint is indeed absurd, but @False@ could simply mean
-- it's too hard to tell and so we can't rule it out.
absurdSubC ::  Context -> Ty -> Ty -> Bool
absurdSubC ctx = \s t -> not $ subtype' opts s t
  where resolveVar findBound x = case Map.lookup x $ ctxVarEqMap ctx of
                                   Nothing -> findBound x (ctxVarBoundsMap ctx)
                                   Just xTy -> xTy
        opts = SubtypeOptions
               { soResolveL = resolveVar findLowerBound,
                 soResolveR = resolveVar findUpperBound,
                  -- We want to check that for all the shared fields
                  -- their are no absurd subtype implications.
                 soRecordFields =
                   \subty flds1 flds2 ->
                     all (\(fld, fldTy2) ->
                            case Map.lookup fld flds1 of
                              Nothing -> True
                              Just fldTy1 -> subty fldTy1 fldTy2)
                          $ Map.toList flds2
               }

-- | Is this equality constraint trivial in the current context?
trivialEqC ::  Context -> Ty -> Ty -> Bool
trivialEqC ctx s t = trivialSubC ctx s t && trivialSubC ctx t s

-- | @absurdEqC s t ctx@ returns @True@ if `s = t` is an absurd constraint given `ctx`.
absurdEqC :: Context -> Ty -> Ty -> Bool
absurdEqC ctx s t =  (absurdSubC ctx s t) || (absurdSubC ctx t s)


-- | @traceContext description ctx ctx'@ reports how the context changed via @trace@.
traceContext :: PP.Doc () -> Context -> Context -> Context
traceContext description preCtx postCtx =
  if not traceUnification then postCtx else
    let msg = PP.vsep [PP.hsep [">>> ", description]
                      , PP.indent 4 $ PP.pretty preCtx
                      , PP.hsep ["<<< ", description]
                      , PP.indent 4 $ PP.pretty postCtx]
      in trace (show msg) postCtx

traceCOpContext :: PP.Doc () -> TyConstraint -> Context -> Context -> Context
traceCOpContext fnNm c ctx ctx' =
  traceContext (fnNm<>"(" <> (PP.pretty $ c)<> ")") ctx ctx'

-- | @solveEqC (s,t) ctx@ updates @ctx@ with the equality
-- `s == t`. Cf. TIE Algorithm 1. If @Nothing@ is returned, the equality
-- failed the occurs check. FIXME should we have a `decomposeEqC` similar to `decomposeSubC`?
solveEqC :: Context -> (Ty,Ty) -> Context
solveEqC ctx (type1, type2) = traceCOpContext "solveEqC" (EqC type1 type2) ctx $
  go (substEqs type1 ctx) (substEqs type2 ctx)
  where go :: Ty -> Ty -> Context
        go s@(VarTy x) t =
          if occursIn x t
            then over (field @"ctxOccursCheckFailures") ((s, t) :) ctx
            else over (field @"ctxVarEqMap" ) (Map.insert x t) ctx
        go s t@(VarTy _) = go t s
        go (PtrTy _w1 s) (PtrTy _w2 t) = over (field @"ctxEqConstraints") ((s, t) :) ctx
        go (RecTy flds1) (RecTy flds2) =
          let fldEqCs = Map.elems $ Map.intersectionWith (,) flds1 flds2
          in over (field @"ctxEqConstraints") (fldEqCs ++) ctx
        go s t = if absurdEqC ctx s t
                 then over (field @"ctxAbsurdConstraints") (EqC s t :) ctx
                 else over (field @"ctxDroppedEqConstraints") ((s, t) :) ctx


-- | @upperBoundsClosure s t ctx@ says given `s <: t`, for all type variables
-- `α` where `α <: s`, we add `α <: t`, update the upper bound of `α`, and
-- record any implied information from `α <: s`. Cf. rule (2) in the
-- Decomposition Rules of § 6.3.2. N.B., we interpret the `S <: T` constraint
-- described by TIE to include any `S` and `T`, but for `∀(α <: S)` to quantify
-- only over known subtype constraints where `α` is _explicitly a type
-- variable_.
upperBoundsClosure :: Ty -> Ty -> Context -> Context
upperBoundsClosure s t ctx0 = traceCOpContext "upperBoundsClosure" (SubC s t) ctx0 $
  -- Find all `α` where `α <: s` and perform updates to propogate `α <: t`.
  Map.foldrWithKey update ctx0 (ctxSubtypeMap ctx0)
  where
    update :: TyVar -> (Set Ty, Set Ty) -> Context -> Context
    update a (lowerBounds,upperBounds) ctx =
      -- If `α </: s` or if we _already_ know `α <: t` then simply move on.
      if not (Set.member s upperBounds) || (Set.member t upperBounds) then ctx
      -- otherwise we need to compute the closure
      else
        let -- `S_{<:} = S_{<:} ∪ {a <: t}`
            supMap' = Map.insert a (lowerBounds, Set.insert t upperBounds) $ ctxSubtypeMap ctx
            -- `B↑(α) ← B↑(α) ⊓ B↑(T)`
            boundsMap' = let aLower = findLowerBound a $ ctxVarBoundsMap ctx
                             aUpper = lowerBound (upperConcretization (VarTy a) ctx) (upperConcretization t ctx)
                          in Map.insert a (aLower, aUpper) $ ctxVarBoundsMap ctx
          in -- Add `Υ(α <: T)` to `C`. (N.B., TIE suggests adding `Υ(α <: S)`
             -- instead, but if we previously recorded `α <: S` already, then we
             -- would have already recorded `Υ(α <: S)` at that time as well).
             addConstraints (decomposeSubC (VarTy a) t)
             $ ctx { ctxSubtypeMap = supMap',
                     ctxVarBoundsMap = boundsMap'}

-- | @lowerBoundsClosure s t ctx@ says given `s <: t`, for all type variables
-- `β` where `t <: β`, we add `s <: β`, update the lower bound of `β`, and
-- record any implied information from `s <: β`. Cf. rule (3) in the
-- Decomposition Rules of § 6.3.2. N.B., we interpret the `S <: T` constraint
-- described by TIE to include any `S` and `T`, but for `∀(T <: α)` to quantify
-- only over known subtype constraints where `β` is _explicitly a type
-- variable_.
lowerBoundsClosure :: Ty -> Ty -> Context -> Context
lowerBoundsClosure s t ctx0 = traceCOpContext "lowerBoundsClosure" (SubC s t) ctx0 $
  -- Find all `β` where `t <: β` and perform updates to propogate `s <: β`.
  Map.foldrWithKey update ctx0 (ctxSubtypeMap ctx0)
  where
    update :: TyVar -> (Set Ty, Set Ty) -> Context -> Context
    update b (lowerBounds,upperBounds) ctx =
      -- If `t </: β` or if we _already_ know `s <: β` then simply move on.
      if not (Set.member t lowerBounds) || (Set.member s lowerBounds) then ctx
      -- otherwise we need to compute the closure
      else
        -- Add `Υ(S <: β)` to `C`. (N.B., TIE suggests adding `Υ(T <: β)`
        -- instead, but if we previously recorded `T <: β` already, then we
        -- would have already recorded `Υ(T <: β)` at that time as well).
        let -- `S_{<:} = S_{<:} ∪ {s <: β}`
            subMap' = Map.insert b (Set.insert s lowerBounds,upperBounds) $ ctxSubtypeMap ctx
            -- `B↓(α) ← B↓(β) ⊔ B↓(S)`
            boundsMap' = let bLower = upperBound (lowerConcretization (VarTy b) ctx) (lowerConcretization s ctx)
                             bUpper = findUpperBound b $ ctxVarBoundsMap ctx
                          in Map.insert b (bLower, bUpper) $ ctxVarBoundsMap ctx
          in addConstraints (decomposeSubC s (VarTy b))
             $ ctx { ctxSubtypeMap = subMap',
                     ctxVarBoundsMap = boundsMap'}

-- | @atomicSubUpdate s t ctx@ records the basic information relevant for `s <:
-- t` (i.e., it does not compute the closure).
atomicSubUpdate :: Ty -> Ty -> Context -> Context
atomicSubUpdate type1 type2 ctx0 = traceCOpContext "atomicSubUpdate" (SubC type1 type2) ctx0 $
  updateLower type1 type2 $ updateUpper type1 type2 ctx0
  where updateLower s (VarTy x) ctx =
          let sMap = ctxSubtypeMap ctx
              (lSet, uSet) = Map.findWithDefault (Set.empty, Set.empty) x sMap
              bMap = ctxVarBoundsMap ctx
              (lBound, uBound) = findTyInterval x bMap
              lBound' = upperBound (lowerConcretization lBound ctx) (lowerConcretization s ctx)
            in ctx { ctxSubtypeMap = Map.insert x (Set.insert s lSet, uSet) sMap
                   , ctxVarBoundsMap = Map.insert x (lBound', uBound) bMap}
        updateLower _ _ ctx = ctx
        updateUpper (VarTy x) t ctx =
          let sMap = ctxSubtypeMap ctx
              (lSet, uSet) = Map.findWithDefault (Set.empty, Set.empty) x sMap
              bMap = ctxVarBoundsMap ctx
              (lBound, uBound) = findTyInterval x bMap
              uBound' = lowerBound (upperConcretization uBound ctx) (upperConcretization t ctx)
            in ctx { ctxSubtypeMap = Map.insert x (lSet, Set.insert t uSet) sMap
                   , ctxVarBoundsMap = Map.insert x (lBound, uBound') bMap}
        updateUpper _ _ ctx = ctx

-- | @solveSubC (t1,t2) cset ctx@ updates @cset@ and @ctx@ with the subtype constraint
-- `t1 <: t2`. Cf. TIE § 6.3.2.
solveSubC :: Context -> (Ty,Ty) -> Context
solveSubC ctx0 (type1,type2) = traceCOpContext "solveSubC" (SubC type1 type2) ctx0 $
  let t1 = substEqs type1 ctx0
      t2 = substEqs type2 ctx0
  in -- cycle check
     if not $ Set.disjoint (tyFreeVars t1) (tyFreeVars t2) then ctx0
     -- If `t1 <: t2` the contraint is trivial and should be discarded.
     else if subtype t1 t2 then ctx0
     -- If `t1 <: t2` appears absurd, record that and continue.
     else if absurdSubC ctx0 t1 t2 then over (field @"ctxAbsurdConstraints") (SubC t1 t2 :) ctx0
     else addConstraints (decomposeSubC t1 t2)
          $ lowerBoundsClosure t1 t2
          $ upperBoundsClosure t1 t2
          $ atomicSubUpdate t1 t2
          $ ctx0

data FinalizerState =
  FinalizerState
  { -- | Type variables yet to be solved.
    fsRemaining :: Set TyVar,
    -- | Variables currently having their types resolved.
    fsWorkingSet :: Set TyVar,
    -- | Variables solved for already.
    fsSolutions :: Map TyVar (Ty, Ty)
  }
  deriving (Generic)

-- | @finalizeBounds ctx fvs@ computes the bounds closure in the given context,
-- producing the final upper (`B^{↑}`) and lower (`B^{↓}`) bounds for variables
-- in @fvs@.
finalizeBounds :: Context -> Set TyVar -> Map TyVar (Ty, Ty)
finalizeBounds ctx vars = fsSolutions $ execState solveVars (FinalizerState vars Set.empty Map.empty)
  where solveVars :: State FinalizerState ()
        solveVars = gets (Set.lookupMin . fsRemaining) >>= \case
           Nothing -> pure ()
           Just x -> do
             modify' (over (field @"fsRemaining") Set.deleteMin)
             solveVar x
             solveVars
        solveVar :: TyVar -> State FinalizerState ()
        solveVar x = do
          xHasLoop <- Set.member x <$> gets fsWorkingSet
          when xHasLoop $
            error $ "Internal type unification error: The type of "
                    ++ (show $ PP.pretty x) ++ " depends on itself in the current context, i.e.\n"
                    ++ (show $ PP.pretty ctx)
          modify' (over (field @"fsWorkingSet") (Set.insert x))
          let (initL, initU) = naiveLookupBounds x
          finalL <- concretizeM initL getLType
          finalU <- concretizeM initU getUType
          modify' (over (field @"fsSolutions") (Map.insert x (finalL, finalU)))
          modify' (over (field @"fsWorkingSet") (Set.delete x))
        -- | Get the lower bound for the type variable.
        getLType :: TyVar -> State FinalizerState Ty
        getLType x = do
          solveVar x
          findLowerBound x <$> gets fsSolutions
        -- Get the upper bound for the type variable.
        getUType :: TyVar -> State FinalizerState Ty
        getUType x = do
          solveVar x
          findUpperBound x <$> gets fsSolutions
        -- | Lookup the bounds of a type variable but "naively", in the sense we
        -- do no concretization or other operations.
        naiveLookupBounds :: TyVar -> (Ty, Ty)
        naiveLookupBounds x = case Map.lookup x (ctxVarEqMap ctx) of
                                Nothing -> findTyInterval x (ctxVarBoundsMap ctx)
                                Just t -> (t,t)


newtype TyUnificationError = TyUnificationError String

processAtomicConstraints :: Context -> Context
processAtomicConstraints ctx = traceContext "processAtomicConstraints" ctx $
  case dequeueEqC ctx of
    Just (ctx', c) -> processAtomicConstraints $ solveEqC ctx' c
    Nothing ->
      case dequeueSubC ctx of
        Just (ctx', c) -> processAtomicConstraints $ solveSubC ctx' c
        Nothing -> ctx

-- | Reduce a constraint given the context.
reduceC :: Context -> TyConstraint -> TyConstraint
reduceC ctx = go
  where
    go :: TyConstraint -> TyConstraint
    go =
      \case
        TopC -> TopC
        BotC -> BotC
        c@(EqC s t) -> if absurdEqC ctx s t then BotC
                      else if trivialEqC ctx s t then TopC
                      else c
        c@(SubC s t) -> if absurdSubC ctx s t then BotC
                        else if trivialSubC ctx s t then TopC
                        else c
        OrC c1 c2 cs -> orC $ map go $ c1:c2:cs
        AndC c1 c2 cs -> andC $ map go $ c1:c2:cs

-- | Attempt to reduce and eliminate disjunctions in the given context. Any
-- resulting non-disjuncts are added to their respective field in the context.
reduceDisjuncts :: Context -> Context
reduceDisjuncts initialContext = traceContext "reduceDisjuncts" initialContext $
  let disjs = ctxOrConstraints initialContext
      ctx0 = initialContext{ctxOrConstraints = []}
   in foldr elim ctx0 disjs
  where elim ::  [TyConstraint] -> Context -> Context
        elim ds ctx = addConstraints [orC (map (reduceC ctx) ds)] ctx

-- | Reduce a context by processing its atomic constraints and then attempting
-- to reduce disjucts to atomic constraints.
reduceContext :: Context -> Context
reduceContext ctx0 = -- traceContext "reduceContext" ctx0 $
  let ctx1 = reduceDisjuncts $ processAtomicConstraints ctx0
    in if hasAtomicConstraints ctx1 then reduceContext ctx1
       else ctx1


-- | Unify the given constraints, returning a conservative type map for all type
-- variables.
unifyConstraints :: [TyConstraint] -> Map TyVar Ty
unifyConstraints initialConstraints =
  let freeVars = foldr (Set.union . cFreeVars) Set.empty initialConstraints
      finalCtx = reduceContext $ initContext initialConstraints
      -- FIXME ^ this reduced context has not taken into account information still
      -- nested in disjucts (cf. § 6.3.4 in TIE). At some point we likely will
      -- want to do this... but we can soundly skip it for now.
      boundsMap = finalizeBounds finalCtx freeVars
      chooseBound (t1,t2) = if uninhabited t1 then t2 else t1
    in fmap chooseBound boundsMap
