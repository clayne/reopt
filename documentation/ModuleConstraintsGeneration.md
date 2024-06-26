# Module Constraints Generation

The goal of this operation is to generate a set of typing constraints for all
values in the binary.

Our target type language is more or less that of LLVM, including typed pointers,
as the final goal is to produce better-typed lifted LLVM code.  Prior to this
work, most pointer values were lifted to num64, and arithmetic operations over
pointer values were lifted to non-pointer arithmetic, as we had no way of
tracking whether pointer-sized values in the binary were pointers or numeric
values.

Of course, some of those pointer-sized values would eventually flow into a
memory operation (load or store).  The old LLVM code would just add an
on-the-fly `inttoptr` cast just before the value is passed to such a memory
operation.

The hope here is to figure out what values are definitely pointers, so that we
can lift to more appropriate LLVM code.  Ideally, all pointers are correctly
identified, and their arithmetic is lifted into `getelementptr` operations
rather than just `add`.

## Constraint language

The constraint language needs to talk about unknown types that may or may not be
the same, and we also want offset-level granularity for structures and arrays.
To support the former, we use **type variables**.  To support the latter, we use
a flavor of **row variables**.

We also have a notion of **row expressions**, which are either row variables
`ρ`, or "shift" operations (denoted `+`) applied to a row variable, e.g. `ρ + 1`.
For instance, given the following information about some row variable `ρ`:

```
{ 0 : i32, 4 : i8, 8 : i64 }
```

to be read as "at offset 0 it contains an `i32`, at offset 4 it contains an
`i8`, and at offset 8 it contains an `i64`", then we ought to be able to deduce
the following information about row expression `ρ + 4`:

```
{ -4 : i32, 0 : i8, 4 : i64 }
```

If you think of an original pointer `p` whose pointee type is described by `ρ`,
then this describes the expected pointee contents for a pointer `p + 4`
(assuming byte-semantics for the addition), describing its view as "shifted"
from `p`'s view.

Note that offsets are expressed in bytes, since we never need more granularity.

The constraint language contains the following concepts (derived organically,
there may be a better way to represent or solve these):

-   Equality constraints (`EqC`), which for simplicity in our solver are biased to
    be between a type variable and an arbitrary type or type variable.

-   Row equality constraints (`EqRowC`), equating two row expressions.

-   Subtyping constraints (`SubC`), representing a looser requirement than
    equality constraint.  These are instantiated in two ways, `SubTypeC` between
    two type variables, and `SubRowC` between two row expressions.

    In both cases, the idea is to capture what happens when a value flows into a
    context that may be more permissive, for instance at function calls.

-   Finally, conditional constraints (`Conditional`) are a bespoke encoding of
    entailment of constraints from other facts being true.  We tend to think of
    them as the following pattern:

    (P1 ∧ P2) ∨ P3 ∨ (P4 ∧ P5) ⊢ C1 ∧ C2

    where the premises are a disjunction of conjunctions of patterns, and the
    conclusions are a bunch of type equality and row equality constraints we
    conclude when any of the premises disjunct is true.  We will discuss where
    these conditional constraints arise in a following section.

## Conflict types

Our type system is mostly concerned with distinguishing pointers and
non-pointers.  However, there are times where we get conflictual constraints
over the same location.

A reasonable way this can happen is when a concept such as C unions was used.
In such cases, the same memory location could have different types, dictated by
some meta-data.

But we also found potential spurious conflicts arising when we accidentally mix
up information that should be separated.

We introduce the notion of a "conflict" type, that we use whenever we witness
such a conflict.  This will be very relevant in the constraint solving
algorithm, as we may first believe that some value is either pointer or
non-pointer, until we process a subsequent constraint telling us contradicting
information.

## How are constraints generated?

Constraints are generated by iterating over basic blocks, after first having
assigned type variables to all phi variables, so as to be able to generate
constraint over the same type variables at block boundaries.

The following sections describe the important parts where constraints are
generated.

### At block boundaries (`genBlockTransfer`)

At block boundary, we collect the values we will pass to the phi variables, and
their matchin type variables based on the target block, and we constrain the
actuals to be a subtype of the expected.

### At function calls, including taill calls (`genCall`)

Quite similar to block boundary, we emit subtype constraints for the values
passed w.r.t. the expected types.

### At function return (`FnRet` case in `genFnBlock`)

Likewise, returning a value generates the appropriate subtype constraint w.r.t.
the expected return type.

### At assignments (`genFnAssignment`)

The assigned value is a symbolic one, so there are a few cases here.

If the value comes from a memory read, see the section about memory operations.

If the value is a symbolic Macaw `App` value, we do specific things based on the
underlying term.

If it is the result of an equality test between two values, we conclude these
values must have had identic type, and the result is a boolean (non-pointer, 1
byte).

If the value is a `Mux` (conditionally one of two values), we enforce equality
of type between the two values.

Boolean operations currently add no constraints.  I think we may want to force
the result to be boolean?

Most bitvector operations generate non-pointer constraints, as they cannot apply
to pointers.  However, some do.

#### Potential pointer addition

Bitvector additions are one of the main exceptions to this rule, as they could
be pointer arithmetic.  When either side of the addition is a constant with
address width, we emit the hypothesis that it could be a pointer addition.

`ptrAddTC` sets up the conditional relationship of a potential pointer addition.

The first conditional constraint states that if either the result is known
numeric, both inputs are known numeric, or anything is conflicted, then all
three types should be unified together (as either numeric or conflicted).

Then, we do something depending on information about the right hand side (RHS).

-   If we know it is numeric, then when either the left hand side operand (LHS)
    or the return value is a pointer, so is the other, and the offset tells us
    the amount of shift between their pointee type.

-   If we know it is a pointer, then as long as the return value is also a
    pointer (no conflict), we conclude the LHS is numeric and RHS a pointer.

-   If the RHS is a symbolic value, then we account for all cases, where either
    the LHS is numeric and the RHS is pointer, or the LHS is pointer and the RHS is
    numeric.

### Potential pointer subtraction

This is fairly similar to the addition case, except only the LHS may ever be a
pointer, so there are fewer cases to consider.

### At memory operations

When we perform a memory read or a memory write with a value for the address, we
conclude that the dereferenced value is a pointer, and the result has the
pointed type for that pointer type at the given offset.  Additionally, if the
Macaw size type of the pointee is not the pointer width, we conclude the pointed
type must be numeric (i.e. non-pointer).
