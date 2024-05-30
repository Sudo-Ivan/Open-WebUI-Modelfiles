# ARMA 3 SQF Scripting Tips

SQF stands for Status Quo Function - a successor of SQS Script, which is deprecated since ArmA: Armed Assault but could still be used in ARMA 3. SQF first appeared in Operation Flashpoint Resistance with the update 1.85, alongside the `call` operator.

*Note:*
- "Status Quo" was a code name for Operation Flashpoint
- "Combined Arms" was a code name for ARMA series
- "Futura" was a code name for ARMA 3

The SQF Language simplifies scripting with a structure that largely relies on operators (scripting commands) rather than traditional programming language constructs. These operators are categorized as Nular, Unary, or Binary.

## Terminating an Expression

SQF expressions are generally terminated by a semicolon `;`, which is the preferred method. However, commas `,` are also used, especially within arrays or to separate arguments in function calls.

```sqf
_num = 10;
_num = _num + 20; systemChat str _num;

// Using commas in function arguments
_pos = [getPos player, "marker1"] call BIS_fnc_nearestPosition;
```

In the first snippet, each line represents a separate expression, delineated by semicolons. In the second snippet, a comma is used to separate function arguments within the parentheses.

## Brackets

- `()` Round brackets are used for precedence or clarity in expressions and for enclosing function arguments.
- `[]` Square brackets are employed to define arrays, and commas within square brackets are used to separate array elements.
- `{}` Curly brackets are used to enclose code blocks or for control structures.

```sqf
// Using commas in arrays
_myArray = [1, 2, 3, 4, 5];
```

## Whitespace

In SQF, both tabs and spaces are recognized as whitespace, with the engine ignoring leading and trailing whitespace within a line.

## Blank Lines

Lines containing nothing but whitespace do not affect the script and are ignored by the SQF engine.

## Comments

Comments can be written as inline `//` or block `/* */` and are ignored when the script is parsed. They're useful for explaining code logic or for disabling code without deleting it.

```sqf
// This is an inline comment

/* This is a 
block comment */
```

## Nular Operators

Nular operators act like computed variables, always returning the current state. They're not global variables but provide real-time, updated values.

Example usage:
```sqf
_unitsArray = allUnits;
systemChat str count _unitsArray;
// Using commas in debug messaging
hintsilent format ["Current number of units: %1", count allUnits];
```

## Unary Operators

Unary operators require an argument to their right. Common mistakes often involve misunderstanding the order in which operations are performed.

```sqf
// Incorrect usage that generates an error
count _arr select 2; // error

// Correct usage
count (_arr select 2); // This will output 2
```

## Binary Operators

Binary operators take two arguments and execute based on their precedence or left-to-right if their precedence matches.

Example:
```sqf
// Complex nested array manipulation
_arr = [[[[[1]]]]];
_arr select 0 select 1 - 1 select 15 / 3 - 5 select 0 select 10 * 10 + 4 * 0 - 100 // evaluates to 1
```