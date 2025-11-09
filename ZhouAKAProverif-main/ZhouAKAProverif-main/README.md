# ProVerif Protocol Verification Project

## Project Overview

This project implements a formal verification of an authentication and key agreement protocol using ProVerif. The protocol is based on bilinear pairings and provides mutual authentication between users (Ui) and servers (Sj), along with secure session key establishment.

The verification focuses on:

*   Session key secrecy
*   Authentication unforgeability
*   Injective agreement properties

## Protocol Description

### Core Components

The protocol involves three main entities:

*   **KGC (Key Generation Center)**: Issues public/private key pairs to users and servers
*   **User (Ui)**: Initiates authentication and establishes session keys
*   **Server (Sj)**: Responds to authentication requests and establishes session keys

### Cryptographic Primitives

The protocol utilizes:

*   **Bilinear Pairing**: `e(g1, g2)` - Pairing operation on cyclic groups
*   **Group Multiplication**: `Mult(a, b)` - Multiplication in the group
*   **Exponentiation**: `Powzn(g, s)` - Computes g^s
*   **Hash Function**: `H(...)` - Cryptographic hash function
*   **XOR Operations**: `Xor(...)` - Bitwise exclusive-or

### Protocol Flow

#### Phase 1: Registration
```
Ui/Sj → KGC: Identity (IDi/IDj)
KGC → Ui/Sj: Private keys (x1, x2) and public key (pk)
```

The KGC generates keys using matrix operations:
*   `x1 = A1*B11 + A2*B21 + A3*B31`
*   `x2 = A1*B12 + A2*B22 + A3*B32`
*   `pk = g1^x1 * g2^x2`

#### Phase 2: Authentication & Key Agreement
```
1. Ui → Sj: IDi, R1i, R2i, Ti
2. Sj → Ui: IDj, R1j, R2j, cj, Tj
3. Ui → Sj: IDi, v1i, v2i, Ti'
4. Sj → Ui: IDj, v1j, v2j, Tj'
5. Both parties verify and compute session key
```

Where:
*   `R1i = g1^r1i, R2i = g2^r2i` (Random commitments)
*   `v1i = cj*x1 + r1i, v2i = cj*x2 + r2i` (Response values)
*   Session key: `SK = H(IDi, IDj, R1j^r1i, R2j^r2i)`

## Environment Setup

### 1. Installing ProVerif

#### Linux/Unix
```bash
# Download ProVerif (version 2.05 recommended)
wget https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz

# Extract
tar -xzf proverif2.05.tar.gz

# Build
cd proverif2.05
./build

# Add to PATH
export PATH=$PATH:/path/to/proverif2.05
```

#### macOS
```bash
# Using Homebrew
brew install proverif

# Or manual installation (same as Linux)
```

#### Windows
1.  Download the Windows binary distribution from the official website
2.  Extract to a directory (e.g., `C:\ProVerif`)
3.  Add the ProVerif executable to your system PATH

### 2. Verify Installation
```bash
proverif -help
```

If the help message displays correctly, ProVerif is installed successfully.

## File Structure

```
.
├── protocol.pv         # Main protocol specification file
└── README.md          # This file
```

### Protocol File Components

The `protocol.pv` file contains:

*   **Type Declarations**: Element types and channel definitions
*   **Constants & Variables**: Group generators, keys, and protocol parameters
*   **Cryptographic Functions**: Pairing, multiplication, hash operations
*   **Event Definitions**: Begin/end events for authentication tracking
*   **Security Queries**: Properties to verify (secrecy, authentication)
*   **Process Definitions**: KGC, User, and Server processes

## Building and Running

### Basic Execution

```bash
# Run verification on the protocol file
proverif protocol.pv

# Save output to a file
proverif protocol.pv > verification_results.txt
```

### Advanced Options

```bash
# Generate detailed HTML report
proverif -in pitype -html report.html protocol.pv

# Generate attack graphs (if vulnerabilities found)
proverif -graph attack.dot protocol.pv

# Enable redundancy elimination for faster verification
proverif -set redundancyElim true protocol.pv
```

### Viewing HTML Reports

```bash
# macOS
open report.html

# Linux
xdg-open report.html

# Windows
start report.html
```

## Security Properties Verified

The protocol specification includes the following security queries:

### 1. Session Key Secrecy
```proverif
query attacker(SKeyU).  (* User session key *)
query attacker(SKeyS).  (* Server session key *)
```

**Expected Result**: `false` - The attacker cannot obtain the session keys

### 2. Authentication Properties
```proverif
query ID:bitstring; inj-event(endUi(IDi)) ==> inj-event(beginUi(IDi)).
query ID:bitstring; inj-event(endSj(IDj)) ==> inj-event(beginSj(IDj)).
```

**Expected Result**: `true` - Each session completion corresponds to a unique session initiation

## Expected Verification Results

### Successful Verification

```
RESULT attacker(SKeyS[]) is false.
RESULT attacker(SKeyU[]) is false.
RESULT inj-event(endUi(IDi)) ==> inj-event(beginUi(IDi)) is true.
RESULT inj-event(endSj(IDj)) ==> inj-event(beginSj(IDj)) is true.

--------------------------------------------------------------
Verification summary:

Query attacker(SKeyS[]) is false.
Query attacker(SKeyU[]) is false.
Query inj-event(endUi(IDi)) ==> inj-event(beginUi(IDi)) is true.
Query inj-event(endSj(IDj)) ==> inj-event(beginSj(IDj)) is true.
```

**Interpretation**:
*   ✅ **Secrecy**: Session keys remain confidential
*   ✅ **Authentication**: Protocol prevents impersonation attacks
*   ✅ **Injective Agreement**: Each session is uniquely matched

### Vulnerability Detection

If ProVerif finds an attack:
```
RESULT attacker(SKeyS[]) is true.

The attacker can obtain the secret.
Reconstruction of attack trace:
[Detailed attack steps...]
```

ProVerif will provide a trace showing how the attacker can break the protocol.

## Key Design Patterns

### Private vs. Public Declarations

```proverif
free x1_ui:element [private].  (* Attacker cannot access *)
free pk_ui:element.            (* Public, attacker knows *)
```

### Channel Security

```proverif
out(Sec, data)  (* Secure channel - confidential *)
out(Pub, data)  (* Public channel - attacker can intercept *)
```

### Process Replication

```proverif
process (!Ui | !Sj | !KGC)
```
The `!` operator creates unbounded replication, modeling multiple concurrent sessions.

## Troubleshooting

### Common Issues

#### Syntax Errors
**Problem**: Parse errors or type mismatches
```
Error: syntax error at line X
```
**Solution**:
*   Verify ProVerif version compatibility
*   Check all variables are declared before use
*   Ensure balanced parentheses

#### Long Verification Time
**Problem**: Verification takes excessive time
**Solution**:
```bash
# Use optimization flags
proverif -set redundancyElim true protocol.pv

# Simplify the model by reducing:
# - Number of matrix elements
# - Process replications
# - Message complexity
```

#### Inconclusive Results
**Problem**: ProVerif outputs "cannot be proved"
**Solution**:
*   This is normal - ProVerif uses approximations
*   Add type constraints to help verification
*   Simplify protocol abstraction
*   Consider manual proof or alternative tools

### Debugging Strategies

#### 1. Add Debug Output
```proverif
out(Pub, ("Debug checkpoint", value))
```

#### 2. Incremental Verification
Start with simple queries and gradually add complexity:
```proverif
(* Step 1: Verify basic secrecy *)
query attacker(SKeyU).

(* Step 2: Add authentication *)
query inj-event(endUi(IDi)) ==> inj-event(beginUi(IDi)).
```

#### 3. Use Visual Reports
HTML reports provide visual trace trees and message flows for easier debugging.

## Advanced Features

### Adding Custom Security Properties

```proverif
(* Forward secrecy *)
query attacker(SKeyU) phase 1 ==> attacker(x1_ui) phase 0.

(* Key confirmation *)
event keyConfirm(bitstring, element).
query ID:bitstring, K:element; 
  event(keyConfirm(ID,K)) ==> event(keyGenerated(ID,K)).
```

### Modeling Active Attackers

```proverif
let ActiveAttacker = 
  in(Pub, x:element); 
  out(Pub, Mult(x, g1)).  (* Modify intercepted messages *)
```

## Performance Considerations

*   **Verification Time**: Depends on protocol complexity and number of processes
*   **Memory Usage**: Complex protocols may require significant RAM
*   **Optimization**: Use `-set redundancyElim true` for faster verification
*   **Scalability**: ProVerif handles unbounded sessions but may not terminate for all protocols

## Notes

*   **ProVerif Version**: Tested with ProVerif 2.05. Other versions may have syntax differences.
*   **Approximations**: ProVerif uses over-approximation; false attacks are possible but false negatives are not.
*   **Channel Model**: `Sec` channel models ideal secure transmission (e.g., TLS); `Pub` models unprotected network.
*   **Private Keys**: Declared with `[private]` modifier to prevent attacker access in the Dolev-Yao model.

## References

*   [ProVerif Official Documentation](https://bblanche.gitlabpages.inria.fr/proverif/)
*   [ProVerif User Manual (PDF)](https://prosecco.gforge.inria.fr/personal/bblanche/proverif/manual.pdf)
*   [ProVerif Tutorial Examples](https://www.proverif-models.org/)
*   [Security Protocol Verification Course](https://secgroup.dais.unive.it/teaching/security-protocol-verification/)

## License

This project is for academic research and educational purposes only.
