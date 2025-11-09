# Security Protocol Experimental Framework

## Project Overview

This experimental framework consists of four related projects that together form a comprehensive security protocol research system, covering the entire process from theoretical security verification to practical application scenario testing.

## Project Components

### 1. ZhouAKAProverif-main
**Function**: Protocol security analysis using Proverif formal verification tool  
**Role**: Provides theoretical foundation and security assurance for the entire experimental system  
**Files**: `README.md`, source code files

### 2. Anti-leakageAKA  
**Function**: Protocol efficiency testing in simulated environments  
**Role**: Validates protocol performance in simulation environments  
**Features**: Controllable testing environment, convenient for parameter adjustment and performance analysis

### 3. Authentication_using_pbc_in_Raspberry_PI
**Function**: Authentication protocol implementation using PBC library on Raspberry Pi hardware platform  
**Role**: Verifies protocol feasibility and performance on actual hardware devices  
**Features**: Real hardware environment, includes PBC cryptography library dependencies

### 4. Veins
**Function**: Protocol efficiency testing in vehicular network environments  
**Role**: Validates protocol applicability in specific application scenarios (vehicular networks)  
**Features**: Oriented towards practical application scenarios, tests performance in vehicular network environments

## Experimental Framework Relationship Diagram

```mermaid
graph TD
    A[ZhouAKAProverif-main<br/>Security Verification] --> B[Anti-leakageAKA<br/>Simulation Environment Testing]
    A --> C[Authentication_using_pbc_in_Raspberry_PI<br/>Raspberry Pi Experiment]
    A --> D[Veins<br/>Vehicular Network Testing]
    
    B --> E[Security Protocol Experimental Framework]
    C --> E
    D --> E
    
    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#e8f5e8
    style D fill:#fff3e0
    style E fill:#fce4ec
