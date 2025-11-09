# Veins-based V2X Simulation Project

A vehicular network simulation project using Veins, OMNeT++, and SUMO for V2X communication research.

## Overview

This project provides a pre-configured Veins simulation environment with a custom map for testing V2X (Vehicle-to-Everything) communications. It integrates:
- OMNeT++ for discrete-event simulation
- SUMO for traffic simulation with a custom map
- Veins for vehicular network modeling

## What's Included

- Pre-configured OMNeT++ project files
- Custom SUMO map (replacing default map)
- Compatible with specified software versions

## Dependencies

Requires these specific versions:
- **OMNeT++**: 5.4.1
- **SUMO**: 1.8.0
- **Veins**: 4.7.1

## Installation & Setup

### 1. Install Required Software

- Install OMNeT++ 5.4.1 from [omnetpp.org](https://omnetpp.org/)
- Install SUMO 1.8.0 from [SUMO archive](https://sumo.dlr.de/docs/Downloads.html#old_versions)
- Set `SUMO_HOME` environment variable to your SUMO installation directory

### 2. Project Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/a805026135/Veins.git
   ```

2. Open OMNeT++ IDE and import the project:
   - `File > Import > Existing Projects into Workspace`
   - Select the cloned repository directory
   - The project is pre-configured and ready to run

## Usage

1. In OMNeT++ IDE, open `omnetpp.ini`
2. Select a configuration from the dropdown menu
3. Click the "Run" button to start simulation
4. SUMO will launch automatically with the custom map

## Documentation

- [Veins Documentation](http://veins.car2x.org/)
- [SUMO Documentation](https://sumo.dlr.de/docs/)
- [OMNeT++ Manual](https://omnetpp.org/documentation/)
