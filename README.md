# AirSuite-Master

AirSuite-Master is a comprehensive wrapper for the Aircrack-ng suite that manages the entire wireless attack workflow with robust error handling, session management, and optimization.

## Features

- Automated wireless network scanning
- Client scanning and selection
- Handshake capture with deauthentication attacks
- Robust error handling and logging
- Session management and state saving
- Dependency checking and setup

## Requirements

- Aircrack-ng suite
- macchanger
- iw
- ethtool

## Installation

To install the required dependencies, run:

```bash
sudo apt install aircrack-ng macchanger iw ethtool
```

## Usage

Run the script with root privileges:

```bash
sudo ./airsuite-master.sh
```

Follow the on-screen instructions to select the wireless interface, target network, and client.

## License

This project is licensed under the MIT License.
