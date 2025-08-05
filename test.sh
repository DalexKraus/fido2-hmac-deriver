#!/bin/bash

# FIDO2 HMAC Deriver Test Script
# This script tests the non-interactive mode and verifies key consistency

# Configuration
PIN="123456"
DEVICE_PATH="/dev/hidraw10"
BINARY="./fido2-hmac-deriver"
ITERATIONS=2

echo "FIDO2 HMAC Deriver Test Script"
echo "================================"
echo ""

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary '$BINARY' not found. Please build the application first."
    echo "Run: go build -o fido2-hmac-deriver"
    exit 1
fi

# Check if binary is executable
if [ ! -x "$BINARY" ]; then
    echo "Error: Binary '$BINARY' is not executable."
    echo "Run: chmod +x fido2-hmac-deriver"
    exit 1
fi

echo "Test Configuration:"
echo "  PIN: $PIN"
echo "  Device Path: $DEVICE_PATH"
echo "  Binary: $BINARY"
echo "  Iterations: $ITERATIONS"
echo ""

# Array to store derived keys
declare -a keys

echo "Running non-interactive key derivation tests..."
echo ""

# Run the test iterations
for i in $(seq 1 $ITERATIONS); do
    echo "Iteration $i:"
    echo "  Command: PIN=$PIN $BINARY --fido-device=$DEVICE_PATH --pin-environment-variable=PIN --key-only"
    
    # Run the command and extract the key
    echo "  Running..."
    
    # Run the command and capture both output and exit code
    full_output=$(PIN="$PIN" "$BINARY" --fido-device="$DEVICE_PATH" --pin-environment-variable=PIN --key-only 2>&1)
    exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        echo "  Error: Command failed with exit code $exit_code"
        echo "  Full output:"
        echo "$full_output"
        echo -e "\n"
        echo "You might want to adjust the PIN or the device inside this script ..."
        exit 1
    fi
    
    # Extract the key from the output
    key=$(echo "$full_output" | grep -A1 "BEGIN DERIVED KEY" | tail -n1 | tr -d '\r\n')
    
    if [ -z "$key" ]; then
        echo "  Error: Could not extract key from output"
        echo "  Full output:"
        echo "$full_output"
        exit 1
    fi
    
    # Store the key
    keys[$i]="$key"
    
    echo "  Key: $key"
    echo ""
    
    # Small delay between iterations to ensure device is ready
    if [ $i -lt $ITERATIONS ]; then
        echo "  Waiting 2 seconds before next iteration..."
        sleep 2
        echo ""
    fi
done

echo "Test Results:"
echo ""

# Print all keys for comparison
for i in $(seq 1 $ITERATIONS); do
    echo "  Iteration $i: ${keys[$i]}"
done

echo ""

# Check if all keys match
all_match=true
reference_key="${keys[1]}"

for i in $(seq 2 $ITERATIONS); do
    if [ "${keys[$i]}" != "$reference_key" ]; then
        all_match=false
        break
    fi
done

# Print final result
if [ "$all_match" = true ]; then
    echo "SUCCESS: All derived keys match!"
    echo "-> FIDO2 HMAC secret derivation is deterministic"
    echo "and the non-interactive mode is working correctly."
    exit 0
else
    echo "ERROR: Derived keys do not match!"
    echo "-> There seems to be an issue with the FIDO2 HMAC derivation"
    echo "or the non-interactive mode implementation."
    
    # Show detailed comparison
    echo ""
    echo "Detailed comparison:"
    for i in $(seq 1 $ITERATIONS); do
        if [ "${keys[$i]}" = "$reference_key" ]; then
            echo "Iteration $i: MATCH"
        else
            echo "Iteration $i: DIFFERENT"
        fi
    done
    
    exit 1
fi
