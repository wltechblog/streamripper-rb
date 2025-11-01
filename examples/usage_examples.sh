#!/bin/bash

# Streamripper Usage Examples

# Example 1: Basic capture with default settings
./bin/streamripper capture rtsp://192.168.1.100:554/stream

# Example 2: Capture for 60 seconds with verbose output
./bin/streamripper capture rtsp://192.168.1.100:554/stream \
  --duration 60 \
  --verbose

# Example 3: Capture with custom output paths
./bin/streamripper capture rtsp://192.168.1.100:554/stream \
  --output logs/camera1_analysis.json \
  --raw-stream streams/camera1_raw.bin

# Example 4: Capture with CSV format
./bin/streamripper capture rtsp://192.168.1.100:554/stream \
  --format csv \
  --output logs/camera1_analysis.csv

# Example 5: Capture both JSON and CSV
./bin/streamripper capture rtsp://192.168.1.100:554/stream \
  --format both \
  --output logs/camera1_analysis

# Example 6: Capture with packet limit
./bin/streamripper capture rtsp://192.168.1.100:554/stream \
  --max-packets 5000 \
  --output logs/limited_capture.json

# Example 7: Capture with authentication
./bin/streamripper capture rtsp://admin:password@192.168.1.100:554/stream \
  --duration 120 \
  --verbose

# Example 8: Capture with all options
./bin/streamripper capture rtsp://admin:password@192.168.1.100:554/stream \
  --output logs/full_analysis.json \
  --raw-stream streams/full_raw.bin \
  --format both \
  --duration 300 \
  --max-packets 50000 \
  --verbose

# Example 9: Capture and save to timestamped files
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
./bin/streamripper capture rtsp://192.168.1.100:554/stream \
  --output "logs/capture_${TIMESTAMP}.json" \
  --raw-stream "streams/capture_${TIMESTAMP}.bin" \
  --duration 60

# Example 10: Background capture with output redirection
nohup ./bin/streamripper capture rtsp://192.168.1.100:554/stream \
  --output logs/background_capture.json \
  --raw-stream streams/background_capture.bin \
  --duration 3600 \
  > logs/streamripper.log 2>&1 &

