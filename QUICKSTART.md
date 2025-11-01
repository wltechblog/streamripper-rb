# Quick Start Guide

## Installation

```bash
git clone https://github.com/yourusername/streamripper-rb.git
cd streamripper-rb
bundle install
```

## Web UI (Recommended)

The easiest way to use Streamripper is through the web interface:

```bash
./bin/streamripper web --port 8080
```

Then open http://localhost:8080 in your browser.

### Using the Web UI

1. **Enter Stream URL**: Paste your RTSP stream URL (e.g., `rtsp://192.168.1.100:554/stream`)
2. **Set Duration**: Choose how long to capture (in seconds)
3. **Start Capture**: Click "Start Capture" button
4. **Monitor Progress**: Watch the spinner and packet count
5. **View Results**: Once complete, see:
   - Frame list with types and sizes
   - Video player for MP4 playback
   - Hex dump of individual frames
   - Detailed packet analysis

## CLI Usage

For command-line capture:

```bash
./bin/streamripper capture rtsp://camera-ip:554/stream --duration 30
```

### Output Files

After capture, files are saved to:
```
logs/streams/{host}_{port}/{timestamp}/
├── raw_stream.bin          # Complete RTSP stream
├── analysis.json           # Packet metadata
├── stream.h264             # H.264 video stream
├── stream.mp4              # Playable video
└── frames/                 # Individual frames
```

## Common Tasks

### Capture a 60-second stream

```bash
./bin/streamripper web --port 8080
# Then use web UI with 60 second duration
```

### Analyze captured stream

```bash
# View analysis JSON
cat logs/streams/192_168_1_100_554/20251101_120000/analysis.json | jq .

# Play MP4 video
mpv logs/streams/192_168_1_100_554/20251101_120000/stream.mp4
```

### Extract individual frames

Frames are automatically extracted to:
```
logs/streams/192_168_1_100_554/20251101_120000/frames/frame00001.bin
logs/streams/192_168_1_100_554/20251101_120000/frames/frame00002.bin
...
```

## Troubleshooting

### Connection refused
- Verify camera IP and port are correct
- Check network connectivity
- Ensure RTSP service is running on camera

### No video in MP4
- Check that capture completed successfully
- Verify stream contains H.264 video
- Check FFmpeg is installed: `ffmpeg -version`

### Web UI not loading
- Verify port 8080 is not in use
- Try different port: `./bin/streamripper web --port 8081`

## Next Steps

- Read [README.md](README.md) for detailed documentation
- Check [docs/](docs/) for technical details
- See [examples/](examples/) for sample usage

