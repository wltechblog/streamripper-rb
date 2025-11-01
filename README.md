# Streamripper - RTSP Stream Analyzer & H.264 Video Extractor

A comprehensive Ruby application to capture, analyze, and extract H.264 video from RTSP streams with forensic capabilities and web UI.

## Installation

```bash
git clone https://github.com/yourusername/streamripper-rb.git
cd streamripper-rb
bundle install
chmod +x bin/streamripper
```

## Quick Start

### Web UI (Recommended)

```bash
./bin/streamripper web --port 8080
```

Then open http://localhost:8080 in your browser.

### CLI Capture

```bash
./bin/streamripper capture rtsp://camera-ip:554/stream --duration 30
```

## Output Files

After capture, the following files are generated:

```
logs/streams/{host}_{endpoint}/{timestamp}/
├── raw_stream.bin          # Complete RTSP-over-TCP stream (true raw data)
├── analysis.json           # Packet metadata and analysis
├── stream.h264             # De-fragmented H.264 video stream
├── stream.mp4              # Playable MP4 video file
└── frames/
    ├── frame00001.bin      # Individual H.264 frames
    ├── frame00002.bin
    └── ...
```

### Raw Stream Format

The `raw_stream.bin` file contains the complete RTSP-over-TCP stream with framing:

```
$ <channel> <length> <RTP packet>
$ <channel> <length> <RTP packet>
...
```

Where:
- `$` = 0x24 (RTSP marker)
- `<channel>` = 1 byte (0=video RTP, 1=video RTCP, 2=audio RTP, 3=audio RTCP)
- `<length>` = 2 bytes big-endian (RTP packet size)
- `<RTP packet>` = variable length RTP data

### Analysis JSON

Packet-level metadata including:
- RTP timestamp and sequence numbers
- Frame type (I-frame, P-frame, SPS, PPS, etc.)
- Packet size and timing information
- Timestamp deviation analysis

### Frame Files

Individual H.264 NAL units with start codes:
```
00 00 01 <NAL header> <NAL data>
```

## Testing

Run the test suite:

```bash
bundle exec rspec
```

Run specific test file:

```bash
bundle exec rspec spec/packet_analyzer_spec.rb
```

## Architecture

### Core Modules

- **RTSPFetcher** (`lib/streamripper/rtsp_fetcher.rb`): RTSP protocol handling and packet reading
- **PacketAnalyzer** (`lib/streamripper/packet_analyzer.rb`): RTP packet parsing and metadata extraction
- **StreamSaver** (`lib/streamripper/stream_saver.rb`): Raw stream data persistence
- **WebServer** (`lib/streamripper/web_server.rb`): Web UI and API server
- **OutputManager** (`lib/streamripper/output_manager.rb`): Output directory management

## Requirements

- Ruby 2.7+
- Bundler
- FFmpeg (for MP4 generation)

## License

MIT
