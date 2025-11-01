require 'socket'
require 'json'
require 'base64'
require_relative 'rtsp_fetcher'
require_relative 'packet_analyzer'

module Streamripper
  class WebServer
    def initialize(port = 8080)
      @port = port
      @server = TCPServer.new('localhost', port)
    end

    def start
      puts "🌐 Streamripper Web UI starting on http://localhost:#{@port}"
      puts "Press Ctrl+C to stop"

      trap('INT') { @server.close; exit }

      loop do
        client = @server.accept
        Thread.new(client) { |c| handle_request(c) }
      end
    end

    private

    def handle_request(client)
      request_line = client.gets
      return unless request_line

      method, path, _ = request_line.split
      headers = {}

      while (line = client.gets.chomp) != ''
        key, value = line.split(': ', 2)
        headers[key] = value
      end

      body = ''
      if headers['Content-Length']
        body = client.read(headers['Content-Length'].to_i)
      end

      response = route_request(method, path, headers, body)
      client.print response
      client.close
    rescue => e
      error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n"
      error_response += { error: e.message }.to_json
      client.print error_response
      client.close
    end

    def route_request(method, path, headers, body)
      # Extract base path without query string
      base_path = path.split('?')[0]

      case base_path
      when '/'
        http_response('text/html', render_ui)
      when '/api/capture'
        if method == 'POST'
          data = JSON.parse(body)
          rtsp_url = data['rtsp_url']
          duration = data['duration'].to_i

          begin
            capture_data = capture_stream(rtsp_url, duration)
            http_response('application/json', capture_data.to_json)
          rescue => e
            http_error(400, { error: e.message }.to_json)
          end
        else
          http_error(405, { error: 'Method not allowed' }.to_json)
        end
      when /^\/api\/frame-hex/
        query = path.split('?', 2)[1]
        if query
          params = parse_query(query)
          frame_base64 = params['frame']

          if frame_base64
            frame_data = Base64.decode64(frame_base64)
            hex_dump = generate_hex_dump(frame_data)
            http_response('application/json', { hex: hex_dump }.to_json)
          else
            http_error(400, { error: 'No frame data provided' }.to_json)
          end
        else
          http_error(400, { error: 'No frame data provided' }.to_json)
        end
      when /^\/api\/scans/
        scans = get_previous_scans
        http_response('application/json', { scans: scans }.to_json)
      when /^\/api\/load-scan/
        query = path.split('?', 2)[1]
        if query
          params = parse_query(query)
          scan_id = params['scan_id']
          host = params['host']

          if scan_id && host
            begin
              scan_data = load_scan_data(host, scan_id)
              http_response('application/json', scan_data.to_json)
            rescue => e
              http_error(400, { error: e.message }.to_json)
            end
          else
            http_error(400, { error: 'Missing scan_id or host' }.to_json)
          end
        else
          http_error(400, { error: 'Missing parameters' }.to_json)
        end
      when /^\/logs\//
        # Serve files from logs directory
        file_path = File.join(Dir.pwd, path)
        if File.exist?(file_path) && File.file?(file_path)
          content = File.binread(file_path)
          content_type = case File.extname(file_path)
                         when '.mp4' then 'video/mp4'
                         when '.h264' then 'video/mp4'  # H.264 raw stream
                         when '.json' then 'application/json'
                         when '.bin' then 'application/octet-stream'
                         else 'application/octet-stream'
                         end
          "HTTP/1.1 200 OK\r\nContent-Type: #{content_type}\r\nContent-Length: #{content.bytesize}\r\nConnection: close\r\n\r\n#{content}"
        else
          http_error(404, { error: 'File not found' }.to_json)
        end
      else
        http_error(404, { error: 'Not found' }.to_json)
      end
    end

    def parse_query(query_string)
      params = {}
      query_string.split('&').each do |pair|
        key, value = pair.split('=', 2)
        params[key] = URI.decode_www_form_component(value) if value
      end
      params
    end

    def http_response(content_type, body)
      "HTTP/1.1 200 OK\r\nContent-Type: #{content_type}\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
    end

    def http_error(status, body)
      status_text = { 400 => 'Bad Request', 404 => 'Not Found', 405 => 'Method Not Allowed', 500 => 'Internal Server Error' }[status]
      "HTTP/1.1 #{status} #{status_text}\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
    end

    def capture_stream(rtsp_url, duration)
      require_relative 'output_manager'

      # Extract host from RTSP URL for directory naming
      uri = URI.parse(rtsp_url)
      host_part = "#{uri.host}_#{uri.path.gsub('/', '_')}"

      # Initialize output manager
      output_mgr = OutputManager.new(rtsp_url)

      require_relative 'stream_saver'

      fetcher = RTSPFetcher.new(rtsp_url)
      analyzer = PacketAnalyzer.new
      packets_data = []

      # Initialize stream saver for raw packets
      raw_stream_file = output_mgr.get_output_path('raw_stream.bin')
      saver = StreamSaver.new(raw_stream_file)

      start_time = Time.now
      packet_count = 0

      fetcher.fetch do |packet|
        analysis = analyzer.analyze(packet)
        packets_data << {
          analysis: analysis,
          payload: packet[:payload]  # Keep in memory for frame aggregation only
        }
        saver.save_packet(packet)
        packet_count += 1

        if Time.now - start_time >= duration
          break
        end
      end

      saver.close

      # Aggregate frames (use payloads from memory)
      frames = aggregate_frames(packets_data)

      # Save analysis data (WITHOUT payloads - only metadata)
      analysis_file = output_mgr.get_output_path('analysis.json')
      File.write(analysis_file, packets_data.map { |p| p[:analysis] }.to_json)

      # Save individual frame binary files
      require_relative 'packet_extractor'
      frames_dir = File.join(output_mgr.run_dir, 'frames')
      discarded_dir = File.join(output_mgr.run_dir, 'discarded_packets')
      FileUtils.mkdir_p(frames_dir)
      FileUtils.mkdir_p(discarded_dir)

      # For H.264, we need to preserve packet order and de-fragment properly
      # Group packets by RTP timestamp to identify frame boundaries
      frames_by_rtp = {}
      frame_order = []
      discarded_packets = []
      found_sps = false

      packets_data.each do |pkt_data|
        payload = pkt_data[:payload]
        analysis = pkt_data[:analysis]
        payload_type = analysis[:payload_type_code]

        # Check if packet passes all filters
        is_valid = true
        discard_reason = nil

        # Filter 1: Check if this is a video packet (payload type 96 = H.264)
        # Discard all non-video packets (audio, etc.)
        if payload_type != 96
          is_valid = false
          discard_reason = "Non-video packet (payload type #{payload_type})"
        end

        # Filter 2: Check if packet has valid payload
        if is_valid && (!payload || payload.length < 1)
          is_valid = false
          discard_reason = "Empty/invalid payload"
        end

        # Filter 3: Check for reserved NAL types
        if is_valid
          first_byte = payload[0].ord
          nal_unit_type = first_byte & 0x1F

          if nal_unit_type >= 30
            is_valid = false
            discard_reason = "Reserved NAL type (#{nal_unit_type})"
          end
        end

        # Filter 4: Check if this is a pre-SPS packet (packet before first SPS)
        if is_valid && !found_sps
          first_byte = payload[0].ord
          nal_unit_type = first_byte & 0x1F

          if nal_unit_type == 7  # SPS
            found_sps = true
          else
            # This packet comes before SPS, discard it
            is_valid = false
            discard_reason = "Pre-SPS packet (#{analysis[:frame_type]})"
          end
        end

        # If packet didn't pass filters, add to discarded
        if !is_valid
          pkt_data[:discard_reason] = discard_reason
          discarded_packets << pkt_data
          next
        end

        # Packet passed all filters, add to frames
        rtp_ts = analysis[:rtp_timestamp_raw]
        unless frames_by_rtp.key?(rtp_ts)
          frames_by_rtp[rtp_ts] = []
          frame_order << rtp_ts
        end
        frames_by_rtp[rtp_ts] << pkt_data
      end

      # Create individual frame files for each RTP timestamp
      # Also create a complete H.264 stream with SPS/PPS at the beginning
      frame_number = 1
      sps_pps_data = nil
      is_first_frame = true

      frame_order.each do |rtp_ts|
        frame_packets = frames_by_rtp[rtp_ts]
        frame_data = defragment_h264_frame(frame_packets, is_first_frame)

        # Extract and save SPS/PPS from first frame
        if sps_pps_data.nil?
          sps_pps_data = extract_sps_pps(frame_data)
        end

        # Save individual frame file
        frame_filename = format("frame%05d.bin", frame_number)
        frame_filepath = File.join(frames_dir, frame_filename)
        File.binwrite(frame_filepath, frame_data)
        frame_number += 1
        is_first_frame = false
      end

      # Save discarded packets for analysis
      save_discarded_packets(discarded_packets, discarded_dir)

      # Save audio packets separately if any exist
      audio_packets = discarded_packets.select { |p| p[:discard_reason]&.include?("Audio") }
      if audio_packets.length > 0
        save_audio_packets(audio_packets, discarded_dir)
      end

      # Create complete H.264 stream with SPS/PPS at the beginning
      h264_stream = defragment_h264_stream(packets_data)

      # Calculate actual frame rate from RTP timestamps
      rtp_timestamps = packets_data.map { |p| p[:analysis][:rtp_timestamp_raw] }.uniq
      actual_fps = calculate_frame_rate(rtp_timestamps, duration)

      # Generate playable MP4 file from the complete H.264 stream
      generate_mp4_from_h264_stream(h264_stream, output_mgr.run_dir, actual_fps)

      # Extract host and scan_id from paths
      # stream_dir: logs/streams/192_168_88_31_ch0
      # run_dir: logs/streams/192_168_88_31_ch0/20251101_110015
      host = File.basename(output_mgr.stream_dir)
      scan_id = File.basename(output_mgr.run_dir)

      {
        status: 'success',
        packet_count: packet_count,
        frame_count: frames.length,
        duration: (Time.now - start_time).round(2),
        frames: frames,
        host: host,
        scan_id: scan_id
      }
    end

    def aggregate_frames(packets_data)
      frames_by_rtp = {}
      frame_order = []

      packets_data.each do |pkt_data|
        packet = pkt_data[:analysis]
        rtp_ts = packet[:rtp_timestamp_raw]
        unless frames_by_rtp.key?(rtp_ts)
          frames_by_rtp[rtp_ts] = []
          frame_order << rtp_ts
        end
        frames_by_rtp[rtp_ts] << pkt_data
      end

      frame_order.map.with_index do |rtp_ts, idx|
        frame_packets = frames_by_rtp[rtp_ts]

        # Concatenate packet payloads
        frame_payload = frame_packets.map { |p| p[:payload] || '' }.join

        {
          frame_number: idx + 1,
          frame_type: frame_packets.first[:analysis][:frame_type].split('(')[0],
          packet_count: frame_packets.length,
          total_size: frame_packets.sum { |p| p[:analysis][:raw_packet_size] },
          rtp_timestamp: rtp_ts,
          first_packet: frame_packets.first[:analysis][:packet_number],
          last_packet: frame_packets.last[:analysis][:packet_number],
          deviation: frame_packets.first[:analysis][:timestamp_deviation_us],
          payload: Base64.encode64(frame_payload).chomp
        }
      end
    end

    def generate_hex_dump(data, bytes_per_line = 16)
      lines = []
      data.each_byte.each_slice(bytes_per_line).with_index do |bytes, line_idx|
        offset = line_idx * bytes_per_line
        hex_part = bytes.map { |b| format('%02X', b) }.join(' ')
        ascii_part = bytes.map { |b| (32..126).include?(b) ? b.chr : '.' }.join
        lines << format('%08X  %-48s  %s', offset, hex_part, ascii_part)
      end
      lines.join("\n")
    end

    def render_ui
      <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Streamripper - RTSP Stream Analyzer</title>
          <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
          <style>
            * {
              margin: 0;
              padding: 0;
              box-sizing: border-box;
            }
            
            body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              min-height: 100vh;
              padding: 20px;
            }
            
            .container {
              max-width: 1400px;
              margin: 0 auto;
              background: white;
              border-radius: 12px;
              box-shadow: 0 20px 60px rgba(0,0,0,0.3);
              overflow: hidden;
            }
            
            .header {
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              color: white;
              padding: 40px;
              text-align: center;
            }
            
            .header h1 {
              font-size: 2.5em;
              margin-bottom: 10px;
            }

            .header a {
              color: white;
              text-decoration: none;
              transition: opacity 0.3s;
            }

            .header a:hover {
              opacity: 0.8;
            }
            
            .content {
              padding: 40px;
            }
            
            .input-section {
              background: #f5f5f5;
              padding: 20px;
              border-radius: 8px;
              margin-bottom: 30px;
            }
            
            .input-group {
              display: flex;
              gap: 10px;
              margin-bottom: 10px;
            }
            
            input[type="text"],
            input[type="number"] {
              flex: 1;
              padding: 12px;
              border: 1px solid #ddd;
              border-radius: 4px;
              font-size: 1em;
            }
            
            button {
              padding: 12px 24px;
              background: #667eea;
              color: white;
              border: none;
              border-radius: 4px;
              cursor: pointer;
              font-size: 1em;
              transition: background 0.3s;
            }
            
            button:hover {
              background: #764ba2;
            }
            
            button:disabled {
              background: #ccc;
              cursor: not-allowed;
            }
            
            .stats-grid {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
              gap: 15px;
              margin-bottom: 30px;
            }
            
            .stat-card {
              background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
              padding: 20px;
              border-radius: 8px;
              border-left: 4px solid #667eea;
            }
            
            .stat-card h3 {
              color: #667eea;
              font-size: 0.9em;
              text-transform: uppercase;
              margin-bottom: 10px;
            }
            
            .stat-card .value {
              font-size: 2em;
              font-weight: bold;
              color: #333;
            }
            
            .frames-table {
              width: 100%;
              border-collapse: collapse;
              margin-top: 20px;
            }
            
            .frames-table th {
              background: #667eea;
              color: white;
              padding: 12px;
              text-align: left;
              font-weight: 600;
            }
            
            .frames-table td {
              padding: 10px 12px;
              border-bottom: 1px solid #eee;
            }
            
            .frames-table tr:hover {
              background: #f5f5f5;
              cursor: pointer;
            }
            
            .frame-type {
              display: inline-block;
              padding: 4px 8px;
              border-radius: 4px;
              font-size: 0.85em;
              font-weight: 600;
              color: white;
            }
            
            .frame-type.i-frame { background: #1b5e20; }
            .frame-type.p-frame { background: #81c784; }
            .frame-type.sps { background: #ffd93d; color: #333; }
            .frame-type.pps { background: #ffd93d; color: #333; }
            .frame-type.audio { background: #1976d2; }
            .frame-type.unknown { background: #d32f2f; }
            
            .loading {
              display: none;
              text-align: center;
              padding: 20px;
            }
            
            .spinner {
              border: 4px solid #f3f3f3;
              border-top: 4px solid #667eea;
              border-radius: 50%;
              width: 40px;
              height: 40px;
              animation: spin 1s linear infinite;
              margin: 0 auto;
            }
            
            @keyframes spin {
              0% { transform: rotate(0deg); }
              100% { transform: rotate(360deg); }
            }
            
            .modal {
              display: none;
              position: fixed;
              z-index: 1000;
              left: 0;
              top: 0;
              width: 100%;
              height: 100%;
              background-color: rgba(0, 0, 0, 0.5);
              overflow: hidden;
            }

            .modal.active {
              display: flex;
              align-items: center;
              justify-content: center;
            }

            .modal-content {
              background-color: white;
              border-radius: 8px;
              width: 90%;
              max-width: 1200px;
              height: 90vh;
              display: flex;
              flex-direction: column;
              box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
              overflow: hidden;
            }

            .capture-modal {
              display: none;
              position: fixed;
              z-index: 2000;
              left: 0;
              top: 0;
              width: 100%;
              height: 100%;
              background-color: rgba(0, 0, 0, 0.7);
              justify-content: center;
              align-items: center;
            }

            .capture-modal.active {
              display: flex;
            }

            .capture-modal-content {
              background: white;
              padding: 40px;
              border-radius: 12px;
              text-align: center;
              box-shadow: 0 20px 60px rgba(0,0,0,0.3);
              min-width: 300px;
            }

            .capture-modal-spinner {
              border: 4px solid #f3f3f3;
              border-top: 4px solid #667eea;
              border-radius: 50%;
              width: 60px;
              height: 60px;
              animation: spin 1s linear infinite;
              margin: 0 auto 20px;
            }

            .capture-modal-text {
              font-size: 1.2em;
              color: #333;
              margin-bottom: 15px;
              font-weight: 500;
            }

            .capture-modal-countdown {
              font-size: 2.5em;
              color: #667eea;
              font-weight: bold;
              font-family: 'Courier New', monospace;
              margin: 20px 0;
            }

            .capture-modal-subtext {
              font-size: 0.9em;
              color: #666;
              margin-top: 15px;
            }

            .modal-header {
              display: flex;
              justify-content: space-between;
              align-items: center;
              padding: 20px;
              border-bottom: 2px solid #667eea;
              flex-shrink: 0;
            }

            .modal-header h2 {
              margin: 0;
              color: #333;
              flex: 1;
            }

            .modal-header-buttons {
              display: flex;
              gap: 10px;
              align-items: center;
            }

            .download-btn {
              background: #667eea;
              color: white;
              border: none;
              padding: 8px 16px;
              border-radius: 4px;
              cursor: pointer;
              font-size: 0.9em;
              transition: background 0.2s;
            }

            .download-btn:hover:not(:disabled) {
              background: #764ba2;
            }

            .download-btn:disabled {
              background: #999;
              cursor: not-allowed;
              opacity: 0.7;
            }

            .modal-body {
              display: flex;
              flex-direction: column;
              flex: 1;
              overflow: hidden;
              padding: 20px;
              gap: 15px;
            }

            .close-btn {
              background: none;
              border: none;
              font-size: 28px;
              color: #667eea;
              cursor: pointer;
              padding: 0;
              width: 32px;
              height: 32px;
              display: flex;
              align-items: center;
              justify-content: center;
            }

            body.modal-open {
              overflow: hidden;
            }
            
            .hex-dump {
              background: #1e1e1e;
              color: #00ff00;
              font-family: 'Courier New', monospace;
              font-size: 15px;
              padding: 15px;
              border-radius: 4px;
              overflow-x: auto;
              line-height: 1.6;
              white-space: pre;
            }
            
            .error {
              background: #ff6b6b;
              color: white;
              padding: 15px;
              border-radius: 4px;
              margin-bottom: 20px;
              display: none;
            }

            #previousScans {
              background: #f5f5f5;
              padding: 20px;
              border-radius: 8px;
              margin-bottom: 20px;
            }

            #previousScans h3 {
              margin-top: 0;
              color: #333;
              font-size: 1.1em;
            }

            .scans-list {
              display: grid;
              grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
              gap: 15px;
            }

            .scan-card {
              background: white;
              padding: 15px;
              border-radius: 4px;
              border-left: 4px solid #667eea;
              box-shadow: 0 2px 4px rgba(0,0,0,0.1);
              transition: transform 0.2s, box-shadow 0.2s;
            }

            .scan-card:hover {
              transform: translateY(-2px);
              box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }

            .scan-card-time {
              font-weight: bold;
              color: #667eea;
              font-size: 0.9em;
            }

            .scan-card-host {
              color: #666;
              font-size: 0.85em;
              margin-top: 5px;
            }

            .scan-card-stats {
              color: #999;
              font-size: 0.8em;
              margin-top: 8px;
            }

            .scan-card-links {
              display: flex;
              gap: 10px;
              margin-top: 10px;
            }

            .scan-link {
              flex: 1;
              padding: 6px 10px;
              background: #667eea;
              color: white;
              text-decoration: none;
              border-radius: 3px;
              font-size: 0.8em;
              text-align: center;
              transition: background 0.2s;
              border: none;
              cursor: pointer;
              font-family: inherit;
            }

            .scan-link:hover {
              background: #764ba2;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1><a href="/">🎬 Streamripper</a></h1>
              <p>Real-time RTSP Stream Analysis & Forensics</p>
            </div>
            
            <div class="content">
              <div class="error" id="errorMsg"></div>
              
              <div class="input-section">
                <div class="input-group">
                  <input type="text" id="rtspUrl" placeholder="RTSP URL (e.g., rtsp://user:pass@host/ch0)" value="rtsp://thingino:thingino@192.168.88.31/ch0">
                  <input type="number" id="duration" placeholder="Duration (seconds)" value="5" min="1" max="300">
                  <button onclick="startCapture()">Start Capture</button>
                </div>
              </div>

              <div class="capture-modal" id="captureModal">
                <div class="capture-modal-content">
                  <div class="capture-modal-spinner"></div>
                  <div class="capture-modal-text">Capturing Stream...</div>
                  <div class="capture-modal-countdown" id="countdownDisplay">0:00</div>
                  <div class="capture-modal-subtext">Please wait while the stream is being captured and analyzed</div>
                </div>
              </div>

              <div id="results" style="display: none;">
                <div class="stats-grid">
                  <div class="stat-card">
                    <h3>Total Frames</h3>
                    <div class="value" id="frameCount">0</div>
                  </div>
                  <div class="stat-card">
                    <h3>Total Packets</h3>
                    <div class="value" id="packetCount">0</div>
                  </div>
                  <div class="stat-card">
                    <h3>Duration</h3>
                    <div class="value" id="captureDuration">0s</div>
                  </div>
                  <div class="stat-card">
                    <h3>Frame Rate</h3>
                    <div class="value" id="frameRate">0 fps</div>
                  </div>
                </div>

                <h2 style="margin-top: 40px;">Analysis Charts</h2>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-top: 20px;">
                  <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="margin-bottom: 15px; color: #333;">Time Deviation (µs)</h3>
                    <canvas id="deviationChart"></canvas>
                  </div>
                  <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="margin-bottom: 15px; color: #333;">Packet Sizes (bytes)</h3>
                    <canvas id="packetSizeChart"></canvas>
                  </div>
                </div>

                <h2 style="margin-top: 40px;">Frame Summary</h2>
                <table class="frames-table">
                  <thead>
                    <tr>
                      <th>Frame #</th>
                      <th>Type</th>
                      <th>Size</th>
                      <th>Packets</th>
                      <th>RTP TS</th>
                      <th>Deviation</th>
                    </tr>
                  </thead>
                  <tbody id="framesBody"></tbody>
                </table>

                <h2 style="margin-top: 40px;">Video Playback</h2>
                <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-top: 20px;">
                  <video id="streamVideo" width="100%" height="auto" controls style="max-width: 100%; border-radius: 4px; background: #000;">
                    <source id="videoSource" src="" type="video/mp4">
                    Your browser does not support the video tag.
                  </video>
                  <p id="videoStatus" style="margin-top: 10px; color: #666; font-size: 14px;">Loading video...</p>
                </div>
              </div>

              <div id="previousScans" style="display: none; margin-top: 40px; padding-top: 40px; border-top: 2px solid #eee;">
                <h2>Previous Scans</h2>
                <div id="scansList" class="scans-list"></div>
              </div>
            </div>
          </div>
          
          <!-- Hex Modal -->
          <div id="hexModal" class="modal">
            <div class="modal-content">
              <div class="modal-header">
                <h2 id="modalTitle">Frame Hex Dump</h2>
                <div class="modal-header-buttons">
                  <button class="download-btn" id="downloadFrameBtn" onclick="downloadFrame()" title="Download frame binary">⬇️ Download</button>
                  <button class="close-btn" onclick="closeHexModal()" title="Close (ESC)">&times;</button>
                </div>
              </div>
              <div class="modal-body">
                <div class="hex-dump" id="hexContent"></div>
              </div>
            </div>
          </div>
          
          <script>
            let captureData = null;
            let currentFrame = null;
            let downloadInProgress = false;
            let countdownInterval = null;
            let deviationChart = null;
            let packetSizeChart = null;

            async function startCapture() {
              const rtspUrl = document.getElementById('rtspUrl').value;
              const duration = parseInt(document.getElementById('duration').value);

              if (!rtspUrl) {
                showError('Please enter an RTSP URL');
                return;
              }

              // Show capture modal
              const captureModal = document.getElementById('captureModal');
              captureModal.classList.add('active');
              document.getElementById('results').style.display = 'none';
              document.getElementById('errorMsg').style.display = 'none';

              // Preset the countdown display with initial value
              const countdownDisplay = document.getElementById('countdownDisplay');
              const minutes = Math.floor(duration / 60);
              const seconds = duration % 60;
              countdownDisplay.textContent = minutes + ':' + (seconds < 10 ? '0' : '') + seconds;

              // Start countdown
              let remainingTime = duration;

              countdownInterval = setInterval(() => {
                remainingTime--;

                // Ensure remainingTime doesn't go below 0
                if (remainingTime < 0) {
                  remainingTime = 0;
                }

                const minutes = Math.floor(remainingTime / 60);
                const seconds = remainingTime % 60;
                countdownDisplay.textContent = minutes + ':' + (seconds < 10 ? '0' : '') + seconds;

                if (remainingTime <= 0) {
                  clearInterval(countdownInterval);
                  countdownInterval = null;
                }
              }, 1000);

              try {
                const response = await fetch('/api/capture', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ rtsp_url: rtspUrl, duration: duration })
                });

                if (!response.ok) {
                  const error = await response.json();
                  throw new Error(error.error || 'Capture failed');
                }

                captureData = await response.json();

                // Extract host and scan_id from the capture response
                if (captureData.host && captureData.scan_id) {
                  // Update URL to the new scan
                  const newUrl = '?host=' + encodeURIComponent(captureData.host) +
                                 '&scan_id=' + encodeURIComponent(captureData.scan_id);
                  window.history.pushState({ host: captureData.host, scan_id: captureData.scan_id }, '', newUrl);
                }

                displayResults(captureData);
              } catch (error) {
                showError(error.message);
              } finally {
                // Clear countdown interval
                if (countdownInterval) {
                  clearInterval(countdownInterval);
                  countdownInterval = null;
                }

                // Hide capture modal
                const captureModal = document.getElementById('captureModal');
                captureModal.classList.remove('active');
                document.getElementById('results').style.display = 'block';
              }
            }
            
            function displayResults(data) {
              document.getElementById('frameCount').textContent = data.frame_count;
              document.getElementById('packetCount').textContent = data.packet_count;
              document.getElementById('captureDuration').textContent = data.duration + 's';
              document.getElementById('frameRate').textContent = (data.frame_count / data.duration).toFixed(2) + ' fps';

              const tbody = document.getElementById('framesBody');
              tbody.innerHTML = '';

              data.frames.forEach(frame => {
                const row = document.createElement('tr');
                const typeClass = frame.frame_type.toLowerCase().replace('-', '-');
                row.innerHTML = `
                  <td>\${frame.frame_number}</td>
                  <td><span class="frame-type \${typeClass}">\${frame.frame_type}</span></td>
                  <td>\${frame.total_size} bytes</td>
                  <td>\${frame.packet_count}</td>
                  <td>\${frame.rtp_timestamp}</td>
                  <td>\${frame.deviation} µs</td>
                `;
                row.onclick = () => showHexDump(frame);
                tbody.appendChild(row);
              });

              // Render charts
              renderDeviationChart(data.frames);
              renderPacketSizeChart(data.frames);

              // Load video if available
              if (data.host && data.scan_id) {
                loadVideo(data.host, data.scan_id);
              }

              document.getElementById('results').style.display = 'block';
              showPreviousScansSection();

              // Scroll to results
              document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
            }

            function loadVideo(host, scanId) {
              const videoSource = document.getElementById('videoSource');
              const videoStatus = document.getElementById('videoStatus');
              const videoElement = document.getElementById('streamVideo');

              if (!videoSource || !videoStatus || !videoElement) {
                console.error('Video elements not found');
                return;
              }

              const mp4Url = '/logs/streams/' + encodeURIComponent(host) + '/' + encodeURIComponent(scanId) + '/stream.mp4';

              console.log('Loading video from:', mp4Url);
              videoSource.src = mp4Url;
              videoElement.load();

              // Check if video file exists and is valid
              fetch(mp4Url, { method: 'HEAD' })
                .then(response => {
                  if (response.ok) {
                    const size = response.headers.get('content-length');
                    if (size > 10000) {
                      videoStatus.textContent = '✓ Video ready for playback';
                      videoStatus.style.color = '#4CAF50';
                    } else {
                      videoStatus.textContent = '⏳ Video is being generated...';
                      videoStatus.style.color = '#FF9800';
                    }
                  } else {
                    videoStatus.textContent = '⏳ Video is being generated...';
                    videoStatus.style.color = '#FF9800';
                  }
                })
                .catch(error => {
                  videoStatus.textContent = '⏳ Video is being generated...';
                  videoStatus.style.color = '#FF9800';
                  console.log('Video file not yet available:', error);
                });
            }

            function renderDeviationChart(frames) {
              // Destroy existing chart if it exists
              if (deviationChart) {
                deviationChart.destroy();
                deviationChart = null;
              }

              const ctx = document.getElementById('deviationChart').getContext('2d');

              const labels = frames.map(f => 'Frame ' + f.frame_number);
              const deviations = frames.map(f => f.deviation);

              // Determine color based on deviation value
              const colors = deviations.map(d => {
                if (d === 0) return '#4CAF50'; // Green for 0
                if (d > 0) return '#FF9800'; // Orange for positive
                return '#F44336'; // Red for negative
              });

              deviationChart = new Chart(ctx, {
                type: 'bar',
                data: {
                  labels: labels,
                  datasets: [{
                    label: 'Time Deviation (µs)',
                    data: deviations,
                    backgroundColor: colors,
                    borderColor: colors,
                    borderWidth: 1
                  }]
                },
                options: {
                  responsive: true,
                  maintainAspectRatio: true,
                  plugins: {
                    legend: {
                      display: true,
                      position: 'top'
                    }
                  },
                  scales: {
                    y: {
                      beginAtZero: true,
                      title: {
                        display: true,
                        text: 'Deviation (µs)'
                      }
                    }
                  }
                }
              });
            }

            function renderPacketSizeChart(frames) {
              // Destroy existing chart if it exists
              if (packetSizeChart) {
                packetSizeChart.destroy();
                packetSizeChart = null;
              }

              const ctx = document.getElementById('packetSizeChart').getContext('2d');

              const labels = frames.map(f => 'Frame ' + f.frame_number);
              const sizes = frames.map(f => f.total_size);

              packetSizeChart = new Chart(ctx, {
                type: 'line',
                data: {
                  labels: labels,
                  datasets: [{
                    label: 'Packet Size (bytes)',
                    data: sizes,
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#667eea',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6
                  }]
                },
                options: {
                  responsive: true,
                  maintainAspectRatio: true,
                  plugins: {
                    legend: {
                      display: true,
                      position: 'top'
                    }
                  },
                  scales: {
                    y: {
                      beginAtZero: true,
                      title: {
                        display: true,
                        text: 'Size (bytes)'
                      }
                    }
                  }
                }
              });
            }
            
            async function showHexDump(frame) {
              try {
                // Store current frame for download
                currentFrame = frame;

                const response = await fetch('/api/frame-hex?frame=' + encodeURIComponent(frame.payload));
                const data = await response.json();
                document.getElementById('hexContent').textContent = data.hex;

                // Update modal header with frame info
                const modalTitle = document.getElementById('modalTitle');
                if (modalTitle) {
                  modalTitle.textContent = 'Frame ' + frame.frame_number + ' - ' + frame.frame_type + ' (' + frame.total_size + ' bytes)';
                }

                const modal = document.getElementById('hexModal');
                modal.classList.add('active');
                document.body.classList.add('modal-open');
              } catch (error) {
                showError('Failed to load hex dump: ' + error.message);
              }
            }

            function downloadFrame() {
              // Prevent double downloads with debounce
              if (downloadInProgress) {
                return;
              }

              if (!currentFrame) {
                showError('No frame selected');
                return;
              }

              try {
                // Set download in progress flag
                downloadInProgress = true;
                const downloadBtn = document.getElementById('downloadFrameBtn');
                const originalText = downloadBtn.textContent;
                downloadBtn.textContent = '⏳ Downloading...';
                downloadBtn.disabled = true;

                // Decode base64 payload to binary
                const binaryString = atob(currentFrame.payload);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                  bytes[i] = binaryString.charCodeAt(i);
                }

                // Create blob and download
                const blob = new Blob([bytes], { type: 'application/octet-stream' });
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = 'frame_' + currentFrame.frame_number.toString().padStart(5, '0') + '_' + currentFrame.frame_type.toLowerCase() + '.bin';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);

                // Reset button after download completes
                setTimeout(() => {
                  downloadBtn.textContent = originalText;
                  downloadBtn.disabled = false;
                  downloadInProgress = false;
                }, 1000);
              } catch (error) {
                showError('Failed to download frame: ' + error.message);
                // Reset on error
                downloadInProgress = false;
                const downloadBtn = document.getElementById('downloadFrameBtn');
                downloadBtn.textContent = '⬇️ Download';
                downloadBtn.disabled = false;
              }
            }

            function closeHexModal() {
              const modal = document.getElementById('hexModal');
              modal.classList.remove('active');
              document.body.classList.remove('modal-open');
            }

            function showError(message) {
              const errorDiv = document.getElementById('errorMsg');
              errorDiv.textContent = message;
              errorDiv.style.display = 'block';
            }

            // Close modal when clicking outside (on the backdrop)
            document.addEventListener('click', function(event) {
              const modal = document.getElementById('hexModal');
              if (event.target === modal) {
                closeHexModal();
              }
            });

            // Close modal on ESC key
            document.addEventListener('keydown', function(event) {
              if (event.key === 'Escape') {
                const modal = document.getElementById('hexModal');
                if (modal.classList.contains('active')) {
                  closeHexModal();
                }
              }
            });

            // Load previous scans on page load
            document.addEventListener('DOMContentLoaded', function() {
              loadPreviousScans();

              // Check if URL has scan parameters
              const params = new URLSearchParams(window.location.search);
              const host = params.get('host');
              const scanId = params.get('scan_id');

              if (host && scanId) {
                // Load the scan from URL parameters
                loadScanData(host, scanId);
              }
            });

            async function loadPreviousScans() {
              try {
                const response = await fetch('/api/scans');
                const data = await response.json();

                if (data.scans && data.scans.length > 0) {
                  displayPreviousScans(data.scans);
                }
              } catch (error) {
                console.error('Failed to load previous scans:', error);
              }
            }

            function displayPreviousScans(scans) {
              const scansList = document.getElementById('scansList');
              const previousScans = document.getElementById('previousScans');

              scansList.innerHTML = '';

              scans.forEach(scan => {
                const card = document.createElement('div');
                card.className = 'scan-card';
                card.innerHTML = `
                  <div class="scan-card-time">${scan.time}</div>
                  <div class="scan-card-host">${scan.host}</div>
                  <div class="scan-card-stats">${scan.packet_count} packets</div>
                  <div class="scan-card-links">
                    <button class="scan-link" onclick="loadScanData('${scan.host}', '${scan.scan_id}')">📊 Load</button>
                    <a href="${scan.json_url}" class="scan-link" target="_blank">📋 JSON</a>
                  </div>
                `;
                scansList.appendChild(card);
              });

              // Always show previous scans
              previousScans.style.display = 'block';
            }

            // Show previous scans after results are displayed
            function showPreviousScansSection() {
              const previousScans = document.getElementById('previousScans');
              previousScans.style.display = 'block';
            }

            async function loadScanData(host, scanId) {
              try {
                document.getElementById('results').style.display = 'none';
                document.getElementById('errorMsg').style.display = 'none';

                const response = await fetch('/api/load-scan?host=' + encodeURIComponent(host) + '&scan_id=' + encodeURIComponent(scanId));

                if (!response.ok) {
                  const error = await response.json();
                  throw new Error(error.error || 'Failed to load scan');
                }

                const data = await response.json();
                displayResults(data);

                // Update URL to include scan identifier
                const newUrl = '?host=' + encodeURIComponent(host) + '&scan_id=' + encodeURIComponent(scanId);
                window.history.pushState({ host: host, scan_id: scanId }, '', newUrl);
              } catch (error) {
                showError('Failed to load scan: ' + error.message);
              }
            }
          </script>
        </body>
        </html>
      HTML
    end

    def load_scan_data(host, scan_id)
      analysis_json = File.join('logs/streams', host, scan_id, 'analysis.json')

      raise "Scan not found: #{scan_id}" unless File.exist?(analysis_json)

      data = JSON.parse(File.read(analysis_json))

      # Calculate duration from wallclock timestamps
      duration = 0
      if data.length > 1
        first_time = data.first['wallclock_time_us']
        last_time = data.last['wallclock_time_us']
        duration = ((last_time - first_time) / 1_000_000.0).round(2)
      end

      # Aggregate frames with host and scan_id for frame file loading
      frames = aggregate_frames_from_data(data, host, scan_id)

      {
        status: 'success',
        packet_count: data.length,
        frame_count: frames.length,
        duration: duration,
        frames: frames,
        host: host,
        scan_id: scan_id
      }
    end

    def aggregate_frames_from_data(packets, host = nil, scan_id = nil)
      frames_by_rtp = {}
      frame_order = []

      packets.each do |packet|
        rtp_ts = packet['rtp_timestamp_raw']
        unless frames_by_rtp.key?(rtp_ts)
          frames_by_rtp[rtp_ts] = []
          frame_order << rtp_ts
        end
        frames_by_rtp[rtp_ts] << packet
      end

      frame_order.map.with_index do |rtp_ts, idx|
        frame_packets = frames_by_rtp[rtp_ts]
        frame_number = idx + 1

        # ALWAYS load frame binary file - this is the single source of truth
        frame_payload = ''
        frame_file_size = 0
        if host && scan_id
          frame_file = File.join('logs/streams', host, scan_id, 'frames', "frame#{frame_number.to_s.rjust(5, '0')}.bin")
          if File.exist?(frame_file)
            frame_payload = File.binread(frame_file)
            frame_file_size = frame_payload.bytesize
          else
            # Frame file doesn't exist - show error
            frame_payload = "[ERROR: Frame file not found]"
          end
        else
          # No host/scan_id provided - show error
          frame_payload = "[ERROR: Frame data not available - no host/scan_id]"
        end

        {
          frame_number: frame_number,
          frame_type: frame_packets.first['frame_type'].split('(')[0],
          packet_count: frame_packets.length,
          total_size: frame_file_size,  # Use actual frame file size, not raw packet size
          rtp_timestamp: rtp_ts,
          first_packet: frame_packets.first['packet_number'],
          last_packet: frame_packets.last['packet_number'],
          deviation: frame_packets.first['timestamp_deviation_us'],
          payload: Base64.encode64(frame_payload).chomp
        }
      end
    end

    def get_previous_scans
      scans_dir = 'logs/streams'
      return [] unless Dir.exist?(scans_dir)

      scans = []
      Dir.glob("#{scans_dir}/*").each do |host_dir|
        next unless File.directory?(host_dir)

        Dir.glob("#{host_dir}/*").each do |scan_dir|
          next unless File.directory?(scan_dir)

          analysis_json = File.join(scan_dir, 'analysis.json')
          analysis_html = File.join(scan_dir, 'analysis.html')

          if File.exist?(analysis_json)
            begin
              data = JSON.parse(File.read(analysis_json))
              timestamp = File.mtime(analysis_json).to_i

              scans << {
                timestamp: timestamp,
                time: Time.at(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                host: File.basename(host_dir),
                scan_id: File.basename(scan_dir),
                packet_count: data.length,
                html_url: analysis_html.sub('logs/', ''),
                json_url: analysis_json.sub('logs/', '')
              }
            rescue => e
              # Skip invalid scans
            end
          end
        end
      end

      scans.sort_by { |s| -s[:timestamp] }.take(20)
    end

    def save_audio_packets(audio_packets, discarded_dir)
      # Save audio packets to separate subdirectory
      audio_dir = File.join(discarded_dir, 'audio')
      FileUtils.mkdir_p(audio_dir)

      # Save raw audio data
      audio_raw_file = File.join(audio_dir, 'audio_packets.bin')
      File.open(audio_raw_file, 'wb') do |f|
        audio_packets.each do |pkt_data|
          payload = pkt_data[:payload]
          f.write(payload) if payload
        end
      end

      # Save audio packet analysis as JSON
      audio_json_file = File.join(audio_dir, 'audio_packets.json')
      audio_data = audio_packets.map do |p|
        analysis = p[:analysis].dup
        analysis[:discard_reason] = p[:discard_reason]
        analysis
      end
      File.write(audio_json_file, JSON.pretty_generate(audio_data))

      # Save audio summary
      audio_summary_file = File.join(audio_dir, 'summary.txt')
      File.open(audio_summary_file, 'w') do |f|
        f.puts "Audio Packets Analysis"
        f.puts "=" * 50
        f.puts "Total audio packets: #{audio_packets.length}"
        f.puts ""

        # Calculate total audio data size
        total_size = audio_packets.sum { |p| p[:payload]&.length || 0 }
        f.puts "Total audio data: #{total_size} bytes"
        f.puts ""

        # Audio codec info
        if audio_packets.length > 0
          first_packet = audio_packets.first
          codec = first_packet[:analysis][:packet_type]
          f.puts "Audio Codec: #{codec}"
          f.puts "Payload Type: #{first_packet[:analysis][:payload_type_code]}"
          f.puts ""
        end

        # RTP timestamp info
        rtp_timestamps = audio_packets.map { |p| p[:analysis][:rtp_timestamp_raw] }.uniq
        f.puts "Unique RTP Timestamps: #{rtp_timestamps.length}"
        f.puts "Average packets per timestamp: #{(audio_packets.length.to_f / rtp_timestamps.length).round(2)}"
      end

      puts "Saved #{audio_packets.length} audio packets to #{audio_dir}"
    end

    def save_discarded_packets(discarded_packets, discarded_dir)
      # Save discarded packets to separate directory for analysis

      # Save raw binary data
      raw_file = File.join(discarded_dir, 'discarded_packets.bin')
      File.open(raw_file, 'wb') do |f|
        discarded_packets.each do |pkt_data|
          payload = pkt_data[:payload]
          f.write(payload) if payload
        end
      end

      # Save analysis data as JSON (including discard reason)
      analysis_file = File.join(discarded_dir, 'discarded_packets.json')
      analysis_data = discarded_packets.map do |p|
        analysis = p[:analysis].dup
        analysis[:discard_reason] = p[:discard_reason]
        analysis
      end
      File.write(analysis_file, JSON.pretty_generate(analysis_data))

      # Save summary report
      summary_file = File.join(discarded_dir, 'summary.txt')
      File.open(summary_file, 'w') do |f|
        f.puts "Discarded Packets Analysis"
        f.puts "=" * 50
        f.puts "Total discarded packets: #{discarded_packets.length}"
        f.puts ""

        # Group by discard reason
        discard_reasons = {}
        discarded_packets.each do |pkt_data|
          reason = pkt_data[:discard_reason] || "Unknown"
          discard_reasons[reason] ||= 0
          discard_reasons[reason] += 1
        end

        if discard_reasons.length > 0
          f.puts "Discard Reasons:"
          discard_reasons.sort.each do |reason, count|
            f.puts "  #{reason}: #{count}"
          end
        else
          f.puts "No packets discarded - stream is clean!"
        end
      end

      puts "Saved #{discarded_packets.length} discarded packets to #{discarded_dir}"
    end

    def extract_sps_pps(h264_data)
      # Extract SPS and PPS NAL units from H.264 data
      sps_pps = ''
      i = 0

      while i < h264_data.length - 4
        if h264_data[i..i+3] == "\x00\x00\x00\x01"
          nal_header = h264_data[i+4].ord
          nal_type = nal_header & 0x1F

          # Find the next start code
          next_start = i + 4
          while next_start < h264_data.length - 4
            if h264_data[next_start..next_start+3] == "\x00\x00\x00\x01"
              break
            end
            next_start += 1
          end

          # Extract this NAL unit
          nal_unit = h264_data[i..next_start-1]

          # Keep SPS (7) and PPS (8)
          if nal_type == 7 || nal_type == 8
            sps_pps += nal_unit
          end

          i = next_start
        else
          i += 1
        end
      end

      sps_pps
    end

    def calculate_frame_rate(rtp_timestamps, capture_duration)
      # Calculate actual frame rate from RTP timestamps
      # RTP clock rate for H.264 is 90000 Hz

      return 25.0 if rtp_timestamps.length < 2 || capture_duration <= 0

      # Number of frames is the number of unique RTP timestamps
      num_frames = rtp_timestamps.length

      # Frame rate = number of frames / capture duration
      frame_rate = num_frames / capture_duration.to_f

      # Clamp to reasonable values (5-60 fps)
      frame_rate = [frame_rate, 5.0].max
      frame_rate = [frame_rate, 60.0].min

      puts "Calculated frame rate: #{frame_rate.round(2)} fps (#{num_frames} frames in #{capture_duration}s)"

      frame_rate
    end

    def defragment_h264_stream(packets_data)
      # De-fragment H.264 NAL units from all packets in order
      # Skip packets until we find SPS to ensure proper stream structure
      # Skip duplicate SPS/PPS that appear after the first occurrence

      result = ''
      current_nal = nil
      found_sps = false
      found_pps = false
      skipped_count = 0
      added_count = 0

      packets_data.each_with_index do |pkt_data, idx|
        payload = pkt_data[:payload]
        if !payload || payload.length < 1
          skipped_count += 1
          next
        end

        first_byte = payload[0].ord
        nal_unit_type = first_byte & 0x1F

        # Skip packets until we find SPS (NAL type 7)
        if !found_sps && nal_unit_type != 7
          skipped_count += 1
          next
        end
        found_sps = true

        # Skip duplicate SPS/PPS after the first occurrence
        if found_pps && (nal_unit_type == 7 || nal_unit_type == 8)
          # This is a duplicate SPS or PPS, skip it
          skipped_count += 1
          next
        end

        # Mark that we've seen PPS (which comes after SPS)
        if nal_unit_type == 8
          found_pps = true
        end

        # Skip reserved NAL types (30-31)
        if nal_unit_type >= 30
          skipped_count += 1
          next
        end

        if nal_unit_type == 28  # FU-A (Fragmentation Unit A)
          # Handle fragmented NAL unit
          if payload.length < 2
            next
          end

          fu_header = payload[1].ord
          nal_type = fu_header & 0x1F
          start_bit = (fu_header >> 7) & 0x1
          end_bit = (fu_header >> 6) & 0x1
          fragment_data = payload[2..-1]

          # Skip FU-A fragments with reserved NAL types (>= 30)
          if nal_type >= 30
            skipped_count += 1
            next
          end

          if start_bit == 1
            # Start of fragmented NAL unit
            # Create NAL unit header with the original NAL type
            nri = (first_byte >> 5) & 0x3
            nal_header = ((nri << 5) | nal_type).chr
            current_nal = "\x00\x00\x01" + nal_header + fragment_data
          elsif current_nal && fragment_data
            # Continuation of fragmented NAL unit
            current_nal += fragment_data
          end

          if end_bit == 1 && current_nal
            # End of fragmented NAL unit
            result += current_nal
            current_nal = nil
          end
        else
          # Single NAL unit (not fragmented)
          result += "\x00\x00\x01" + payload
        end
      end

      # Add any remaining fragmented NAL unit
      result += current_nal if current_nal

      result
    end

    def defragment_h264_frame(frame_packets, is_first_frame = true)
      # De-fragment H.264 NAL units from RTP packets
      # Handle FU-A (Fragmentation Unit A) and single NAL units

      result = ''
      current_nal = nil

      frame_packets.each do |pkt_data|
        payload = pkt_data[:payload]
        next if !payload || payload.length < 1

        first_byte = payload[0].ord
        nal_unit_type = first_byte & 0x1F

        if nal_unit_type == 28  # FU-A (Fragmentation Unit A)
          # Handle fragmented NAL unit
          if payload.length < 2
            next
          end

          fu_header = payload[1].ord
          nal_type = fu_header & 0x1F
          start_bit = (fu_header >> 7) & 0x1
          end_bit = (fu_header >> 6) & 0x1
          fragment_data = payload[2..-1]

          # Skip FU-A fragments with reserved NAL types (>= 30)
          if nal_type >= 30
            next
          end

          if start_bit == 1
            # Start of fragmented NAL unit
            # Create NAL unit header with the original NAL type
            nri = (first_byte >> 5) & 0x3
            nal_header = ((nri << 5) | nal_type).chr
            current_nal = "\x00\x00\x01" + nal_header + fragment_data
          elsif current_nal && fragment_data
            # Continuation of fragmented NAL unit
            current_nal += fragment_data
          end

          if end_bit == 1 && current_nal
            # End of fragmented NAL unit
            result += current_nal
            current_nal = nil
          end
        else
          # Single NAL unit (not fragmented)
          result += "\x00\x00\x01" + payload
        end
      end

      # Add any remaining fragmented NAL unit
      result += current_nal if current_nal

      result
    end

    def generate_mp4_from_h264_stream(h264_stream, output_dir, fps = 25.0)
      mp4_file = File.join(output_dir, 'stream.mp4')

      # Return if MP4 already exists
      return if File.exist?(mp4_file)

      begin
        # Save H.264 stream to file
        h264_file = File.join(output_dir, 'stream.h264')
        File.binwrite(h264_file, h264_stream)

        puts "Created H.264 file: #{h264_file} (#{File.size(h264_file)} bytes)"

        # Use ffmpeg to copy H.264 stream to MP4 container with proper timing
        # -r fps sets the input frame rate
        # -c:v copy copies the H.264 stream without re-encoding
        # -movflags +faststart puts moov atom at the beginning for streaming
        cmd = "ffmpeg -r #{fps} -f h264 -i #{h264_file} -c:v copy -movflags +faststart -y #{mp4_file} 2>&1"
        output = `#{cmd}`

        if File.exist?(mp4_file) && File.size(mp4_file) > 10000
          puts "Created MP4 file with ffmpeg: #{mp4_file} (#{File.size(mp4_file)} bytes) at #{fps.round(2)} fps"
        else
          puts "ffmpeg copy failed, trying with re-encoding..."

          # Fallback: re-encode with libx264
          cmd = "ffmpeg -r #{fps} -f h264 -i #{h264_file} -c:v libx264 -preset ultrafast -r #{fps} -y #{mp4_file} 2>&1"
          output = `#{cmd}`

          if File.exist?(mp4_file) && File.size(mp4_file) > 10000
            puts "Created MP4 file with re-encoding: #{mp4_file} (#{File.size(mp4_file)} bytes)"
          else
            puts "Warning: MP4 generation failed"
          end
        end
      rescue => e
        puts "Warning: Failed to generate MP4: #{e.message}"
      end
    end

    def generate_mp4_from_frames(frames_dir, output_dir, fps = 25.0)
      mp4_file = File.join(output_dir, 'stream.mp4')

      # Return if MP4 already exists
      return if File.exist?(mp4_file)

      begin
        # Create H.264 file by concatenating frames
        h264_file = File.join(output_dir, 'stream.h264')
        File.open(h264_file, 'wb') do |out|
          Dir.glob("#{frames_dir}/frame*.bin").sort.each do |frame_file|
            frame_data = File.binread(frame_file)
            # Frames already have proper H.264 structure with start codes
            out.write(frame_data)
          end
        end

        puts "Created H.264 file: #{h264_file} (#{File.size(h264_file)} bytes)"

        # Use ffmpeg to copy H.264 stream to MP4 container with proper timing
        # -r fps sets the input frame rate
        # -c:v copy copies the H.264 stream without re-encoding
        # -movflags +faststart puts moov atom at the beginning for streaming
        cmd = "ffmpeg -r #{fps} -f h264 -i #{h264_file} -c:v copy -movflags +faststart -y #{mp4_file} 2>/dev/null"
        result = system(cmd)

        if result && File.exist?(mp4_file) && File.size(mp4_file) > 10000
          puts "Created MP4 file with ffmpeg: #{mp4_file} (#{File.size(mp4_file)} bytes) at #{fps.round(2)} fps"
        else
          puts "ffmpeg copy failed, trying with re-encoding..."

          # Fallback: re-encode with libx264
          cmd = "ffmpeg -r #{fps} -f h264 -i #{h264_file} -c:v libx264 -preset ultrafast -r #{fps} -y #{mp4_file} 2>/dev/null"
          system(cmd)

          if File.exist?(mp4_file) && File.size(mp4_file) > 10000
            puts "Created MP4 file with re-encoding: #{mp4_file} (#{File.size(mp4_file)} bytes)"
          else
            puts "Warning: MP4 generation failed"
          end
        end
      rescue => e
        puts "Warning: Failed to generate MP4: #{e.message}"
      end
    end
  end
end

