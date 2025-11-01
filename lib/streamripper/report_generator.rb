require 'json'

module Streamripper
  class ReportGenerator
    def initialize(analysis_json_path, frames_dir = nil)
      @analysis_json_path = analysis_json_path
      @frames_dir = frames_dir
      @data = load_analysis_data
      @report_path = analysis_json_path.gsub(/\.json$/, '.html')
    end

    attr_reader :report_path

    def generate
      html_content = render_template
      File.write(@report_path, html_content)
      @report_path
    end

    private

    def load_analysis_data
      JSON.parse(File.read(@analysis_json_path))
    end

    def render_template
      build_html
    end

    def aggregate_frames
      # Group packets by RTP timestamp to create frames
      frames = {}

      @data.each do |packet|
        rtp_ts = packet['rtp_timestamp_raw']
        frames[rtp_ts] ||= {
          rtp_timestamp_raw: rtp_ts,
          rtp_timestamp_us: packet['rtp_timestamp_us'],
          frame_type: packet['frame_type'].split('(')[0], # Remove fragment info
          packet_count: 0,
          total_size: 0,
          first_wallclock: packet['wallclock_time_us'],
          last_wallclock: packet['wallclock_time_us'],
          first_packet_number: packet['packet_number'],
          last_packet_number: packet['packet_number'],
          timestamp_deviation_us: packet['timestamp_deviation_us'],
          sequence_numbers: []
        }

        frame = frames[rtp_ts]
        frame[:packet_count] += 1
        frame[:total_size] += packet['raw_packet_size']
        frame[:last_wallclock] = packet['wallclock_time_us']
        frame[:last_packet_number] = packet['packet_number']
        frame[:sequence_numbers] << packet['sequence_number']
      end

      # Convert to array and sort by first packet number
      frames.values.sort_by { |f| f[:first_packet_number] }
    end

    def build_html
      frames = aggregate_frames
      frame_data_json = frames.to_json
      packet_data_json = @data.to_json
      stats = calculate_stats_from_frames(frames)
      frame_rows = build_frame_rows(frames)
      packet_rows = build_packet_rows

      <<~HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Stream Analysis Report</title>
          <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
          <style>
            * {
              margin: 0;
              padding: 0;
              box-sizing: border-box;
            }
            
            body {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
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
            
            .header p {
              font-size: 1.1em;
              opacity: 0.9;
            }
            
            .content {
              padding: 40px;
            }
            
            .stats-grid {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
              gap: 20px;
              margin-bottom: 40px;
            }
            
            .stat-card {
              background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
              padding: 20px;
              border-radius: 8px;
              border-left: 4px solid #667eea;
            }
            
            .stat-card h3 {
              color: #333;
              font-size: 0.9em;
              text-transform: uppercase;
              margin-bottom: 10px;
              opacity: 0.7;
            }
            
            .stat-card .value {
              font-size: 2em;
              font-weight: bold;
              color: #667eea;
            }
            
            .chart-container {
              position: relative;
              height: 400px;
              margin-bottom: 40px;
              background: #f9f9f9;
              padding: 20px;
              border-radius: 8px;
            }
            
            .chart-title {
              font-size: 1.3em;
              font-weight: bold;
              color: #333;
              margin-bottom: 20px;
            }
            
            .controls {
              margin-bottom: 20px;
              display: flex;
              gap: 10px;
              flex-wrap: wrap;
            }
            
            .control-btn {
              padding: 8px 16px;
              background: #667eea;
              color: white;
              border: none;
              border-radius: 4px;
              cursor: pointer;
              font-size: 0.9em;
              transition: background 0.3s;
            }
            
            .control-btn:hover {
              background: #764ba2;
            }
            
            .control-btn.active {
              background: #764ba2;
            }
            
            .table-container {
              overflow-x: auto;
              margin-top: 20px;
            }
            
            table {
              width: 100%;
              border-collapse: collapse;
              font-size: 0.9em;
            }
            
            th {
              background: #667eea;
              color: white;
              padding: 12px;
              text-align: left;
              font-weight: 600;
            }
            
            td {
              padding: 10px 12px;
              border-bottom: 1px solid #eee;
            }
            
            tr:hover {
              background: #f5f5f5;
            }
            
            .frame-type {
              display: inline-block;
              padding: 4px 8px;
              border-radius: 4px;
              font-size: 0.85em;
              font-weight: 600;
            }

            .frame-type.i-frame {
              background: #1b5e20;
              color: white;
            }

            .frame-type.p-frame {
              background: #81c784;
              color: white;
            }

            .frame-type.fragment {
              background: #95e1d3;
              color: #333;
            }

            .frame-type.sps {
              background: #ffd93d;
              color: #333;
            }

            .frame-type.pps {
              background: #ffd93d;
              color: #333;
            }

            .frame-type.audio {
              background: #a8e6cf;
              color: #333;
            }

            .frame-type.unknown {
              background: #d32f2f;
              color: white;
            }
            
            .footer {
              background: #f5f5f5;
              padding: 20px;
              text-align: center;
              color: #666;
              font-size: 0.9em;
              border-top: 1px solid #eee;
            }
            
            .legend {
              display: flex;
              gap: 20px;
              flex-wrap: wrap;
              margin-bottom: 20px;
              font-size: 0.9em;
            }
            
            .legend-item {
              display: flex;
              align-items: center;
              gap: 8px;
            }
            
            .legend-color {
              width: 20px;
              height: 20px;
              border-radius: 3px;
            }

            .download-link {
              display: inline-block;
              padding: 4px 8px;
              background: #667eea;
              color: white;
              text-decoration: none;
              border-radius: 4px;
              font-size: 0.9em;
              transition: background 0.3s;
            }

            .download-link:hover {
              background: #764ba2;
            }

            .packet-row {
              cursor: pointer;
              transition: background-color 0.2s;
            }

            .packet-row:hover {
              background-color: #f0f0f0 !important;
            }

            /* Modal Styles */
            .modal {
              display: none;
              position: fixed;
              z-index: 1000;
              left: 0;
              top: 0;
              width: 100%;
              height: 100%;
              background-color: rgba(0, 0, 0, 0.5);
              animation: fadeIn 0.3s;
              overflow: hidden;
            }

            .modal.active {
              display: flex;
              align-items: center;
              justify-content: center;
            }

            @keyframes fadeIn {
              from { opacity: 0; }
              to { opacity: 1; }
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
              animation: slideIn 0.3s;
              overflow: hidden;
            }

            @keyframes slideIn {
              from {
                transform: translateY(-50px);
                opacity: 0;
              }
              to {
                transform: translateY(0);
                opacity: 1;
              }
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

            .modal-header-actions {
              display: flex;
              gap: 10px;
              align-items: center;
            }

            .close-btn {
              background: none;
              border: none;
              font-size: 28px;
              font-weight: bold;
              color: #667eea;
              cursor: pointer;
              transition: color 0.3s;
              padding: 0;
              width: 32px;
              height: 32px;
              display: flex;
              align-items: center;
              justify-content: center;
            }

            .close-btn:hover {
              color: #764ba2;
            }

            .modal-body {
              display: flex;
              flex-direction: column;
              flex: 1;
              overflow: hidden;
              padding: 20px;
              gap: 15px;
            }

            .hex-dump {
              background: #1e1e1e;
              color: #00ff00;
              font-family: 'Courier New', monospace;
              font-size: 12px;
              padding: 15px;
              border-radius: 4px;
              overflow-y: auto;
              overflow-x: auto;
              line-height: 1.6;
              white-space: pre;
              border: 1px solid #333;
              flex: 1;
            }

            .hex-info {
              display: grid;
              grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
              gap: 15px;
              flex-shrink: 0;
            }

            .hex-info-item {
              background: #f5f5f5;
              padding: 10px;
              border-radius: 4px;
              border-left: 4px solid #667eea;
            }

            .hex-info-label {
              font-weight: bold;
              color: #667eea;
              font-size: 0.9em;
            }

            .hex-info-value {
              color: #333;
              font-size: 1.1em;
              margin-top: 5px;
            }

            body.modal-open {
              overflow: hidden;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>📊 Stream Analysis Report</h1>
              <p>Interactive packet flow analysis with timing and deviation metrics</p>
            </div>
            
            <div class="content">
              <!-- Statistics Cards -->
              <div class="stats-grid">
                <div class="stat-card">
                  <h3>Total Frames</h3>
                  <div class="value">#{frames.length}</div>
                </div>
                <div class="stat-card">
                  <h3>Duration</h3>
                  <div class="value">#{stats[:duration]}</div>
                </div>
                <div class="stat-card">
                  <h3>Frame Rate</h3>
                  <div class="value">#{stats[:frame_rate]}</div>
                </div>
                <div class="stat-card">
                  <h3>Avg Deviation</h3>
                  <div class="value">#{stats[:avg_deviation]}</div>
                </div>
              </div>
              
              <!-- Packet Size Chart -->
              <div class="chart-container">
                <div class="chart-title">📦 Packet Size Over Time</div>
                <canvas id="sizeChart"></canvas>
              </div>
              
              <!-- Timestamp Deviation Chart -->
              <div class="chart-container">
                <div class="chart-title">⏱️ Timestamp Deviation</div>
                <canvas id="deviationChart"></canvas>
              </div>
              
              <!-- Packet Type Distribution -->
              <div class="chart-container">
                <div class="chart-title">🎬 Frame Type Distribution</div>
                <canvas id="typeChart"></canvas>
              </div>
              
              <!-- Frame Summary Table -->
              <div>
                <div class="chart-title">📋 Frame Summary</div>
                <div class="controls">
                  <button class="control-btn active" onclick="filterTable('all')">All</button>
                  <button class="control-btn" onclick="filterTable('i-frame')">I-Frame</button>
                  <button class="control-btn" onclick="filterTable('p-frame')">P-Frame</button>
                  <button class="control-btn" onclick="filterTable('sps')">SPS</button>
                  <button class="control-btn" onclick="filterTable('pps')">PPS</button>
                </div>
                <div class="table-container">
                  <table id="packetTable">
                    <thead>
                      <tr>
                        <th>Packets</th>
                        <th>Frame Type</th>
                        <th>Total Size (bytes)</th>
                        <th>Packet Count</th>
                        <th>RTP Timestamp</th>
                        <th>Deviation (µs)</th>
                      </tr>
                    </thead>
                    <tbody>
                      #{frame_rows}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
            
            <div class="footer">
              <p>Generated on #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
          </div>
          
          <script>
            const frameData = #{frame_data_json};
            const packetData = #{packet_data_json};

            // Frame Size Chart
            const sizeCtx = document.getElementById('sizeChart').getContext('2d');
            new Chart(sizeCtx, {
              type: 'line',
              data: {
                labels: frameData.map((f, i) => 'Frame ' + (i + 1)),
                datasets: [{
                  label: 'Frame Size (bytes)',
                  data: frameData.map(f => f.total_size),
                  borderColor: '#667eea',
                  backgroundColor: 'rgba(102, 126, 234, 0.1)',
                  tension: 0.1,
                  fill: true,
                  pointRadius: 3,
                  pointHoverRadius: 5,
                  pointBackgroundColor: frameData.map(f => {
                    if (f.frame_type.includes('I-frame')) return '#ff6b6b';
                    if (f.frame_type.includes('P-frame')) return '#4ecdc4';
                    if (f.frame_type === 'SPS') return '#ffd93d';
                    if (f.frame_type === 'PPS') return '#ffd93d';
                    return '#667eea';
                  })
                }]
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: { display: true }
                },
                scales: {
                  y: { beginAtZero: true }
                }
              }
            });

            // Timestamp Deviation Chart (by frame)
            const deviationCtx = document.getElementById('deviationChart').getContext('2d');
            new Chart(deviationCtx, {
              type: 'bar',
              data: {
                labels: frameData.map((f, i) => 'Frame ' + (i + 1)),
                datasets: [{
                  label: 'Timestamp Deviation (µs)',
                  data: frameData.map(f => f.timestamp_deviation_us),
                  backgroundColor: frameData.map(f => f.timestamp_deviation_us < 0 ? '#ff6b6b' : '#51cf66'),
                  borderColor: '#333',
                  borderWidth: 0.5
                }]
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: { display: true }
                },
                scales: {
                  y: { beginAtZero: true }
                }
              }
            });

            // Frame Type Distribution
            const frameTypes = {};
            frameData.forEach(f => {
              frameTypes[f.frame_type] = (frameTypes[f.frame_type] || 0) + 1;
            });
            
            const typeCtx = document.getElementById('typeChart').getContext('2d');
            new Chart(typeCtx, {
              type: 'doughnut',
              data: {
                labels: Object.keys(frameTypes),
                datasets: [{
                  data: Object.values(frameTypes),
                  backgroundColor: [
                    '#ff6b6b',
                    '#4ecdc4',
                    '#95e1d3',
                    '#ffd93d',
                    '#a8e6cf',
                    '#667eea'
                  ]
                }]
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: { position: 'bottom' }
                }
              }
            });
            
            // Table filtering
            function filterTable(type) {
              const rows = document.querySelectorAll('.packet-row');
              rows.forEach(row => {
                if (type === 'all' || row.dataset.type === type) {
                  row.style.display = '';
                } else {
                  row.style.display = 'none';
                }
              });
              
              // Update button states
              document.querySelectorAll('.control-btn').forEach(btn => {
                btn.classList.remove('active');
              });
              event.target.classList.add('active');
            }
          </script>

          <!-- Hex Dump Modal -->
          <div id="hexModal" class="modal">
            <div class="modal-content">
              <div class="modal-header">
                <h2 id="modalTitle">Frame Hex Dump</h2>
                <div class="modal-header-actions">
                  <button class="close-btn" onclick="closeHexModal()" title="Close (ESC)">&times;</button>
                </div>
              </div>
              <div class="modal-body">
                <div class="hex-info">
                  <div class="hex-info-item">
                    <div class="hex-info-label">Frame Number</div>
                    <div class="hex-info-value" id="hexFrameNum">-</div>
                  </div>
                  <div class="hex-info-item">
                    <div class="hex-info-label">Frame Type</div>
                    <div class="hex-info-value" id="hexFrameType">-</div>
                  </div>
                  <div class="hex-info-item">
                    <div class="hex-info-label">Frame Size</div>
                    <div class="hex-info-value" id="hexFrameSize">-</div>
                  </div>
                  <div class="hex-info-item">
                    <div class="hex-info-label">Download</div>
                    <div class="hex-info-value" id="hexDownload">-</div>
                  </div>
                </div>
                <div class="hex-dump" id="hexDumpContent"></div>
              </div>
            </div>
          </div>

          <script>
            function showHexModal(frameNum, frameType, frameSize, downloadUrl) {
              const modal = document.getElementById('hexModal');
              const hexContent = document.getElementById('hexDumpContent');
              const modalTitle = document.getElementById('modalTitle');

              document.getElementById('hexFrameNum').textContent = frameNum;
              document.getElementById('hexFrameType').textContent = frameType;
              document.getElementById('hexFrameSize').textContent = frameSize + ' bytes';
              modalTitle.textContent = 'Frame ' + frameNum + ' - ' + frameType;

              // Set download link
              const downloadDiv = document.getElementById('hexDownload');
              if (downloadUrl) {
                downloadDiv.innerHTML = '<a href="' + downloadUrl + '" download class="download-link">📥 Download</a>';
              } else {
                downloadDiv.textContent = 'Not available';
              }

              if (window.frameHexData && window.frameHexData[frameNum]) {
                hexContent.textContent = window.frameHexData[frameNum];
              } else {
                hexContent.textContent = 'Hex data not available';
              }

              modal.classList.add('active');
              document.body.classList.add('modal-open');
            }

            function closeHexModal() {
              const modal = document.getElementById('hexModal');
              modal.classList.remove('active');
              document.body.classList.remove('modal-open');
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
          </script>
        </body>
        </html>
      HTML
    end

    def calculate_stats_from_frames(frames)
      first = @data.first
      last = @data.last
      duration_us = last['wallclock_time_us'] - first['wallclock_time_us']
      duration_s = duration_us / 1_000_000.0
      frame_rate = frames.length / duration_s

      deviations = frames.map { |f| f[:timestamp_deviation_us] }.compact
      avg_dev = deviations.sum.to_f / deviations.length

      {
        duration: "#{duration_s.round(2)}s",
        frame_rate: "#{frame_rate.round(2)} fps",
        avg_deviation: "#{avg_dev.round(2)} µs"
      }
    end

    def build_frame_rows(frames)
      frames.map.with_index do |frame, idx|
        frame_class = get_frame_class(frame[:frame_type])
        filter_type = get_filter_type(frame[:frame_type])
        frame_number = idx + 1
        frame_filename = "frame#{frame_number.to_s.rjust(5, '0')}.bin"

        has_file = @frames_dir && File.exist?(File.join(@frames_dir, frame_filename))

        hex_dump = if has_file
          frame_data = File.binread(File.join(@frames_dir, frame_filename))
          generate_hex_dump(frame_data, frame_number)
        else
          ""
        end

        <<~ROW
          <tr class="packet-row" data-type="#{filter_type}" onclick="showHexModal(#{frame_number}, '#{frame[:frame_type]}', #{frame[:total_size]}, #{has_file ? "'frames/#{frame_filename}'" : 'null'})">
            <td>#{frame[:first_packet_number]}-#{frame[:last_packet_number]}</td>
            <td><span class="frame-type #{frame_class}">#{frame[:frame_type]}</span></td>
            <td>#{frame[:total_size]}</td>
            <td>#{frame[:packet_count]}</td>
            <td>#{frame[:rtp_timestamp_raw]}</td>
            <td>#{frame[:timestamp_deviation_us]}</td>
          </tr>
          <script>
            window.frameHexData = window.frameHexData || {};
            window.frameHexData[#{frame_number}] = `#{hex_dump}`;
          </script>
        ROW
      end.join
    end

    def generate_hex_dump(data, frame_number, bytes_per_line = 16)
      lines = []
      data.each_byte.each_slice(bytes_per_line).with_index do |bytes, line_idx|
        offset = line_idx * bytes_per_line
        hex_part = bytes.map { |b| format('%02X', b) }.join(' ')
        ascii_part = bytes.map { |b| (32..126).include?(b) ? b.chr : '.' }.join
        lines << format('%08X  %-48s  %s', offset, hex_part, ascii_part)
      end
      lines.join("\n")
    end

    def build_packet_rows
      @data.map do |packet|
        frame_class = get_frame_class(packet['frame_type'])
        filter_type = get_filter_type(packet['frame_type'])

        <<~ROW
          <tr class="packet-row" data-type="#{filter_type}">
            <td>#{packet['packet_number']}</td>
            <td><span class="frame-type #{frame_class}">#{packet['frame_type']}</span></td>
            <td>#{packet['raw_packet_size']}</td>
            <td>#{packet['wallclock_time_us']}</td>
            <td>#{packet['rtp_timestamp_raw']}</td>
            <td>#{packet['timestamp_deviation_us']}</td>
            <td>#{packet['sequence_number']}</td>
          </tr>
        ROW
      end.join
    end

    def get_frame_class(frame_type)
      case frame_type
      when /^I-frame/
        'i-frame'
      when /^P-frame/
        'p-frame'
      when /^Fragment/
        'fragment'
      when 'SPS'
        'sps'
      when 'PPS'
        'pps'
      when 'Audio'
        'audio'
      when /^Unknown/
        'unknown'
      else
        'fragment'
      end
    end

    def get_filter_type(frame_type)
      case frame_type
      when /^I-frame/
        'i-frame'
      when /^P-frame/
        'p-frame'
      when /^Fragment/
        'fragment'
      when 'SPS'
        'sps'
      when 'PPS'
        'pps'
      when 'Audio'
        'audio'
      else
        'fragment'
      end
    end
  end
end

