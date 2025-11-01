module Streamripper
  class StreamSaver
    attr_reader :output_file, :bytes_written

    def initialize(output_file)
      @output_file = output_file
      @file_handle = nil
      @bytes_written = 0
      @packet_count = 0
      
      setup_output_file
    end

    def save_packet(packet)
      # Save the complete RTSP-over-TCP framing + RTP packet
      # This is the TRUE RAW data - nothing stripped

      # RTSP framing: $ (1 byte) + channel (1 byte) + length (2 bytes)
      rtsp_marker = '$'
      rtsp_channel = packet[:rtsp_channel] || 0

      # Build the complete RTP packet
      rtp_data = packet[:raw_header]

      # Add CSRC data if present
      if packet[:csrc_data]
        rtp_data += packet[:csrc_data]
      end

      # Add extension data if present
      if packet[:extension_data]
        rtp_data += packet[:extension_data]
      end

      # Add payload
      if packet[:payload]
        rtp_data += packet[:payload]
      end

      # Write RTSP framing
      raw_data = rtsp_marker
      raw_data += rtsp_channel.chr
      raw_data += [rtp_data.length].pack('n')  # Big-endian 16-bit unsigned short
      raw_data += rtp_data

      @file_handle.write(raw_data)
      @bytes_written += raw_data.length
      @packet_count += 1
    end

    def close
      @file_handle.close if @file_handle
    end

    def get_statistics
      {
        total_packets_saved: @packet_count,
        total_bytes_written: @bytes_written,
        output_file: @output_file
      }
    end

    private

    def setup_output_file
      # Create directory if it doesn't exist
      dir = File.dirname(@output_file)
      FileUtils.mkdir_p(dir) unless Dir.exist?(dir)
      
      @file_handle = File.open(@output_file, 'wb')
    end
  end
end

