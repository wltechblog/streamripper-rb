module Streamripper
  class PacketExtractor
    def initialize(output_dir)
      @output_dir = output_dir
      @packets_dir = File.join(output_dir, 'packets')
      @frames_dir = File.join(output_dir, 'frames')
      FileUtils.mkdir_p(@packets_dir)
      FileUtils.mkdir_p(@frames_dir)
    end

    attr_reader :frames_dir

    def save_packet(packet_number, payload)
      filename = format_packet_filename(packet_number)
      filepath = File.join(@packets_dir, filename)
      File.binwrite(filepath, payload)
      filepath
    end

    def save_frame(frame_number, packets_data)
      # Concatenate all packet payloads for this frame
      frame_payload = packets_data.map { |p| p[:payload] }.join

      filename = format_frame_filename(frame_number)
      filepath = File.join(@frames_dir, filename)
      File.binwrite(filepath, frame_payload)

      {
        filename: filename,
        filepath: filepath,
        size: frame_payload.length,
        packet_count: packets_data.length
      }
    end

    def save_unknown_packets(analysis_data)
      # Find packets with unknown payload types
      unknown_packets = analysis_data.select do |packet|
        packet['packet_type'] == 'Unknown' ||
        packet['frame_type'] == 'Unknown'
      end

      unknown_packets.each do |packet|
        # We need to re-read the raw stream to get the payload
        # For now, just log which packets are unknown
        yield(packet) if block_given?
      end

      unknown_packets
    end

    private

    def format_packet_filename(packet_number)
      "packet#{packet_number.to_s.rjust(5, '0')}.bin"
    end

    def format_frame_filename(frame_number)
      "frame#{frame_number.to_s.rjust(5, '0')}.bin"
    end
  end
end

