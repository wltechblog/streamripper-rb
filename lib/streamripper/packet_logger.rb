require 'json'
require 'csv'
require 'fileutils'

module Streamripper
  class PacketLogger
    attr_reader :log_file, :format

    def initialize(log_file, format = :json)
      @log_file = log_file
      @format = format
      @file_handle = nil
      @csv_writer = nil
      @packet_count = 0

      # Create directory if it doesn't exist
      dir = File.dirname(@log_file)
      FileUtils.mkdir_p(dir) unless Dir.exist?(dir)

      setup_log_file
    end

    def log_packet(analysis)
      case @format
      when :json
        log_json(analysis)
      when :csv
        log_csv(analysis)
      when :both
        log_json(analysis)
        log_csv(analysis)
      end
      
      @packet_count += 1
    end

    def close
      case @format
      when :json
        finalize_json
        @file_handle.close if @file_handle
      when :csv
        @file_handle.close if @file_handle
      when :both
        finalize_json_file(@json_file)
        @json_file.close if @json_file
        @csv_file.close if @csv_file
      end
    end

    def get_statistics
      {
        total_packets_logged: @packet_count,
        log_file: @log_file,
        format: @format
      }
    end

    private

    def setup_log_file
      case @format
      when :json
        @file_handle = File.open(@log_file, 'w')
        @file_handle.write("[\n")
      when :csv
        @file_handle = File.open(@log_file, 'w')
        write_csv_header
      when :both
        # For both format, we'll create separate files
        json_file = @log_file.end_with?('.json') || @log_file.end_with?('.csv') ? @log_file.sub(/\.\w+$/, '.json') : "#{@log_file}.json"
        csv_file = @log_file.end_with?('.json') || @log_file.end_with?('.csv') ? @log_file.sub(/\.\w+$/, '.csv') : "#{@log_file}.csv"

        @json_file = File.open(json_file, 'w')
        @json_file.write("[\n")

        @csv_file = File.open(csv_file, 'w')
        write_csv_header(@csv_file)
      end
    end

    def log_json(analysis)
      file = @format == :both ? @json_file : @file_handle
      if @packet_count > 0
        file.write(",\n")
      end
      file.write(JSON.generate(analysis))
      file.flush
    end

    def log_csv(analysis)
      if @format == :both
        @csv_file.puts(format_csv_row(analysis))
        @csv_file.flush
      else
        @file_handle.puts(format_csv_row(analysis))
        @file_handle.flush
      end
    end

    def write_csv_header(file = nil)
      file ||= @file_handle
      headers = [
        'packet_number',
        'wallclock_time_us',
        'packet_type',
        'frame_type',
        'payload_type_code',
        'raw_packet_size',
        'rtp_timestamp_raw',
        'rtp_timestamp_us',
        'sequence_number',
        'marker_bit',
        'ssrc',
        'timestamp_deviation_us'
      ]
      file.puts(headers.to_csv)
    end

    def format_csv_row(analysis)
      [
        analysis[:packet_number],
        analysis[:wallclock_time_us],
        analysis[:packet_type],
        analysis[:frame_type],
        analysis[:payload_type_code],
        analysis[:raw_packet_size],
        analysis[:rtp_timestamp_raw],
        analysis[:rtp_timestamp_us],
        analysis[:sequence_number],
        analysis[:marker_bit],
        analysis[:ssrc],
        analysis[:timestamp_deviation_us]
      ].to_csv
    end

    def finalize_json
      @file_handle.write("\n]")
      @file_handle.flush
    end

    def finalize_json_file(file)
      file.write("\n]")
      file.flush
    end
  end
end

