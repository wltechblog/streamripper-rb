require 'spec_helper'
require 'tempfile'
require 'json'

describe Streamripper::PacketLogger do
  let(:temp_file) { Tempfile.new('test_log').path }

  after do
    File.delete(temp_file) if File.exist?(temp_file)
  end

  let(:sample_analysis) do
    {
      packet_number: 1,
      wallclock_time_ms: 1234567890123,
      packet_type: 'H264',
      payload_type_code: 96,
      raw_packet_size: 1500,
      stream_timestamp: 1000,
      sequence_number: 1,
      marker_bit: 0,
      ssrc: 12345,
      timestamp_deviation_ms: 0
    }
  end

  describe 'JSON format' do
    it 'logs packets in JSON format' do
      logger = Streamripper::PacketLogger.new(temp_file, :json)
      logger.log_packet(sample_analysis)
      logger.close

      content = File.read(temp_file)
      expect(content).to include('"packet_number":1')
      expect(content).to include('"packet_type":"H264"')
    end

    it 'creates valid JSON array' do
      logger = Streamripper::PacketLogger.new(temp_file, :json)
      logger.log_packet(sample_analysis)
      logger.log_packet(sample_analysis.merge(packet_number: 2))
      logger.close

      content = File.read(temp_file)
      # Should have opening bracket
      expect(content).to start_with('[')
    end
  end

  describe 'CSV format' do
    it 'logs packets in CSV format' do
      logger = Streamripper::PacketLogger.new(temp_file, :csv)
      logger.log_packet(sample_analysis)
      logger.close

      content = File.read(temp_file)
      lines = content.strip.split("\n")
      
      # Should have header and data row
      expect(lines.length).to be >= 2
      expect(lines[0]).to include('packet_number')
    end

    it 'includes all required CSV columns' do
      logger = Streamripper::PacketLogger.new(temp_file, :csv)
      logger.log_packet(sample_analysis)
      logger.close

      content = File.read(temp_file)
      header = content.split("\n").first
      
      expected_columns = [
        'packet_number',
        'wallclock_time_ms',
        'packet_type',
        'payload_type_code',
        'raw_packet_size',
        'stream_timestamp',
        'sequence_number',
        'marker_bit',
        'ssrc',
        'timestamp_deviation_ms'
      ]
      
      expected_columns.each do |col|
        expect(header).to include(col)
      end
    end
  end

  describe 'statistics' do
    it 'tracks logged packet count' do
      logger = Streamripper::PacketLogger.new(temp_file, :json)
      3.times { |i| logger.log_packet(sample_analysis.merge(packet_number: i + 1)) }
      
      stats = logger.get_statistics
      expect(stats[:total_packets_logged]).to eq(3)
    end

    it 'returns log file path in statistics' do
      logger = Streamripper::PacketLogger.new(temp_file, :json)
      stats = logger.get_statistics
      
      expect(stats[:log_file]).to eq(temp_file)
      expect(stats[:format]).to eq(:json)
    end
  end
end

