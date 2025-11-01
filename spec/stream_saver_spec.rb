require 'spec_helper'
require 'tempfile'

describe Streamripper::StreamSaver do
  let(:temp_file) { Tempfile.new('test_stream').path }

  after do
    File.delete(temp_file) if File.exist?(temp_file)
  end

  let(:sample_packet) do
    {
      raw_header: "\x80\x60\x00\x01" + "\x00" * 8,
      csrc_data: nil,
      extension_data: nil,
      payload: 'x' * 1488
    }
  end

  describe '#save_packet' do
    it 'saves packet data to file' do
      saver = Streamripper::StreamSaver.new(temp_file)
      saver.save_packet(sample_packet)
      saver.close

      expect(File.exist?(temp_file)).to be true
      expect(File.size(temp_file)).to be > 0
    end

    it 'tracks bytes written' do
      saver = Streamripper::StreamSaver.new(temp_file)
      saver.save_packet(sample_packet)
      
      expect(saver.bytes_written).to be > 0
    end

    it 'saves multiple packets' do
      saver = Streamripper::StreamSaver.new(temp_file)
      3.times { saver.save_packet(sample_packet) }
      saver.close

      file_size = File.size(temp_file)
      expected_size = sample_packet[:raw_header].length + sample_packet[:payload].length
      
      expect(file_size).to eq(expected_size * 3)
    end

    it 'includes CSRC data if present' do
      packet = sample_packet.merge(csrc_data: 'csrc' * 4)
      saver = Streamripper::StreamSaver.new(temp_file)
      saver.save_packet(packet)
      saver.close

      file_size = File.size(temp_file)
      expected_size = sample_packet[:raw_header].length + 16 + sample_packet[:payload].length
      
      expect(file_size).to eq(expected_size)
    end

    it 'includes extension data if present' do
      packet = sample_packet.merge(extension_data: 'ext' * 4)
      saver = Streamripper::StreamSaver.new(temp_file)
      saver.save_packet(packet)
      saver.close

      file_size = File.size(temp_file)
      expected_size = sample_packet[:raw_header].length + 12 + sample_packet[:payload].length
      
      expect(file_size).to eq(expected_size)
    end
  end

  describe '#get_statistics' do
    it 'returns statistics' do
      saver = Streamripper::StreamSaver.new(temp_file)
      saver.save_packet(sample_packet)
      
      stats = saver.get_statistics
      expect(stats).to include(:total_packets_saved, :total_bytes_written, :output_file)
      expect(stats[:total_packets_saved]).to eq(1)
    end
  end

  describe 'directory creation' do
    it 'creates output directory if it does not exist' do
      nested_path = File.join(temp_file, '..', 'nested', 'dir', 'stream.bin')
      saver = Streamripper::StreamSaver.new(nested_path)
      saver.save_packet(sample_packet)
      saver.close

      expect(File.exist?(nested_path)).to be true
      File.delete(nested_path)
    end
  end
end

