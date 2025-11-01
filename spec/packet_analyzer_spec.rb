require 'spec_helper'

describe Streamripper::PacketAnalyzer do
  let(:analyzer) { Streamripper::PacketAnalyzer.new }

  describe '#analyze' do
    let(:packet) do
      {
        wallclock_time: 1234567890.123,
        packet_type: 96,
        payload_type: 96,
        raw_packet_size: 1500,
        timestamp: 1000,
        sequence_number: 1,
        marker: 0,
        ssrc: 12345,
        cc: 0,
        extension_data: nil,
        payload: 'x' * 1488
      }
    end

    it 'increments packet count' do
      expect { analyzer.analyze(packet) }.to change { analyzer.packet_count }.by(1)
    end

    it 'returns analysis hash with required fields' do
      analysis = analyzer.analyze(packet)

      expect(analysis).to include(
        :packet_number,
        :wallclock_time_ms,
        :packet_type,
        :frame_type,
        :payload_type_code,
        :raw_packet_size,
        :stream_timestamp,
        :sequence_number,
        :marker_bit,
        :ssrc,
        :timestamp_deviation_ms
      )
    end

    it 'correctly identifies payload type' do
      analysis = analyzer.analyze(packet)
      expect(analysis[:packet_type]).to eq('H264')
    end

    it 'calculates packet size correctly' do
      analysis = analyzer.analyze(packet)
      expect(analysis[:raw_packet_size]).to be > 0
    end

    it 'tracks timestamp deviations' do
      packet1 = packet.merge(timestamp: 1000)
      packet2 = packet.merge(timestamp: 1090)
      packet3 = packet.merge(timestamp: 2180)

      analyzer.analyze(packet1)
      analyzer.analyze(packet2)
      analysis3 = analyzer.analyze(packet3)

      expect(analysis3[:timestamp_deviation_ms]).to eq(0)
    end

    it 'handles multiple packets' do
      3.times { |i| analyzer.analyze(packet.merge(timestamp: 1000 + (i * 100))) }
      expect(analyzer.packet_count).to eq(3)
    end
  end

  describe 'payload type mapping' do
    it 'maps common payload types' do
      test_cases = [
        [26, 'JPEG'],
        [31, 'H261'],
        [96, 'H264'],
        [97, 'H265'],
        [99, 'Unknown(99)']
      ]

      test_cases.each do |pt, expected_name|
        packet = {
          wallclock_time: 1234567890.123,
          packet_type: pt,
          payload_type: pt,
          raw_packet_size: 1500,
          timestamp: 1000,
          sequence_number: 1,
          marker: 0,
          ssrc: 12345,
          cc: 0,
          extension_data: nil,
          payload: 'x' * 1488
        }

        analysis = analyzer.analyze(packet)
        expect(analysis[:packet_type]).to eq(expected_name)
      end
    end
  end

  describe 'H.264 frame type detection' do
    it 'detects I-frame (NAL type 5)' do
      # NAL unit type 5 = IDR picture (I-frame)
      payload = "\x65" + "x" * 100  # 0x65 = 01100101, NAL type = 5
      packet = {
        wallclock_time: 1234567890.123,
        packet_type: 96,
        payload_type: 96,
        raw_packet_size: 101,
        timestamp: 1000,
        sequence_number: 1,
        marker: 1,
        ssrc: 12345,
        cc: 0,
        extension_data: nil,
        payload: payload
      }

      analysis = analyzer.analyze(packet)
      expect(analysis[:frame_type]).to eq('I-frame')
    end

    it 'detects P-frame (NAL type 1)' do
      # NAL unit type 1 = non-IDR picture (P-frame)
      payload = "\x61" + "x" * 100  # 0x61 = 01100001, NAL type = 1
      packet = {
        wallclock_time: 1234567890.123,
        packet_type: 96,
        payload_type: 96,
        raw_packet_size: 101,
        timestamp: 1000,
        sequence_number: 1,
        marker: 0,
        ssrc: 12345,
        cc: 0,
        extension_data: nil,
        payload: payload
      }

      analysis = analyzer.analyze(packet)
      expect(analysis[:frame_type]).to eq('P-frame')
    end

    it 'detects SPS (NAL type 7)' do
      # NAL unit type 7 = SPS
      payload = "\x67" + "x" * 50  # 0x67 = 01100111, NAL type = 7
      packet = {
        wallclock_time: 1234567890.123,
        packet_type: 96,
        payload_type: 96,
        raw_packet_size: 51,
        timestamp: 1000,
        sequence_number: 1,
        marker: 0,
        ssrc: 12345,
        cc: 0,
        extension_data: nil,
        payload: payload
      }

      analysis = analyzer.analyze(packet)
      expect(analysis[:frame_type]).to eq('SPS')
    end

    it 'detects PPS (NAL type 8)' do
      # NAL unit type 8 = PPS
      payload = "\x68" + "x" * 20  # 0x68 = 01101000, NAL type = 8
      packet = {
        wallclock_time: 1234567890.123,
        packet_type: 96,
        payload_type: 96,
        raw_packet_size: 21,
        timestamp: 1000,
        sequence_number: 1,
        marker: 0,
        ssrc: 12345,
        cc: 0,
        extension_data: nil,
        payload: payload
      }

      analysis = analyzer.analyze(packet)
      expect(analysis[:frame_type]).to eq('PPS')
    end
  end
end

