require 'logger'
require_relative 'streamripper/version'
require_relative 'streamripper/rtsp_fetcher'
require_relative 'streamripper/packet_analyzer'
require_relative 'streamripper/packet_logger'
require_relative 'streamripper/stream_saver'
require_relative 'streamripper/cli'

module Streamripper
  class Error < StandardError; end
end

