module Streamripper
  class OutputManager
    def initialize(rtsp_url)
      @rtsp_url = rtsp_url
      @stream_dir = parse_stream_directory(rtsp_url)
      @run_timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
      @run_dir = File.join(@stream_dir, @run_timestamp)
      create_directories
    end

    attr_reader :stream_dir, :run_dir, :run_timestamp

    def parse_stream_directory(url)
      # Parse rtsp://user:pass@host:port/endpoint
      # Extract: host and endpoint
      # Format: host_ip_endpoint (e.g., 192_168_88_31_ch0)
      
      uri = URI.parse(url)
      host = uri.host
      path = uri.path.gsub(/^\//, '').gsub(/\//, '_')
      
      # Convert dots to underscores in IP
      host_formatted = host.gsub('.', '_')
      
      # Combine host and path
      stream_name = "#{host_formatted}_#{path}"
      
      File.join('logs', 'streams', stream_name)
    end

    def create_directories
      FileUtils.mkdir_p(@run_dir)
    end

    def get_output_path(filename)
      File.join(@run_dir, filename)
    end

    def get_stream_info
      {
        stream_dir: @stream_dir,
        run_dir: @run_dir,
        run_timestamp: @run_timestamp,
        rtsp_url: @rtsp_url
      }
    end
  end
end

