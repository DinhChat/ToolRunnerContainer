# frozen_string_literal: true

require 'open3'
require 'rest-client'

class ScanRunnerService
  attr_reader :scan_id, :target_url, :scan_tool_name, :scan_parameters, :callback_url

  # Cấu hình các Docker images
  SCAN_TOOLS = {
    'ZAP' => {
      image: 'owasp/zap2docker-stable',
      command_template: lambda { |target, output_file|
        "zap.sh -cmd -port 8080 -host 0.0.0.0 -daemon -config api.disablekey=true " +
          "-target #{target} -json #{output_file} -T 30 -quickurl #{target}"
      },
      output_parser: ->(output_path) { ReportParserService.parse_zap_json(output_path) }
    },
    'NIKTO' => {
      image: 'alpine/nikto',
      command_template: lambda { |target, output_file|
        "nikto.pl -h #{target} -o #{output_file} -Format json"
      },
      output_parser: ->(output_path) { ReportParserService.parse_nikto_json(output_path) }
    }
  }.freeze

  def initialize(scan_id, target_url, scan_tool_name, scan_parameters, callback_url)
    @scan_id = scan_id
    @target_url = target_url
    @scan_tool_name = scan_tool_name.upcase
    @scan_parameters = JSON.parse(scan_parameters) rescue {}
    @callback_url = callback_url
    @docker_socket_path = '/var/run/docker.sock'
    @output_dir = "/tmp/scan_results/#{scan_id}"
  end

  def run
    tool_config = SCAN_TOOLS[@scan_tool_name]
    unless tool_config
      Rails.logger.error "Scan tool '#{@scan_tool_name}' not configured."
      send_callback('FAILED', "Scan tool '#{@scan_tool_name}' not configured.", [])
      return
    end
    # Tạo thư mục cục bộ để mount và lưu báo cáo
    FileUtils.mkdir_p(@output_dir) unless File.directory?(@output_dir)
    report_file_name = "#{@scan_tool_name.downcase}_report.json"
    full_output_path_on_host = File.join(@output_dir, report_file_name)
    output_path_in_container = "/app/#{report_file_name}" # Đường dẫn bên trong container quét

    docker_run_command = build_docker_command(tool_config, output_path_in_container)

    Rails.logger.info "Executing Docker command for Scan ID #{@scan_id}: #{docker_run_command}"

    stdout_str, stderr_str, status = Open3.capture3(docker_run_command)

    if status.success?
      Rails.logger.info "Docker command for Scan ID #{@scan_id} completed successfully."
      # Đọc và phân tích báo cáo từ file đã mount
      if File.exist?(full_output_path_on_host)
        raw_results = tool_config[:output_parser].call(full_output_path_on_host)
        send_callback('COMPLETED', nil, raw_results)
      else
        error_msg = "Report file not found at #{full_output_path_on_host}"
        Rails.logger.error error_msg
        send_callback('FAILED', error_msg, [])
      end
    else
      error_msg = "Docker command for Scan ID #{@scan_id} failed. Error: #{stderr_str}"
      Rails.logger.error error_msg
      send_callback('FAILED', error_msg, [])
    end
  ensure
    # Dọn dẹp thư mục kết quả tạm thời
    FileUtils.remove_dir(@output_dir) if File.directory?(@output_dir)
  end

  private

  # Xây dựng lệnh run docker
  def build_docker_command(tool_config, output_path_in_container)
    image = tool_config[:image]
    docker_prefix = "docker run --rm " +
                    "-v #{@docker_socket_path}:#{@docker_socket_path} " +
                    "-v #{@output_dir}:/app " +
                    "--network host " +
                    "#{image}"

    # Build lệnh cụ thể của công cụ quét
    scan_command = tool_config[:command_template].call(@target_url, output_path_in_container)

    "#{docker_prefix} #{scan_command}"
  end

  # Gửi callback về Web Service
  def send_callback(status, error_message, raw_results)
    payload = {
      scanId: @scan_id,
      status: status,
      rawResults: raw_results,
      errorMessage: error_message
    }.to_json

    begin
      RestClient.post(@callback_url, payload, content_type: :json, accept: :json)
      Rails.logger.info "Sent callback for Scan ID #{@scan_id} with status #{status} to #{@callback_url}"
    rescue RestClient::ExceptionWithResponse => e
      Rails.logger.error "Failed to send callback for Scan ID #{@scan_id}: #{e.message} - Response: #{e.response}"
    rescue RestClient::Exception => e
      Rails.logger.error "Failed to send callback for Scan ID #{@scan_id}: #{e.message}"
    end
  end
end
