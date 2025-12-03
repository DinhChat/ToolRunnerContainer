# frozen_string_literal: true

require 'open3'
require 'rest-client'
require 'shellwords'

class ScanRunnerService
  class InvalidParamsError < StandardError; end

  SCANNERS = {
    "NUCLEI" => Scanners::NucleiService,
    "ZAP"    => Scanners::ZapService,
    "NIKTO"  => Scanners::NiktoService
  }.freeze

  def initialize(params)
    @scan_id       = params[:scan_id]
    @target_url    = params[:target_url]
    @scan_tools    = Array(params[:scan_tools]).map(&:upcase)
    @callback_url  = params[:callback_url]
    @scan_parameters = params[:scan_parameters] || {}

    validate_params!
  end

  def run_all_scans
    results = {}

    @scan_tools.each do |tool_name|
      tool_key = tool_name.downcase
      begin
        scanner_class = SCANNERS[tool_name]
        unless scanner_class
          results[tool_key] = { status: "FAILED", error: "Scanner '#{tool_name}' not supported" }
          next
        end

        Rails.logger.info "Starting #{tool_name} scan for Scan ID #{@scan_id}"

        scanner = scanner_class.new(
          target_url: @target_url,
          scan_id: @scan_id,
          parameters: @scan_parameters[tool_key] || {}
        )

        result = scanner.run

        if result[:success]
          results[tool_key] = {
            status: "COMPLETED",
            summary: result.dig(:data, :summary),
            target_updates: result.dig(:data, :target_updates),
            vulnerabilities: result.dig(:data, :vulnerabilities) || []
          }
        else
          results[tool_key] = {
            status: "FAILED",
            error: result[:error] || "Unknown error"
          }
        end

      rescue StandardError => e
        Rails.logger.error "Scanner #{tool_name} crashed: #{e.message}"
        results[tool_key] = { status: "FAILED", error: "Internal Scanner Error: #{e.message}" }
      end
    end

    final_status = determine_final_status(results)
    send_callback(final_status, results)
    results
  end

  private

  def determine_final_status(results)
    statuses = results.values.map { |r| r[:status] }

    if statuses.all?("COMPLETED")
      "COMPLETED"
    elsif statuses.all?("FAILED")
      "FAILED"
    else
      "PARTIAL"
    end
  end

  def validate_params!
    raise InvalidParamsError, "scan_id is required" if @scan_id.blank?
    raise InvalidParamsError, "target_url is required" if @target_url.blank?
    unless @target_url =~ /\Ahttps?:\/\/[\S]+\z/
      raise InvalidParamsError, "Target URL format is invalid (must start with http:// or https://)"
    end
    raise InvalidParamsError, "scan_tools must be an array" unless @scan_tools.is_a?(Array)
    raise InvalidParamsError, "scan_tools cannot be empty" if @scan_tools.empty?
    raise InvalidParamsError, "callback_url is required" if @callback_url.blank?

    invalid_tools = @scan_tools - SCANNERS.keys
    unless invalid_tools.empty?
      raise InvalidParamsError, "Unsupported scan tools: #{invalid_tools.join(', ')}"
    end
  end

  def send_callback(final_status, tool_results)
    payload = {
      scanId: @scan_id,
      status: final_status,
      completedAt: Time.now.iso8601,
      results: tool_results
    }

    begin
      response = RestClient.post(
        @callback_url,
        payload.to_json,
        content_type: :json,
        accept: :json,
        timeout: 30
      )
      Rails.logger.info "Callback sent successfully for Scan ID #{@scan_id} → #{final_status}"
    rescue RestClient::ExceptionWithResponse => e
      Rails.logger.error "Callback failed (response): #{e.message} | Body: #{e.response&.body}"
    rescue => e
      Rails.logger.error "Callback failed (exception): #{e.class} - #{e.message}"
    end
  end
end
