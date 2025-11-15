# frozen_string_literal: true

class ScanJob < ApplicationJob
  queue_as :default

  def perform(scan_id, target_url, scan_tool_name, scan_parameters, callback_url)
    Rails.logger.info "Starting scan execution for Scan ID: #{scan_id} with tool #{scan_tool_name} on #{target_url}"

    ScanRunnerService.new(scan_id, target_url, scan_tool_name, scan_parameters, callback_url).run
  rescue StandardError => e
    Rails.logger.error "ScanJob for Scan ID #{scan_id} failed: #{e.message}\n#{e.backtrace.join("\n")}"
    send_failure_callback(scan_id, callback_url, e.message)
  end

  private

  def send_failure_callback(scan_id, callback_url, error_message)
    payload = {
      scanId: scan_id,
      status: 'FAILED',
      errorMessage: error_message
    }.to_json

    begin
      RestClient.post(callback_url, payload, content_type: :json, accept: :json)
      Rails.logger.info "Sent failure callback for Scan ID #{scan_id} to #{callback_url}"
    rescue RestClient::ExceptionWithResponse => e
      Rails.logger.error "Failed to send failure callback for Scan ID #{scan_id}: #{e.message} - Response: #{e.response}"
    rescue RestClient::Exception => e
      Rails.logger.error "Failed to send failure callback for Scan ID #{scan_id}: #{e.message}"
    end
  end
end
