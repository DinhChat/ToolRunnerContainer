# frozen_string_literal: true

class ScanJob < ApplicationJob
  queue_as :scans
  discard_on StandardError do |job, error|
    Rails.logger.error "ScanJob CRITICAL FAILURE: #{error.message}"
  end

  def perform(args)
    args = args.symbolize_keys
    scan_id = args[:scan_id]
    callback_url = args[:callback_url]

    Rails.logger.info "ScanJob started | ID: #{scan_id}"
    service = ScanRunnerService.new(args)

    service.run_all_scans

  rescue ScanRunnerService::InvalidParamsError => e
    send_failure_callback(scan_id, callback_url, "Invalid parameters: #{e.message}")

  rescue StandardError => e
    Rails.logger.error "ScanJob failed | Scan ID: #{scan_id} | Error: #{e.class} - #{e.message}\n#{e.backtrace.join("\n")}"
    send_failure_callback(scan_id, callback_url, "Scan failed: #{e.message}")
  end

  private

  def send_failure_callback(scan_id, callback_url, error_message)
    return if callback_url.blank?

    payload = {
      scanId: scan_id,
      status: "FAILED",
      errorMessage: error_message,
      failedAt: Time.current.iso8601
    }

    begin
      RestClient.post(
        callback_url,
        payload.to_json,
        content_type: :json,
        accept: :json,
        timeout: 15
      )
      Rails.logger.info "Sent FAILURE callback for Scan ID #{scan_id}"
    rescue => e
      Rails.logger.error "Cannot send failure callback to #{callback_url} | #{e.class}: #{e.message}"
    end
  end
end
