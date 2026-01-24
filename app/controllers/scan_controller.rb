# frozen_string_literal: true

class ScanController < ApplicationController
  wrap_parameters false
  skip_before_action :verify_authenticity_token, only: [:start]
  #POST /Scan/start
  def start
    service = ScanRunnerService.new(scan_params)

    if Rails.env.development? || Rails.env.test?
      results = service.run_all_scans
      render_success_response("Scan completed synchronously", results)
    else
      # Đẩy vào background job
      job = ScanJob.perform_later(scan_params)

      render json: {
        status: "QUEUED",
        scan_id: scan_params[:scan_id].to_s,
        message: "Scan queued successfully (Active Job)",
        queued_at: Time.current.iso8601
      }, status: :accepted
    end

  rescue ScanRunnerService::InvalidParamsError => e
    render json: {
      status: "ERROR",
      scan_id: scan_params[:scan_id],
      error: "Invalid parameters",
      message: e.message
    }, status: :bad_request

  rescue StandardError => e
    Rails.logger.error "Unexpected error in ScanController#start: #{e.class} - #{e.message}"
    Rails.logger.error e.backtrace.join("\n")

    render json: {
      status: "ERROR",
      scan_id: scan_params[:scan_id],
      error: "Internal server error",
      message: e.message
    }, status: :internal_server_error
  end

  private

  def scan_params
    params.require(:scan_id)
    params.require(:target_url)
    params.require(:scan_tools)
    params.require(:callback_url)

    params.permit(
      :scan_id,
      :target_url,
      :callback_url,
      scan_tools: [],
      scan_parameters: {}
    ).to_h.symbolize_keys
  end

  def render_success_response(message, results)
    total_scanners = results.keys.size
    completed_scanners = results.values.count { |r| r[:status] == "COMPLETED" }

    render json: {
      status: "COMPLETED",
      scan_id: scan_params[:scan_id],
      message: message,
      summary: {
        total_scanners: total_scanners,
        completed_scanners: completed_scanners,
        failed_scanners: total_scanners - completed_scanners
      },
      results: results,
      completed_at: Time.current.iso8601
    }, status: :ok
  end
end
