# frozen_string_literal: true

class ScanController < ApplicationController
  protect_from_forgery with: :null_session
  #POST /Scan/start
  def start
    scan_id = params[:scan_id]
    target_url = params[:target_url]
    scan_tool_name = params[:scan_tool_name]
    scan_parameters = params[:scan_parameters]
    callback_url = params[:callback_url]

    unless scan_id && target_url && scan_tool_name && callback_url
      render json: { error: 'Missing required parameters' }, status: :bad_request
      return
    end

    Rails.logger.info "Received scan request for Scan ID: #{scan_id}, Target: #{target_url}, Tool: #{scan_tool_name}"

    ScanJob.perform_later(scan_id, target_url, scan_tool_name, scan_parameters, callback_url)

    render json: { message: "Scan request received and queued for Scan ID: #{scan_id}" }, status: :accepted rescue StandardError => e
    Rails.logger.error "Error processing scan request: #{e.message}"
    render json: { error: "Internal server error: #{e.message}" }, status: :internal_server_error
  end
end
