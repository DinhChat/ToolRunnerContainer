# frozen_string_literal: true

module Scanners
  class ZapService
    def initialize(target_url:, scan_id:, parameters: {})
      @target_url = target_url
      @scan_id = scan_id
      @parameters = parameters || {}
    end

    def run
      Rails.logger.info("Running OWASP ZAP | Scan ID: #{@scan_id}")

      output_file = Tempfile.new(%w[zap_result_ .json])
      cmd = build_command(output_file.path)

      stdout, stderr, status = Open3.capture3(*cmd)

      unless status.success?
        return {
          success: false,
          error: stderr.presence || "ZAP exited with code #{status.exitstatus}"
        }
      end

      raw = File.read(output_file.path)
      parsed = JSON.parse(raw)

      {
        success: true,
        data: build_response(parsed)
      }
    rescue StandardError => e
      Rails.logger.error("ZAP scan failed: #{e.message}")
      {
        success: false,
        error: e.message
      }
    ensure
      output_file&.unlink
    end

    private

    def build_command(output_path)
      timeout = @parameters["timeout"] || 300
      policy  = @parameters["policy"]  # optional scan policy

      cmd = [
        "docker", "run", "--rm",
        "-u", "zap",
        "zaproxy/zap-stable",
        "zap-full-scan.py",
        "-t", @target_url,
        "-J", "/zap/wrk/result.json",
        "-m", timeout.to_s
      ]

      cmd += ["-p", policy] if policy.present?

      # mount output
      cmd.insert(3, "-v", "#{File.dirname(output_path)}:/zap/wrk")

      cmd
    end

    def build_response(parsed)
      alerts = parsed["site"]&.first&.dig("alerts") || []

      {
        summary: build_summary(alerts),
        target_updates: extract_target(parsed),
        vulnerabilities: alerts.map { |a| parse_alert(a) }
      }
    end

    def build_summary(alerts)
      {
        total: alerts.size,
        high: alerts.count { |a| a["riskcode"] == "3" },
        medium: alerts.count { |a| a["riskcode"] == "2" },
        low: alerts.count { |a| a["riskcode"] == "1" },
        info: alerts.count { |a| a["riskcode"] == "0" }
      }
    end

    def extract_target(parsed)
      site = parsed["site"]&.first || {}

      {
        host: site["@name"],
        port: site["@port"],
        scheme: site["@ssl"] == "true" ? "https" : "http"
      }
    end

    def parse_alert(alert)
      {
        plugin_id: alert["pluginid"],
        name: alert["alert"],
        severity: map_severity(alert["riskcode"]),
        confidence: alert["confidence"],
        description: alert["desc"],
        solution: alert["solution"],
        reference: alert["reference"],
        cwe_id: alert["cweid"],
        wasc_id: alert["wascid"],
        evidence: extract_instances(alert)
      }
    end

    def extract_instances(alert)
      alert["instances"]&.map do |i|
        {
          uri: i["uri"],
          method: i["method"],
          param: i["param"],
          evidence: i["evidence"]
        }
      end || []
    end

    def map_severity(code)
      case code.to_s
      when "3" then "high"
      when "2" then "medium"
      when "1" then "low"
      else "info"
      end
    end
  end
end

