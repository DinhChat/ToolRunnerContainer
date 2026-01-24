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

      # Tạo file tạm
      output_file = Tempfile.new(['zap_result_', '.json'])
      # QUAN TRỌNG: Cấp quyền 777 để user 'zap' trong Docker có thể ghi đè vào file này
      # Vì mặc định Tempfile chỉ cho user hiện tại của Rails đọc/ghi
      File.chmod(0777, output_file.path)

      cmd = build_command(output_file.path)

      stdout, stderr, status = Open3.capture3(*cmd)

      # SỬA LỖI CODE 2:
      # Chấp nhận exit code 0 (Sạch) và 2 (Có lỗi bảo mật) là thành công về mặt kỹ thuật
      unless [0, 2].include?(status.exitstatus)
        return {
          success: false,
          error: stderr.presence || "ZAP exited with code #{status.exitstatus}"
        }
      end

      # Reload file để đảm bảo nội dung mới nhất
      # output_file.rewind # Không cần thiết vì mình dùng File.read bên dưới

      raw = File.read(output_file.path)

      # Kiểm tra nếu file rỗng (trường hợp ZAP chạy nhưng không ghi được output)
      if raw.blank?
        return { success: false, error: "ZAP output file is empty" }
      end

      parsed = JSON.parse(raw)

      {
        success: true,
        data: build_response(parsed)
      }
    rescue JSON::ParserError
      { success: false, error: "Invalid JSON output from ZAP" }
    rescue StandardError => e
      Rails.logger.error("ZAP scan failed: #{e.message}")
      {
        success: false,
        error: e.message
      }
    ensure
      output_file&.close
      output_file&.unlink
    end

    private

    def build_command(output_path)
      timeout = @parameters["timeout"] || 300
      policy  = @parameters["policy"]

      # Lấy thư mục chứa file tạm để mount
      mount_dir = File.dirname(output_path)
      # Lấy tên file (ví dụ: zap_result_123.json) để báo ZAP ghi vào đúng tên đó
      filename  = File.basename(output_path)

      cmd = [
        "docker", "run", "--rm",
        "-u", "zap", # Chạy dưới user zap
        # Mount thư mục chứa file temp vào /zap/wrk
        "-v", "#{mount_dir}:/zap/wrk",
        "zaproxy/zap-stable",
        "zap-full-scan.py",
        "-t", @target_url,
        # SỬA LỖI LOGIC FILE:
        # Chỉ truyền tên file, script sẽ ghi vào /zap/wrk/{filename}
        "-J", filename,
        "-m", timeout.to_s,

        # Thêm flag này để ZAP không trả về Code 1/2 khi tìm thấy lỗi
        # (nhưng giữ code 2 ở logic Ruby cho chắc chắn vẫn tốt hơn)
        "-I"
      ]

      cmd += ["-p", policy] if policy.present?

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

