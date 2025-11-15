# frozen_string_literal: true
class ReportParserService
  # DTO cho kết quả thô gửi về Web Service
  RawResultDto = Struct.new(:toolSpecificId, :title, :severity, :urlFound, :parameterFound, :rawDetails, :rawOutput, keyword_init: true)

  def self.parse_zap_json(file_path)
    report_json = JSON.parse(File.read(file_path))
    results = []

    report_json['site'].each do |site|
      site['alerts'].each do |alert|
        # Ánh xạ từ cấu trúc ZAP sang RawResultDto
        # Đây là nơi bạn định nghĩa cách trích xuất thông tin
        # từ báo cáo ZAP.
        results << RawResultDto.new(
          toolSpecificId: alert['alertid'],
          title: alert['alert'],
          severity: alert['riskdesc'], # 'Low', 'Medium', 'High'
          urlFound: alert['instances'].first&.dig('uri') || site['@name'],
          parameterFound: alert['instances'].first&.dig('param'),
          rawDetails: alert['description'],
          rawOutput: alert.to_json # Lưu toàn bộ alert object
        )
      end
    end
    results
  rescue JSON::ParserError => e
    Rails.logger.error "Failed to parse ZAP JSON report at #{file_path}: #{e.message}"
    []
  rescue StandardError => e
    Rails.logger.error "Error parsing ZAP report: #{e.message}"
    []
  end

  def self.parse_nikto_json(file_path)
    report_json = JSON.parse(File.read(file_path))
    results = []

    report_json['vulnerabilities'].each do |vuln|
      # Ánh xạ từ cấu trúc Nikto sang RawResultDto
      results << RawResultDto.new(
        toolSpecificId: vuln['id'],
        title: vuln['msg'],
        severity: 'Informational', # Nikto thường không có severity rõ ràng, cần gán mặc định
        urlFound: report_json['host'],
        parameterFound: nil, # Nikto ít khi có param cụ thể
        rawDetails: vuln['msg'],
        rawOutput: vuln.to_json
      )
    end
    results
  rescue JSON::ParserError => e
    Rails.logger.error "Failed to parse Nikto JSON report at #{file_path}: #{e.message}"
    []
  rescue StandardError => e
    Rails.logger.error "Error parsing Nikto report: #{e.message}"
    []
  end

end
