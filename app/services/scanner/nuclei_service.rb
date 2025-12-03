# frozen_string_literal: true
require 'open3'
require 'json'
module Scanners
  class NucleiService
    def initialize(target_url, scan_id)
      @target_url = target_url
      @scan_id = scan_id
    end

    def run
      cmd = [
        "docker", "run", "--rm",
        "-i",
        "projectdiscovery/nuclei:latest",
        "-u", @target_url,
        "-jsonl",
        "-silent",
        "-nc"
      ]

      puts("Running Nuclei for Scan_Id: #{@scan_id}")
      stdout, stderr, status = Open3.capture3(*cmd)
      if status.success?
        vulnerabilities = parse_jsonl(stdout)
        {
          success: true,
          data: build_response(vulnerabilities)
        }
      else
        {
          success: false,
          error: stderr.presence || "Nuclei exited with code #{status.exitstatus}"
        }
      end
    end

    private

    def parse_jsonl(raw_output)
      raw_output.each_line.map do |line|
        next if line.strip.empty?
        begin
          JSON.parse(line.strip)
        rescue JSON::ParserError => e
          Rails.logger.warn "Invalid JSON line in Nuclei output: #{e.message}"
          nil
        end
      end.compact
    end

    def extract_cwe_ids(classification)
      return [] unless classification.is_a?(Hash) && classification["cwe-id"].present?

      classification["cwe-id"].map do |cwe|
        cwe.to_s.downcase.start_with?("cwe-") ? cwe.split("-").last.to_i : nil
      end.compact.uniq
    end

    def build_response(vulnerables)
      summary = {
        total: vulnerables.size,
        critical: vulnerables.count { |v| v.dig("info", "severity") == "critical" },
        high:     vulnerables.count { |v| v.dig("info", "severity") == "high" },
        medium:   vulnerables.count { |v| v.dig("info", "severity") == "medium" },
        low:      vulnerables.count { |v| v.dig("info", "severity") == "low" },
        info:     vulnerables.count { |v| v.dig("info", "severity") == "info" }
      }

      first_vuln = vulnerables.first || {}

      {
        scan_id: @scan_id,
        status: "completed",
        summary: summary,
        target_updates: {
          ip: first_vuln["ip"],
          host: first_vuln["host"],
          scheme: first_vuln["scheme"],
          port: first_vuln["port"]
        },
        vulnerabilities: vulnerables.map { |v| parse_vulnerability(v) }
      }
    end

    def parse_vulnerability(vuln)
      info = vuln["info"] || {}
      classification = info["classification"] || {}

      base = {
        template_id: vuln["template-id"],
        name: info["name"] || "Unknown Vulnerability",
        severity: info["severity"] || "info",
        description: info["description"].to_s.strip,
        matched_at: vuln["matched-at"] || vuln["url"] || vuln["host"],
        cwe_ids: extract_cwe_ids(classification),
        references: info["reference"] || []
      }

      evidence = {}
      if vuln["extracted-results"].present?
        evidence = { type: "extracted", resources: vuln["extracted-results"] }
      elsif vuln["interaction"].present?
        interaction = vuln["interaction"]
        evidence = {
          type: "oast",
          interaction_domain: interaction["full-id"],
          remote_ip: interaction["remote-address"]
        }
      elsif vuln["curl-command"].present?
        evidence = { type: "curl", command: vuln["curl-command"] }
      end

      base.merge(
        evidence: evidence.presence,
        curl_command: vuln["curl-command"]
      )
    end
  end
end
