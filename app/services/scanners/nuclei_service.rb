# frozen_string_literal: true
require 'open3'
require 'json'

module Scanners
  class NucleiService
    def initialize(target_url:, scan_id:, parameters: {})
      @target_url = target_url
      @scan_id = scan_id
      @parameters = parameters || {}
    end

    def run
      cmd = build_command
      Rails.logger.info("Running NUCLEI | Scan ID: #{@scan_id}")

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

    def build_command
      template_path = @parameters["template_path"]
      severity = @parameters["severity"]

      cmd = [
        "docker", "run", "--rm",
        "-i",
        "projectdiscovery/nuclei:latest",
        "-u", @target_url,
        "-jsonl",
        "-silent",
        "-nc"
      ]

      cmd += ["-t", template_path] if template_path.present?
      cmd += ["-severity", severity] if severity.present?

      cmd
    end

    def parse_jsonl(raw)
      raw.each_line.map do |line|
        next if line.strip.empty?
        begin
          JSON.parse(line.strip)
        rescue JSON::ParserError => e
          Rails.logger.warn "Invalid JSON line from Nuclei: #{e.message}"
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

      first = vulnerables.first || {}

      {
        summary: summary,
        target_updates: {
          ip: first["ip"],
          host: first["host"],
          scheme: first["scheme"],
          port: first["port"]
        },
        vulnerabilities: vulnerables.map { |v| parse_vulnerability(v) }
      }
    end

    def parse_vulnerability(v)
      info = v["info"] || {}
      classification = info["classification"] || {}

      base = {
        template_id: v["template-id"],
        name: info["name"],
        severity: info["severity"],
        description: info["description"].to_s.strip,
        matched_at: v["matched-at"] || v["url"] || v["host"],
        cwe_ids: extract_cwe_ids(classification),
        references: info["reference"] || []
      }

      base.merge(evidence: extract_evidence(v))
    end

    def extract_evidence(v)
      if v["extracted-results"].present?
        {
          type: "extracted",
          resources: v["extracted-results"]
        }
      elsif v["interaction"].present?
        interaction = v["interaction"]
        {
          type: "oast",
          interaction_domain: interaction["full-id"],
          remote_ip: interaction["remote-address"]
        }
      elsif v["curl-command"].present?
        {
          type: "curl",
          command: v["curl-command"]
        }
      else
        nil
      end
    end
  end
end
