require 'damerau-levenshtein'
require 'time'

class ElectionAnalyzer
  attr_reader :scammers

  def initialize(file_path)
    @file_path = file_path
    @votes_data = []
    @votes_count = Hash.new(0)
    @votes_by_ip = Hash.new { |hash, key| hash[key] = [] }
    @votes_by_time = Hash.new { |hash, key| hash[key] = [] }
    @scammers = {}
  end

  def run_analysis
    load_votes
    normalize_names
    identify_fraud
  end

  def top_candidates(limit = 10)
    @votes_count.sort_by { |_, v| -v }.first(limit)
  end

  def most_suspicious_by_ip(limit = 5)
    ip_ratios.sort_by { |_, ratio| ratio }.first(limit)
  end

  def most_suspicious_by_time(limit = 5)
    time_gaps.sort_by { |_, avg_gap| avg_gap }.first(limit)
  end

  private

  def load_votes
    puts "Загрузка данных..."
    File.readlines(@file_path).each do |line|
      if line =~ /id: (\d+), time: ([\d\-: ]+), ip: ([\d\.]+), candidate: (.+)/
        @votes_data << {
          id: $1.to_i,
          time: $2.strip,
          ip: $3.strip,
          candidate: $4.strip
        }
      end
    end
    puts "Прочитано #{@votes_data.size} голосов"
  end

  def normalize_names
    puts "Исправление опечаток..."
    name_counts = Hash.new(0)
    @votes_data.each { |v| name_counts[v[:candidate]] += 1 }

    min_votes = [@votes_data.size / 1000, 5].max
    rare_names = name_counts.select { |_, c| c < min_votes }.keys
    common_names = name_counts.select { |_, c| c >= min_votes }.keys

    name_corrections = {}
    rare_names.each do |rare|
      common_names.each do |common|
        if DamerauLevenshtein.distance(rare, common, 2) <= 2
          name_corrections[rare] = common
          break
        end
      end
    end

    @votes_data.each do |vote|
      if name_corrections[vote[:candidate]]
        vote[:candidate] = name_corrections[vote[:candidate]]
      end
    end

    # Пересчёт
    @votes_count.clear
    @votes_by_ip.clear
    @votes_by_time.clear

    @votes_data.each do |vote|
      name = vote[:candidate]
      @votes_count[name] += 1
      @votes_by_ip[name] << vote[:ip]
      @votes_by_time[name] << vote[:time]
    end
  end

  def identify_fraud
    check_ip_fraud
    check_time_fraud
  end

  def ip_ratios
      ip_uniqueness = {}
      @votes_by_ip.each do |candidate, ips|
        total_votes = ips.size
        unique_ips = ips.uniq.size
        uniqueness_ratio = unique_ips.to_f / total_votes
        ip_uniqueness[candidate] = uniqueness_ratio
      end
      ip_uniqueness
  end

  def time_gaps
    time_intervals = {}
    @votes_by_time.each do |candidate, time_strings|
      next if time_strings.size < 10
      parsed_times = time_strings.map { |t| Time.parse(t) }.sort
      intervals = []
      (1...parsed_times.size).each do |i|
        interval_seconds = parsed_times[i] - parsed_times[i-1]
        intervals << interval_seconds if interval_seconds > 0
      end
      avg_interval = intervals.empty? ? Float::INFINITY : intervals.sum / intervals.size
      time_intervals[candidate] = avg_interval
    end
    time_intervals
  end

  def check_ip_fraud
    ip_ratios.sort_by { |_, r| r }.first(3).each do |candidate, ratio|
      if ratio < 0.3
        @scammers[candidate] = "Мало уникальных IP: #{(ratio * 100).round(2)}%"
      end
    end
  end

  def check_time_fraud
    time_gaps.sort_by { |_, avg| avg }.first(3).each do |candidate, avg_gap|
      if avg_gap < 60
        @scammers[candidate] = "Слишком быстрые голоса: средний интервал #{avg_gap.round(1)} сек"
      end
    end
  end
end