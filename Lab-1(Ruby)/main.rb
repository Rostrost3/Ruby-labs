require_relative 'vote_analyzer'

def main
  analyzer = ElectionAnalyzer.new('data/votes_30.txt')
  analyzer.run_analysis

  puts "\nТоп-10 участников:"
  analyzer.top_candidates.each_with_index do |(name, votes), i|
    puts "#{i+1}. #{name}: #{votes} голосов"
  end

  puts "\nТоп-5 подозрительных по IP:"
  analyzer.most_suspicious_by_ip.each_with_index do |(name, ratio), i|
    puts "#{i+1}. #{name}: #{(ratio*100).round(2)}% уникальных IP"
  end

  puts "\nТоп-5 подозрительных по времени:"
  analyzer.most_suspicious_by_time.each_with_index do |(name, avg_gap), i|
    puts "#{i+1}. #{name}: средний интервал #{avg_gap.round(1)} сек"
  end

  puts "\nВыявленные мошенники:"
  if analyzer.scammers.any?
    analyzer.scammers.each do |name, reason|
      puts "#{name}: #{reason}"
    end
  else
    puts "Мошенники не найдены"
  end
end

main if __FILE__ == $0