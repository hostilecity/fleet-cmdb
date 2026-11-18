# The history tables' time partitions (ADR 0027, #195). PartitionMaintenanceJob does this every hour; these are for
# the server console and for after a schema load.
namespace :partitions do
  desc "Create the history tables' partitions ahead, and their default partitions (also run after db:prepare and db:schema:load)"
  task ensure: :environment do
    created = Partitions.ensure!
    next puts("Another partition maintenance run is in progress: nothing done.") if created.nil?

    made = created.reject { |_, names| names.empty? }
    puts(made.any? ? made.map { |table, names| "#{table}: created #{names.join(', ')}" } : "Every partition ahead exists.")
  end

  desc "List each partitioned table's partitions and anything /health would report about them"
  task status: :environment do
    Partitions::TABLES.each_key do |table|
      next puts("#{table}: not partitioned yet (run bin/rails db:migrate)") unless Partitions.partitioned?(table)

      parts = Partitions.list(table)
      ranged = parts.reject(&:default?)
      puts "#{table}: #{ranged.size} partitions, #{ranged.first&.from&.to_date || 'MINVALUE'} to #{ranged.last&.to&.to_date}" \
           "#{', legacy partition until ' + ranged.first.to.to_date.to_s if ranged.first&.legacy?}#{', default' if parts.any?(&:default?)}"
    end
    problems = Partitions.problems
    puts(problems.empty? ? "No problems." : problems.map { |p| "#{p.severity}: #{p.text}" })
    problem = Partitions.audit_guard_problem
    puts "Audit guard (ops/postgres/audit-guard.sql): #{problem ? "does NOT hold: #{problem}" : 'installed'}"
  end

  desc "Report rows whose host, CIS rule, or rule version does not exist (the nightly check)"
  task check: :environment do
    found = PartitionCheckJob.perform_now
    abort found.map { |column, count| "#{column}: #{count} rows" }.join("\n") if found.any?
    puts "No rows without their host or rule."
  end
end

# A new or reset database gets its partitions straight away: the schema holds only the partitioned parents.
%w[db:prepare db:schema:load db:schema:load:primary].each do |name|
  Rake::Task[name].enhance { Rake::Task["partitions:ensure"].invoke } if Rake::Task.task_defined?(name)
end
