require "optparse"

module FleetBenchmark
  module CLI
    COMMANDS = %w[seed queries explain jobs load].freeze

    module_function

    def run(argv)
      command = argv.shift
      options = {}
      parser = OptionParser.new do |o|
        o.banner = "Usage: bin/benchmark #{COMMANDS.join('|')} [options]  (docs/operations/benchmark.md)"
        o.separator "seed:"
        Seed::DEFAULTS.each { |key, default| o.on("--#{key.to_s.tr('_', '-')} N", Integer, "default #{default}") { |v| options[key] = v } }
        o.separator "queries, explain, jobs:"
        o.on("--samples N", Integer, "hosts sampled (queries 50, jobs 200)") { |v| options[:samples] = v }
        o.on("--only TEXT", "only the cases whose name contains TEXT") { |v| options[:only] = v }
        o.on("--verbose", "queries: list one request's statements; explain: the whole statement") { options[:verbose] = true }
        o.on("--repeat N", Integer, "jobs: runs per measurement (default 3)") { |v| options[:repeat] = v }
        o.separator "load:"
        o.on("--url URL", "the running server, for example http://127.0.0.1:3000") { |v| options[:url] = v }
        o.on("--kind KIND", "#{Load::KINDS.keys.join(', ')}, or mix (default heartbeat)") { |v| options[:kind] = v }
        o.on("--threads N", Integer, "client threads (default 8)") { |v| options[:threads] = v }
        o.on("--duration S", Integer, "seconds (default 30)") { |v| options[:duration] = v }
        o.on("--load-hosts N", Integer, "seeded hosts to send as, in turn (default 20000)") { |v| options[:load_hosts] = v }
        o.on("--first-host N", Integer, "the first of them (default 1001, after the hosts with queued tasks)") { |v| options[:first_host] = v }
        o.on("--agent-host NAME", "the server's FLEET_AGENT_HOST (default this environment's)") { |v| options[:agent_host] = v }
      end
      parser.parse!(argv)
      refuse_production!
      case command
      when "seed" then Seed.new(**options.slice(*Seed::DEFAULTS.keys)).call
      when "queries" then Queries.new(**options.slice(:samples, :verbose, :only)).call
      when "explain" then Explain.new(**options.slice(:verbose, :only)).call
      when "jobs" then Jobs.new(**options.slice(:repeat, :samples, :only)).call
      when "load"
        Load.new(url: options.fetch(:url) { abort("load needs --url") }, hosts: options.fetch(:load_hosts, 20_000),
                 **options.slice(:kind, :threads, :duration, :first_host, :agent_host)).call
      else
        puts parser
        return 1
      end
      0
    end

    # Seeding writes test data and the other commands write to the hosts they sample; never against production.
    def refuse_production!
      abort "bin/benchmark refuses to run in production" if Rails.env.production?
    end
  end
end
