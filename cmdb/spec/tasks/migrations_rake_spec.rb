require "rails_helper"
require "rake"

# Migrations never run through a transaction-mode pooler, where Rails takes no migration lock (#198, ADR 0025):
# they run once, in a one-off container on direct connections.
RSpec.describe "migrations behind a pooler (lib/tasks/migrations.rake)" do
  before(:all) { Rails.application.load_tasks unless Rake::Task.task_defined?("db:refuse_through_pooler") }

  def refuse(env)
    task = Rake::Task["db:refuse_through_pooler"]
    task.reenable
    saved = env.keys.to_h { |key| [ key, ENV.fetch(key, nil) ] }
    env.each { |key, value| ENV[key] = value }
    task.invoke
  ensure
    saved&.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end

  it "guards every task that migrates or loads a schema, for each database" do
    %w[db:migrate db:prepare db:setup db:rollback db:schema:load db:migrate:primary db:migrate:queue].each do |name|
      expect(Rake::Task[name].prerequisites).to include("db:refuse_through_pooler"), name
    end
  end

  it "stops a migration through the pooler, and lets one on direct connections run" do
    expect { refuse("FLEET_DB_POOLER" => "transaction") }.to raise_error(SystemExit).and output(/do not run through the pooler/).to_stderr
    expect { refuse("FLEET_DB_POOLER" => "") }.not_to raise_error
  end
end
