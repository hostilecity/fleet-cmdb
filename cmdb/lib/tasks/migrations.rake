# Migrations never run through a transaction-mode pooler (#198, ADR 0025, ADR 0031). There Rails takes no migration
# lock (advisory_locks: false), so two containers could each run the same migration. They run once per deploy, in a
# one-off container whose database URLs go straight to PostgreSQL with FLEET_DB_POOLER unset, so the lock is on
# (docs/operations/scaling.md).
namespace :db do
  task :refuse_through_pooler do
    if DeploymentTopology.transaction_pooler?
      abort "Migrations do not run through the pooler (FLEET_DB_POOLER=transaction): run them in a one-off container " \
            "with the database URLs straight to PostgreSQL and FLEET_DB_POOLER unset (docs/operations/scaling.md)."
    end
  end
end

Rake::Task.tasks.select { |task| task.name.match?(/\Adb:(migrate|prepare|setup|rollback|schema:load)(:|\z)/) }
          .each { |task| task.enhance([ "db:refuse_through_pooler" ]) }
