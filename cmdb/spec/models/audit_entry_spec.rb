require "rails_helper"

# FR-S.3: the audit log is append-only. The application offers no update or delete path, and the
# database rejects UPDATE, DELETE, and TRUNCATE even from code that bypasses the model.
RSpec.describe AuditEntry do
  let!(:entry) do
    host = create(:host)
    AuditEntry.for_target(host).sole
  end

  # Each attempt runs in a savepoint so the database error does not abort the test transaction.
  def attempt(&block)
    AuditEntry.transaction(requires_new: true, &block)
  end

  describe "in the application" do
    it "makes saved entries read-only" do
      expect(entry).to be_readonly
      expect { entry.update!(action: Audit::Actions::HOST_RETIRED) }.to raise_error(ActiveRecord::ReadOnlyRecord)
      expect { entry.update_column(:action, Audit::Actions::HOST_RETIRED) }.to raise_error(ActiveRecord::ReadOnlyRecord)
      expect { entry.destroy }.to raise_error(ActiveRecord::ReadOnlyRecord)
      expect { entry.delete }.to raise_error(ActiveRecord::ReadOnlyRecord)
    end
  end

  describe "in the database" do
    it "rejects bulk updates" do
      expect { attempt { AuditEntry.where(id: entry.id).update_all(action: Audit::Actions::HOST_RETIRED) } }
        .to raise_error(ActiveRecord::StatementInvalid, /append-only: UPDATE/)
    end

    it "rejects bulk deletes" do
      expect { attempt { AuditEntry.where(id: entry.id).delete_all } }
        .to raise_error(ActiveRecord::StatementInvalid, /append-only: DELETE/)
    end

    it "rejects raw SQL updates, deletes, and truncation" do
      [
        "UPDATE audit_entries SET action = 'host.retired'",
        "DELETE FROM audit_entries",
        "TRUNCATE audit_entries"
      ].each do |sql|
        expect { attempt { AuditEntry.connection.execute(sql) } }.to raise_error(ActiveRecord::StatementInvalid, /append-only/), sql
      end
      expect(entry.reload.action).to eq(Audit::Actions::HOST_CREATED)
    end

    it "sets occurred_at from the database clock" do
      expect(AuditEntry.columns_hash["occurred_at"].default_function).to eq("CURRENT_TIMESTAMP")
    end

    it "constrains actor type and id" do
      expect do
        attempt { AuditEntry.insert_all!([ { actor_type: "system", actor_id: 1, action: Audit::Actions::HOST_EDITED } ]) }
      end.to raise_error(ActiveRecord::StatementInvalid, /audit_entries_actor_id_matches_type/)
    end
  end
end
