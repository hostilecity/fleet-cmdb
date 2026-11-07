# Advisory files uploaded on the dashboard are imported in the background (P2-D06, owner decision on #129).
#
# - advisory_imports gains the states of an upload waiting for its job (queued) and being imported (importing).
#   finished_at is empty exactly while an import is in one of them. matching keeps what the result page says
#   about re-matching (how many changed source packages, on how many hosts), since the page is no longer drawn
#   in the request that imported the file.
# - advisory_uploads holds an uploaded file until its import ends (or, for a full import refused for what it
#   would withdraw, until the operator confirms it or it expires): at most 64 MiB each (the request
#   body limit), tied to the operator who uploaded it and to its import, deleted by the job when the import ends
#   and, failing that, after expires_at by AdvisoryUploadPruneJob. In the database rather than on disk, so the
#   job can read it whichever process or container runs it, and it is written in the same transaction as its
#   import row.
class CreateAdvisoryUploads < ActiveRecord::Migration[8.1]
  def change
    change_column_null :advisory_imports, :finished_at, true
    add_column :advisory_imports, :matching, :jsonb
    remove_check_constraint :advisory_imports, "state IN ('succeeded', 'failed')", name: "advisory_imports_state_valid"
    add_check_constraint :advisory_imports, "state IN ('queued', 'importing', 'succeeded', 'failed')", name: "advisory_imports_state_valid"
    add_check_constraint :advisory_imports, "(finished_at IS NULL) = (state IN ('queued', 'importing'))", name: "advisory_imports_finished_iff_done"

    create_table :advisory_uploads do |t|
      t.references :advisory_import, null: false, foreign_key: { on_delete: :cascade }, index: { unique: true }
      t.references :operator, null: false, foreign_key: true
      t.string :filename, null: false, limit: 256
      t.bigint :byte_size, null: false
      t.binary :data, null: false
      # A full import refused for what it would withdraw keeps its file, and the operator's second confirmation
      # records here, per ecosystem, how many withdrawals it accepted (review of #129).
      t.jsonb :allowed_withdrawals, null: false, default: {}
      t.datetime :created_at, null: false
      t.datetime :expires_at, null: false
    end
    add_index :advisory_uploads, :expires_at
    add_check_constraint :advisory_uploads, "byte_size = octet_length(data) AND byte_size <= 67108864", name: "advisory_uploads_size_bounded"
  end
end
