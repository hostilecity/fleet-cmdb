# The task catalog (FR-3.1, P3-S01) is loaded and linted at boot, so the server never starts with a catalog that
# allows a free-form string, a command-like parameter, or an open schema. The file is docs/api/tasks/task-catalog.json,
# read at runtime like the agent API schemas; the Docker image copies it in from the "api" build context, and
# FLEET_TASK_CATALOG_DIR overrides where it is read from.
Rails.application.config.after_initialize do
  TaskCatalog.current
end
