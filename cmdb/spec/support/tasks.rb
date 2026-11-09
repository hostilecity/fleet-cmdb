# Helpers for task specs (P3-S02).
module TaskHelpers
  # An active host whose agent reports that it supports and enables the given task types (P3-A01).
  def task_host(types: TaskCatalog.current.types, enabled: types, catalog_version: TaskCatalog.current.version,
                services: %w[nginx.service], **attributes)
    host = create(:host, :active, **attributes)
    host.update_columns(task_catalog_version: catalog_version, task_types_supported: types, task_types_enabled: enabled,
                        task_services_allowed: services, task_capabilities_reported_at: Time.current)
    host
  end

  # A batch made through TaskBatches.create!, as the dashboard will make it. Returns the TaskBatches::Result.
  def create_task_batch(hosts, type: "refresh_reports", parameters: {}, operator: create(:operator), **request)
    hosts = Array(hosts)
    request = { "type" => type, "parameters" => parameters, "target" => { "host_ids" => hosts.map(&:id) } }.merge(request.stringify_keys)
    request["confirm_host_count"] ||= hosts.size if hosts.size > TaskBatches::CONFIRM_ABOVE
    TaskBatches.create!(request, operator:)
  end

  # Makes TaskCatalog.current a catalog without these types, as a later catalog might be.
  def stub_catalog_without(*types)
    data = JSON.parse(TaskCatalog::PATH.read)
    data["tasks"].reject! { |task| types.include?(task["type"]) }
    allow(TaskCatalog).to receive(:current).and_return(TaskCatalog.send(:build, data, "0" * 64))
  end

  def create_task(host = task_host, **options) = create_task_batch([ host ], **options).tasks.sole
end

RSpec.configure { |config| config.include TaskHelpers }
