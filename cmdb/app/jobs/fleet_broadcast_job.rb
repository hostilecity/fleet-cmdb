# Sends the changed fleet rows, the status counts, and each host's status header to signed-in dashboards
# over Turbo Streams (P1-D05). Rows and counts go in one message so they update together. A retired host's
# row is removed. Pages that do not show a target ignore it.
class FleetBroadcastJob < ApplicationJob
  queue_as :default
  discard_on ActiveJob::DeserializationError

  def perform(host_ids)
    hosts = Host.where(id: host_ids).to_a
    rows = FleetList.rows(hosts.reject(&:retired?).map(&:id)).index_by(&:id)
    streams = hosts.flat_map do |host|
      if host.retired?
        [ stream(:remove, ActionView::RecordIdentifier.dom_id(host, :row)) ]
      else
        [ stream(:replace, ActionView::RecordIdentifier.dom_id(host, :row), "hosts/row", host: rows.fetch(host.id)),
          stream(:replace, ActionView::RecordIdentifier.dom_id(host, :status), "hosts/status", host:) ]
      end
    end
    streams << stream(:replace, "fleet_counts", "hosts/counts", counts: FleetList.counts)
    Turbo::StreamsChannel.broadcast_stream_to(FleetBroadcast::STREAM, content: safe_join(streams))
  end

  private

  def stream(action, target, partial = nil, **locals)
    content = partial && ApplicationController.render(partial:, locals:, formats: [ :html ])
    turbo_stream_tag(action, target, content)
  end

  def turbo_stream_tag(action, target, content)
    template = content ? "<template>#{content}</template>" : ""
    %(<turbo-stream action="#{action}" target="#{ERB::Util.html_escape(target)}">#{template}</turbo-stream>).html_safe
  end

  def safe_join(parts) = ActionController::Base.helpers.safe_join(parts)
end
