# What the Agents page shows (P1-RELEASES, P1-D09; approved mockups agents.html and agents-halted.html):
# releases and imports, the latest rollout with its stages and hosts, and the form to start one. Shared by the
# controllers whose forms are on that page, so a refused form is shown in place on the page.
module AgentsPage
  extend ActiveSupport::Concern

  # Rows in the rollout's host table and canary choices in the start form. The stage cards always count
  # every host, so a larger fleet loses no outcome; the table says how many it leaves out.
  ROLLOUT_HOST_LIMIT = 200
  CANARY_CHOICE_LIMIT = 200

  private

  def load_agents_page
    @releases = AgentRelease.includes(:imported_by).newest_first
    @running = Host.in_fleet.where(agent_version: @releases.map(&:version)).group(:agent_version).count
    @imports = AgentReleaseImport.includes(:operator).recent.to_a
    @keys = Releases.keys
    load_latest_rollout
    load_start_form
  end

  def load_latest_rollout
    @rollout = Rollout.includes(:agent_release, :started_by, :halted_by, :resumed_by).order(started_at: :desc, id: :desc).first
    return unless @rollout

    @stage_counts = @rollout.rollout_hosts.group(:stage, :state).count
    @rollout_hosts = @rollout.rollout_hosts.includes(:host).order(:stage, :host_id).limit(ROLLOUT_HOST_LIMIT).to_a
    @rollout_host_total = @stage_counts.values.sum
    @canary_names = @rollout.rollout_hosts.where(stage: 0).joins(:host).order("hosts.name").limit(4).pluck("hosts.name")
    @update_reasons = latest_reasons(@rollout.agent_updates.where(host_id: @rollout_hosts.map(&:host_id)))
  end

  # The start form's choices: canary tags among active hosts, with their counts, and active hosts to pick.
  # A refused start keeps what the operator chose (@start); otherwise the newest release, the tag "canary" when
  # some active host has it, and the default stages.
  def load_start_form
    active = Host.active
    @canary_tags = active.group(Arel.sql("unnest(hosts.tags)")).order(Arel.sql("unnest(hosts.tags)")).count
    @start ||= { release: @releases.first&.version, canary_tag: ("canary" if @canary_tags.key?("canary")), canary_host_ids: [],
                 stages: Rollouts::DEFAULT_STAGES.join(", ") }
    @canary_choices = active.order(:name, :id).limit(CANARY_CHOICE_LIMIT).to_a
    @active_total = active.count
  end

  # The reason each host gave with its latest result, by host id.
  def latest_reasons(updates)
    updates.order(:received_at, :id).pluck(:host_id, :reason).to_h
  end
end
