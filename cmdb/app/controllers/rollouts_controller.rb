# Starting and driving agent rollouts from the dashboard (P1-D09, FR-S.5, ADR 0018; approved mockups
# agents.html, agents-halted.html, dialogs.html). Every action asks for confirmation first (GET), and only the
# CSRF-protected POST acts, through the Rollouts service, which audits it with the signed-in operator as actor.
# A rollout that changed state while the confirmation was open is refused with the service's reason.
class RolloutsController < ApplicationController
  include AgentsPage

  before_action :load_rollout, except: %i[new create]
  before_action :load_start, only: %i[new create]

  # GET /agents/rollouts/new: confirm the release, canaries, and stages chosen on the Agents page.
  def new
    @canaries = Rollouts.canary_hosts(release: @release, canary_host_ids: @start[:canary_host_ids], canary_tag: @start[:canary_tag])
      .order(:name, :id).to_a
    @stage_percents = Rollouts.stage_percents!(@start[:stages])
    raise Rollouts::Invalid, "A rollout is already open. Finish or cancel it first." if Rollout.open_now.exists?
    raise Rollouts::Invalid, "None of the chosen canaries is an active host running an older version than #{@release.version}." if @canaries.empty?
  rescue Rollouts::Invalid => e
    refuse_start(e.message)
  end

  def create
    rollout = Rollouts.start!(release: @release, actor: current_operator, canary_host_ids: @start[:canary_host_ids],
                              canary_tag: @start[:canary_tag], stage_percents: @start[:stages])
    canaries = rollout.rollout_hosts.count
    redirect_to agents_path, notice: "Rollout to #{@release.version} started. #{helpers.pluralize(canaries, 'canary host')} " \
                                     "#{canaries == 1 ? 'is' : 'are'} offered it on #{canaries == 1 ? 'its' : 'their'} next heartbeat."
  rescue Rollouts::Invalid => e
    refuse_start(e.message)
  end

  def confirm_advance; end
  def confirm_halt; end
  def confirm_resume
    @problems = @rollout.rollout_hosts.includes(:host).where(state: %w[failed rolled_back unconfirmed]).order(:stage, :host_id).limit(ROLLOUT_HOST_LIMIT).to_a
    @update_reasons = latest_reasons(@rollout.agent_updates.where(host_id: @problems.map(&:host_id)))
  end
  def confirm_cancel; end

  def advance = act(:advance!) { "The rollout to #{version} moved on to stage #{@rollout.current_stage + 1}." }
  def halt = act(:halt!) { "The rollout to #{version} is halted. No more hosts are offered it until you resume it." }
  def resume = act(:resume!) { "The rollout to #{version} is running again." }
  def cancel = act(:cancel!) { "The rollout to #{version} is cancelled. Hosts stay on the version they run now." }

  private

  def load_rollout
    @rollout = Rollout.includes(:agent_release, :started_by, :halted_by, :resumed_by).find(params[:id])
  end

  def version = @rollout.agent_release.version

  # The notice is built after the action, from the rollout as it left it.
  def act(method)
    Rollouts.public_send(method, @rollout, actor: current_operator)
    redirect_to agents_path, notice: yield
  rescue Rollouts::Invalid => e
    redirect_to agents_path, alert: "Nothing changed: #{e.message}"
  end

  # The start form's choices, as sent. An unknown release is refused on the Agents page.
  def load_start
    @start = { release: params[:release].to_s, canary_tag: params[:canary_tag].to_s.presence,
               canary_host_ids: Array(params[:canary_host_ids]).map(&:to_s).compact_blank.first(AgentsPage::CANARY_CHOICE_LIMIT),
               stages: params[:stages].to_s.first(100) }
    @release = AgentRelease.find_by(version: @start[:release])
    refuse_start("Choose a release to roll out.") unless @release
  end

  def refuse_start(message)
    @errors = { rollout: message }
    load_agents_page
    render "agent_releases/index", status: :unprocessable_content
  end
end
