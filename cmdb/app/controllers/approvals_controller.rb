# Onboarding approval (P1-D07, DEC-17, FR-S.1). An installer prints /onboard/<user code>; an operator signs
# in, checks the code against the terminal and what the VM reported, and approves it as a new host or as the
# re-enrollment of a host they choose, or rejects it. Built on Onboarding::Approve and ::Reject (P1-S14).
class ApprovalsController < ApplicationController
  CODE_LOOKUPS_PER_MINUTE = 20

  # Typing codes is limited per operator, so the code box is no oracle for guessing codes.
  rate_limit to: CODE_LOOKUPS_PER_MINUTE, within: 1.minute, only: :lookup, by: -> { current_operator.id },
             store: AgentApi.rate_limit_store, name: "onboard_lookup",
             with: -> { redirect_to onboard_path, alert: "Too many codes tried. Wait a minute and try again." }

  before_action :load_request, only: %i[show approve reject]

  def index
    @awaiting = OnboardingRequest.awaiting.order(created_at: :desc).to_a
    @matches = @awaiting.to_h { |r| [ r.id, r.matching_hosts ] }
  end

  # The code box only finds requests that are waiting; expired, decided, and unknown codes all get the same
  # answer, so it reveals nothing (approved mockups, P1-D06).
  def lookup
    @code = params[:code].to_s.strip.first(20)
    request = OnboardingRequest.find_awaiting_by_user_code(@code)
    return redirect_to onboard_request_path(request.user_code) if request

    @code_error = "No waiting VM has this code. Check the terminal; codes expire after #{OnboardingRequest.config.ttl.in_minutes.to_i} minutes."
    index
    render :index, status: :unprocessable_content
  end

  def show
    prepare_review if @request.awaiting?
  end

  def approve
    return redirect_to onboard_request_path(@request.user_code) unless @request.awaiting?

    target = chosen_target
    Onboarding::Approve.call(request: @request, operator: current_operator, attributes: host_params.to_h, target_host: target)
    redirect_to onboard_request_path(@request.user_code) # the page shows the outcome and updates live
  rescue ActiveRecord::RecordInvalid => e
    prepare_review(host: e.record)
    render :show, status: :unprocessable_content
  rescue Onboarding::Approve::TargetRetired, ActiveRecord::RecordNotFound
    redirect_to onboard_request_path(@request.user_code), alert: "That host can no longer be re-enrolled. Choose again."
  rescue Onboarding::NotDecidable
    redirect_to onboard_request_path(@request.user_code)
  end

  def reject
    Onboarding::Reject.call(request: @request, operator: current_operator) if @request.awaiting?
    redirect_to onboard_request_path(@request.user_code)
  rescue Onboarding::NotDecidable
    redirect_to onboard_request_path(@request.user_code)
  end

  private

  def load_request
    @request = OnboardingRequest.latest_by_user_code(params[:code])
    render :unknown, status: :not_found unless @request
  end

  # "new" or "reenroll-<host id>"; a re-enrollment target must be one of the hosts this request matched.
  def chosen_target
    choice = params[:choice].to_s
    return nil if choice == "new" || choice.blank?

    id = choice.delete_prefix("reenroll-")
    host = @request.matching_hosts.map(&:first).find { |h| h.id.to_s == id }
    host or raise ActiveRecord::RecordNotFound
  end

  def host_params = params.fetch(:host, {}).permit(:name, :hostname, :tags, :description, :notes)

  def prepare_review(host: nil)
    @matches = @request.matching_hosts
    default_target = @matches.find { |_, why| why == :machine_id }&.first
    @choice = params[:choice].presence || (default_target ? "reenroll-#{default_target.id}" : "new")
    @host = host || Host.new(name: @request.hostname&.split(".")&.first, hostname: @request.hostname)
  end
end
