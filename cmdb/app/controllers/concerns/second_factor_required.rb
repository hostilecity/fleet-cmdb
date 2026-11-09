# The step-up check for dashboard actions that need a recent second factor (P3-S09, DEC-14): creating a task or batch,
# cancelling a task, and changing task allowlists or limits. Enforced on the server for every request to the action,
# so a forged POST that skips the page is refused the same way as one from it.
#
#   class TaskBatchesController < ApplicationController
#     require_second_factor "create_task", only: :create
#   end
#
# The action's form carries the code box (render "second_factors/prompt", result: second_factor_result) and posts
# the code as second_factor_code with everything else, so one submit checks the code and does the action (Q11). An
# open 5-minute window for this session passes without a code. A refused request does nothing and gets the step-up
# page with 403 (or 429 when locked); an action that wants to show its own confirmation again overrides
# second_factor_refused, which runs instead of the action.
module SecondFactorRequired
  extend ActiveSupport::Concern

  PARAM = :second_factor_code

  included do
    helper_method :second_factor_result
  end

  class_methods do
    # fresh: true asks for a code even inside the window.
    def require_second_factor(purpose, fresh: false, **options)
      raise ArgumentError, "unknown second factor purpose #{purpose.inspect}" unless SecondFactors::PURPOSES.key?(purpose.to_s)

      before_action(**options) { require_second_factor!(purpose:, fresh:) }
    end
  end

  private

  # The last check's result, or for a page that only shows the box, the current state without checking a code.
  def second_factor_result
    @second_factor_result ||= SecondFactors.status(Current.operator_session)
  end

  def require_second_factor!(purpose:, fresh: false)
    @second_factor_result = SecondFactors.step_up(operator_session: Current.operator_session, code: params[PARAM], purpose:, fresh:)
    second_factor_refused(@second_factor_result) unless @second_factor_result.passed?
    @second_factor_result
  end

  def second_factor_refused(result)
    response.headers["Cache-Control"] = "no-store"
    render "second_factors/refused", status: (result.status == :locked ? :too_many_requests : :forbidden)
  end
end
