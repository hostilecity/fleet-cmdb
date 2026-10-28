# Liveness thresholds (P1-D02, moved from P1-S09). Validated and audited by Setting; errors are shown in
# place (FR-S.4).
class SettingsController < ApplicationController
  def edit
    thresholds = Setting.liveness_thresholds
    @online = thresholds[:online].in_minutes.to_i
    @stale = thresholds[:stale].in_minutes.to_i
  end

  def update
    @online = params[:online_minutes].to_s
    @stale = params[:stale_minutes].to_s
    Setting.update_liveness_thresholds!(online_minutes: @online, stale_minutes: @stale, actor: current_operator)
    redirect_to settings_path, notice: "Settings saved. They apply from the next liveness check."
  rescue Setting::Invalid => e
    @error = e
    render :edit, status: :unprocessable_content
  end
end
