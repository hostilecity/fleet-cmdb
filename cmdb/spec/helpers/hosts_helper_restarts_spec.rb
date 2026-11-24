require "rails_helper"

# How the agent last stopped, in words (#251): systemd's result for a kill at MemoryMax is oom-kill, or signal with
# SIGKILL when it saw the exit first.
RSpec.describe HostsHelper, type: :helper do
  def words(result, code = nil, status = nil)
    helper.agent_last_stop_words(Host.new(agent_last_stop_result: result, agent_last_stop_exit_code: code, agent_last_stop_exit_status: status))
  end

  it "says what systemd said, in words first" do
    expect(words(nil)).to be_nil
    expect(words("success", "exited", 0)).to eq("Stopped cleanly (systemd: success, exit status 0)")
    expect(words("oom-kill", "killed", 9)).to eq("Killed at its memory limit (systemd: oom-kill, killed by signal 9 (SIGKILL))")
    expect(words("signal", "killed", 9)).to eq("Killed by SIGKILL, perhaps at its memory limit (systemd: signal, killed by signal 9 (SIGKILL))")
    expect(words("signal", "killed", 15)).to eq("Ended by a signal (systemd: signal, killed by signal 15)")
    expect(words("core-dump", "dumped", 11)).to eq("Stopped (systemd: core-dump, dumped core on signal 11)")
    expect(words("signal", "killed", nil)).to eq("Ended by a signal (systemd: signal, killed by a signal)")
    expect(words("exit-code", "exited", 1)).to eq("Exited with an error (systemd: exit-code, exit status 1)")
    expect(words("resources")).to eq("Stopped (systemd: resources)")
  end
end
