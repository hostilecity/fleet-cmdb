module FleetSimulator
  # Gives every simulated host a credential through the real agent API (FR-1.1, DEC-04, DEC-17):
  #
  #   token       a pending host and an enrollment token are created as `bin/rails hosts:create` creates them,
  #               and the token is redeemed at POST /api/v1/enroll
  #   onboarding  the installer's flow at POST /api/v1/onboarding, approved at once by the simulator's operator
  #               (Onboarding::Approve, as the approval page does), then collected at /api/v1/onboarding/token
  #
  # Credentials are kept in a private state file so a rerun brings the same hosts back rather than adding new
  # ones; a saved credential the server no longer accepts is replaced by re-enrolling the host.
  class Enroller
    class Failed < StandardError; end

    DEFAULT_STATE_FILE = Rails.root.join("tmp/fleet_simulator/credentials.json")

    def initialize(transport:, payloads:, via:, clock: Clock.new, out: $stdout, state_file: DEFAULT_STATE_FILE)
      @transport = transport
      @payloads = payloads
      @via = via
      @clock = clock
      @out = out
      @state_file = Pathname(state_file)
      @saved = load_state
    end

    def enroll_all(hosts)
      hosts.each do |host|
        credential = @saved[host.name]
        credential = enroll(host) unless credential && accepted?(host, credential)
        host.credential = credential
        host.host_id = Host.in_fleet.find_by!(name: host.name).id
        @saved[host.name] = credential
      end
      save_state
      hosts
    end

    def enroll(host)
      existing = Host.in_fleet.find_by(name: host.name)
      @via == "onboarding" ? onboard(host, existing) : redeem_token(host, existing)
    end

    private

    def attributes(host) = { name: host.name, hostname: host.hostname, tags: TAG, description: "Simulated by bin/simulate-fleet" }

    def accepted?(host, credential)
      @transport.post_api("/api/v1/heartbeat", @payloads.heartbeat(host, now: @clock.now), credential:).success?
    end

    def redeem_token(host, existing)
      token = if existing
        Enrollment::IssueToken.call(host: existing, actor: Audit::SYSTEM)
      else
        Enrollment::RegisterHost.call(attributes(host), actor: Audit::SYSTEM).last
      end
      expect!(host, "enroll", post("/api/v1/enroll", @payloads.enroll(host, token)), 201).json.fetch("credential")
    end

    def onboard(host, existing)
      started = expect!(host, "start onboarding", post("/api/v1/onboarding", @payloads.onboarding(host)), 201).json
      request = OnboardingRequest.latest_by_user_code(started.fetch("user_code"))
      Onboarding::Approve.call(request:, operator: OperatorCookie.operator, target_host: existing,
                               attributes: existing ? {} : attributes(host))
      body = { "schema_version" => 1, "agent_version" => @payloads.heartbeat(host, now: @clock.now)["agent_version"],
               "device_code" => started.fetch("device_code") }
      expect!(host, "collect onboarding", post("/api/v1/onboarding/token", body), 201).json.fetch("credential")
    end

    # Enrollment and onboarding are rate-limited per client address (DEC-08); wait as an agent would.
    def post(path, payload)
      loop do
        response = @transport.post_api(path, payload)
        return response unless response.retry_after

        @out.puts "  #{path} is rate-limited; waiting #{response.retry_after}s " \
                  "(start the server with FLEET_ENROLL_RATE_LIMIT_PER_MINUTE=100 FLEET_ONBOARDING_RATE_LIMIT_PER_MINUTE=100 to skip this)"
        @clock.sleep(response.retry_after)
      end
    end

    def expect!(host, step, response, status)
      return response if response.status == status

      raise Failed, "#{host.name}: #{step} answered #{response.status}: #{response.body.to_s.first(300)}"
    end

    def load_state
      @state_file.exist? ? JSON.parse(@state_file.read) : {}
    end

    def save_state
      @state_file.dirname.mkpath
      File.open(@state_file, File::WRONLY | File::CREAT | File::TRUNC, 0o600) { |f| f.write(JSON.pretty_generate(@saved)) }
    end
  end
end
