require "rails_helper"

# Onboarding services (P1-ONBOARD, DEC-17): the decisions the dashboard will call, and the edge cases of
# starting and collecting that the request spec does not reach.
RSpec.describe "Onboarding services" do
  let(:operator) { create(:operator) }
  let(:started) { start_onboarding }
  let(:request) { started.record }

  describe Onboarding::Approve do
    it "rejects invalid host fields without deciding, so the operator can correct them" do
      expect { described_class.call(request:, operator:, attributes: { name: "", tags: "bad tag!" }) }.to raise_error(ActiveRecord::RecordInvalid)
      expect(request.reload.state).to eq("open")
      expect(AuditEntry.for_target(request)).to be_empty
    end

    it "requires a hostname when the VM could not report one" do
      blind = start_onboarding(hostname: nil, client_ip: "192.0.2.11").record
      expect { described_class.call(request: blind, operator:, attributes: { name: "VM" }) }.to raise_error(ActiveRecord::RecordInvalid, /Hostname/)
      described_class.call(request: blind, operator:, attributes: { name: "VM", hostname: "vm-02.example.lan" })
      expect(blind.reload.host_attributes).to include("hostname" => "vm-02.example.lan")
    end

    it "stores the normalised fields the host will be created with" do
      described_class.call(request:, operator:, attributes: { name: "  Media   server ", tags: "Media, LAB", hostname: "" })
      expect(request.reload.host_attributes).to eq("name" => "Media server", "hostname" => "vm-01.example.lan", "description" => nil, "notes" => nil, "tags" => %w[media lab])
    end

    it "cannot decide a request twice, or one that expired" do
      described_class.call(request:, operator:, attributes: { name: "VM" })
      expect { described_class.call(request:, operator:, attributes: { name: "VM" }) }.to raise_error(Onboarding::NotDecidable)
      expect { Onboarding::Reject.call(request:, operator:) }.to raise_error(Onboarding::NotDecidable)

      late = start_onboarding(client_ip: "192.0.2.11").record
      travel_to(11.minutes.from_now) do
        expect { described_class.call(request: late, operator:, attributes: { name: "VM" }) }.to raise_error(Onboarding::NotDecidable)
      end
    end

    it "refuses to re-enroll a retired host" do
      host = create(:host, :retired)
      expect { described_class.call(request:, operator:, target_host: host) }.to raise_error(Onboarding::Approve::TargetRetired)
      expect(request.reload.state).to eq("open")
    end

    it "lets a pre-registered (pending) host be enrolled by onboarding instead of its token" do
      host, token = Enrollment::RegisterHost.call({ name: "Lab", hostname: "vm-01.example.lan" }, actor: Audit::SYSTEM)
      described_class.call(request:, operator:, target_host: host)
      expect(EnrollmentToken.redeemable.where(host:)).to be_empty
      expect(token).to be_present
      expect(collect_onboarding(started.device_code).host).to eq(host)
      expect(host.reload.enrollment_state).to eq("active")
    end
  end

  describe Onboarding::Collect do
    it "starts again when an approval names a host between reading and locking the request" do
      host, = enrolled_host(hostname: "vm-01.example.lan")
      allow(OnboardingRequest).to receive(:find_by_device_code).and_wrap_original do |original, *args|
        found = original.call(*args)
        if found.state == "open" # the operator approves as a re-enrollment just after the unlocked read
          Onboarding::Approve.call(request: OnboardingRequest.find(found.id), operator:, target_host: host)
        end
        found
      end
      result = collect_onboarding(started.device_code)
      expect(result.status).to eq(:approved)
      expect(result.host).to eq(host)
      expect(OnboardingRequest).to have_received(:find_by_device_code).twice
    end

    it "gives up with an internal error rather than retrying forever if the request keeps changing" do
      other = create(:host)
      allow(OnboardingRequest).to receive(:find_by_device_code) { request.dup.tap { |r| r.id = request.id; r.host_id = other.id } }
      expect { collect_onboarding(started.device_code) }.to raise_error(AgentApi::InternalError)
      expect(OnboardingRequest).to have_received(:find_by_device_code).exactly(Onboarding::Collect::ATTEMPTS).times
    end

    it "redacts the credential when inspected" do
      described_class # loaded
      Onboarding::Approve.call(request:, operator:, attributes: { name: "VM" })
      result = collect_onboarding(started.device_code)
      expect(result.inspect).not_to include(result.credential)
      expect(started.inspect).not_to include(started.device_code)
    end
  end

  describe Onboarding::Start do
    it "retries a user code that an open request already holds" do
      taken = request.user_code
      allow(OnboardingRequest).to receive(:generate_user_code).and_return(taken, taken, "BCDF-GHJK")
      expect(start_onboarding(client_ip: "192.0.2.11").record.user_code).to eq("BCDF-GHJK")
    end

    it "gives up after repeated collisions rather than looping" do
      taken = request.user_code
      allow(OnboardingRequest).to receive(:generate_user_code).and_return(taken)
      expect { start_onboarding(client_ip: "192.0.2.11") }.to raise_error(ActiveRecord::RecordNotUnique)
      expect(OnboardingRequest).to have_received(:generate_user_code).exactly(Onboarding::Start::USER_CODE_ATTEMPTS).times
    end

    it "only issues user codes from the unambiguous alphabet" do
      codes = Array.new(200) { OnboardingRequest.generate_user_code }
      expect(codes).to all(match(OnboardingRequest::USER_CODE_FORMAT))
      expect(codes.join.delete("-").chars.uniq.size).to be > 10
    end
  end

  describe "finding a request by user code" do
    it "accepts the code as typed: any case, with or without the dash, only while it awaits a decision" do
      code = request.user_code
      [ code, code.downcase, code.delete("-"), " #{code.downcase.tr('-', ' ')} " ].each do |typed|
        expect(OnboardingRequest.find_awaiting_by_user_code(typed)).to eq(request)
      end
      expect(OnboardingRequest.find_awaiting_by_user_code("AAAA-AAAA")).to be_nil
      expect(OnboardingRequest.find_awaiting_by_user_code(nil)).to be_nil
      Onboarding::Reject.call(request:, operator:)
      expect(OnboardingRequest.find_awaiting_by_user_code(code)).to be_nil
    end
  end

  describe OnboardingPruneJob do
    it "removes requests a day after they expired, whatever their state" do
      old = request
      Onboarding::Reject.call(request: old, operator:)
      fresh = travel_to(23.hours.from_now) { start_onboarding(client_ip: "192.0.2.11").record } # expired, but not a day ago
      travel_to(1.day.from_now + 11.minutes) { expect(described_class.perform_now).to eq(1) }
      expect(OnboardingRequest.where(id: [ old.id, fresh.id ]).pluck(:id)).to eq([ fresh.id ])
    end
  end
end
