require "rails_helper"

# Why a host's findings can or cannot be escalated by N5 now (HostApplicability::ListenerSource.coverage), which the host
# tab's Needs attention section says (VT-HOST-TAB #260), read in one query from host_applicability as #268 writes it.
RSpec.describe HostApplicability::ListenerSource do
  let(:host) { enrolled_host.first }
  let(:now) { Time.utc(2026, 11, 22, 12) }
  let(:listener) { [ { "listener" => "openssh-server", "service" => "ssh.service", "class" => "network", "sockets" => [ "0.0.0.0:22/tcp" ], "packages" => [ "libc6" ] } ] }

  def row(**attributes) = HostApplicability.create!(host_id: host.id, **attributes)

  def coverage = described_class.coverage(host.id, now:)

  it "names each case: nothing reported, the scan off or failed, a kernel before 5.14, evidence expired, or known" do
    expect(coverage).to eq(:not_reported) # no row: an agent that predates #258
    applicability = row(reboot_required: true) # an inventory only: no in-use report yet
    expect(coverage).to eq(:not_reported)
    applicability.update!(in_use_reported: true, library_scan: "off")
    expect(coverage).to eq(:scan_off)
    applicability.update!(library_scan: "failed")
    expect(coverage).to eq(:scan_failed)
    applicability.update!(library_scan: "ran", loaded_by_listeners: nil, library_scan_received_at: now - 1.hour)
    expect(coverage).to eq(:kernel_too_old)
    applicability.update!(loaded_by_listeners: listener, library_scan_received_at: now - VulnerabilityTriage::LISTENER_FRESH)
    expect(coverage).to eq(:expired)
    applicability.update!(library_scan_received_at: now - 1.hour)
    expect(coverage).to eq(:known)
    applicability.update!(loaded_by_listeners: []) # known, and nothing listens
    expect(coverage).to eq(:known)
  end

  it "is one query whatever the host's findings" do
    row(in_use_reported: true, library_scan: "ran", loaded_by_listeners: listener, library_scan_received_at: now)
    expect(count_queries { coverage }).to eq(1)
  end

  it "is what the triage hook reports for the tab, and :unread with no source" do
    row(in_use_reported: true, library_scan: "off")
    expect(VulnerabilityTriage::HostFacts.listener_coverage(host.id, now:)).to eq(:scan_off)
    allow(VulnerabilityTriage::HostFacts).to receive(:listener_source).and_return(nil)
    expect(VulnerabilityTriage::HostFacts.listener_coverage(host.id, now:)).to eq(:unread)
  end
end
