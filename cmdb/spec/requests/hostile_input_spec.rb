require "rails_helper"

# A compromised VM, or a careless operator, must not be able to inject markup into an operator's browser
# through any field (NFR-1, P1-S12, AC-1.7). Hostile values are stored directly in every agent-supplied and
# operator-supplied field, skipping the validations that normally reject most of them, so these specs prove the
# views escape on their own. Then every dashboard view that can show them is rendered and checked.
RSpec.describe "Hostile input in every view", :signed_in, type: :request do
  VARIANTS = {
    "script element and event handler" => HOSTILE,
    "attribute-breaking quotes" => %(" onmouseover="alert(1)" autofocus onfocus="alert(2)" x=' onclick='alert(3)),
    "tag-closing markup" => %("></td></tr></table><svg/onload=alert(1)><iframe src="javascript:alert(1)"></iframe><a href="javascript:alert(1)">x</a>),
    "control characters" => "line\u0001one\u0007\u001b[31mred\u007f\ttab\r\nline two",
    "bidirectional text" => "‮gpj.exe‭ evil ⁦hidden⁩‏؜",
    "a very long string" => "A" * 4_000
  }.freeze

  # The ways markup could get through, looked for in the parsed page: executable or external elements that
  # are not the layout's own, an attribute that runs code, or a link that does.
  def expect_no_injected_markup(path)
    doc = page
    expect(doc.css("script").reject { |script| script["nonce"] }).to be_empty, "unnonced script on #{path}"
    expect(doc.css("svg, iframe, object, embed, img[src='x']")).to be_empty, "injected element on #{path}"
    expect(doc.xpath("//@*[starts-with(name(), 'on')]").map(&:name)).to be_empty, "event handler attribute on #{path}"
    expect(doc.css("[href], [src], [action]").flat_map { |node| node.attribute_nodes.map(&:value) }.grep(/\A\s*(javascript|data|vbscript):/i)).to be_empty, "script URL on #{path}"
    expect(doc.css("[autofocus]")).to be_empty, "autofocus attribute on #{path}"
    expect(response.body).not_to match(/<script>alert|<svg|<iframe|<img src=x/i), "raw hostile markup in #{path}"
  end

  # Text from the VM or operator appears as text, character for character (so nothing is silently rewritten and
  # nothing is interpreted).
  def expect_shown_as_text(value, path)
    text = page.at_css("body").text
    # Up to the first control character, which the HTML parser may normalise.
    expect(text).to include(value[/\A[^[:cntrl:]]+/].to_s.first(80)), "#{path} does not show the value as text"
  end

  let(:hostile_operator) { create(:operator, name: HOSTILE) }

  # Error pages as production serves them, not Rails' detailed development page with its own scripts.
  around do |example|
    config = Rails.application.env_config
    config["action_dispatch.show_detailed_exceptions"] = false
    example.run
  ensure
    config["action_dispatch.show_detailed_exceptions"] = true
  end

  VARIANTS.each do |label, value|
    context "with #{label}" do
      let(:text) { value }

      # Strings that must fit a database column are cut to it; the cut value is still hostile.
      def fit(limit) = text.first(limit)

      let!(:host) do
        host, = enrolled_host
        host.update_columns(name: fit(100), hostname: fit(253), description: text.first(1_000), notes: text, tags: [ fit(32), fit(31) + "z" ],
                            agent_version: fit(64), reported_machine_id: fit(32), machine_id_mismatch_at: Time.current)
        host
      end

      let!(:inventory) do
        stable = {
          "hostname" => text, "kernel_version" => text, "architecture" => text, "cpu_model" => text, "cpu_cores" => 4,
          "memory_total_bytes" => 8_589_934_592, "boot_id" => text, "machine_id" => text, "agent_version" => text,
          "os" => { "id" => text, "version_id" => text, "pretty_name" => text },
          "disks" => [ { "mount" => text, "filesystem" => text, "size_bytes" => 34_359_738_368 } ],
          "network_interfaces" => [ { "name" => text, "primary" => true, "addresses" => [ text, "#{text}/24" ] } ]
        }
        volatile = { "memory_available_bytes" => 1, "uptime_seconds" => 60, "disk_free_bytes" => { text => 1 } }
        warnings = [ { "field" => "cpu_cores", "message" => text }, { "field" => "disks", "message" => text }, { "field" => text, "message" => text } ]
        changed = stable.merge("cpu_model" => "#{text} (changed)", "disks" => [ { "mount" => "#{text}2", "filesystem" => text, "size_bytes" => 1 } ])
        2.times.zip([ stable, changed ]).each_with_index do |(_, snapshot_stable), index|
          InventorySnapshot.create!(host:, stable: snapshot_stable, warnings:, stable_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid,
                                    collected_at: (2 - index).hours.ago, received_at: (2 - index).hours.ago)
        end
        HostInventory.create!(host:, stable: changed, volatile:, warnings:, stable_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid,
                              schema_version: 1, collected_at: 1.minute.ago, received_at: 1.minute.ago)
      end

      let!(:audit) do
        AuditEntry.create!(actor_type: "operator", actor_id: hostile_operator.id, action: Audit::Actions::HOST_EDITED, target_type: "Host", target_id: host.id,
                           changeset: { "name" => [ text, text ], "hostname" => [ text, text ], "description" => [ text, nil ], "notes" => [ nil, text ],
                                        text => [ text, text ], "tags" => [ [ text ], [ text, "x" ] ] },
                           request_id: text.first(200), occurred_at: Time.current)
      end

      let!(:onboarding) do
        started = start_onboarding(client_ip: "192.0.2.77")
        started.record.update_columns(hostname: fit(253), machine_id: fit(32), agent_version: fit(64),
                                      os: { "id" => text, "version_id" => text, "pretty_name" => text })
        started.record
      end

      let!(:failure) { failed_job(class_name: "Hostile#{SecureRandom.hex(2)}Job", queue: "default", error_class: "Error", message: text) }

      # A halted rollout whose host, operator, halt reason, versions, canary tag, and reported reason are all hostile
      # (P1-D09). Rows are written directly, as with the host above, so the views are tested on their own.
      let!(:rollout) do
        release = release_for_rollout("0.3.0")
        now = Time.current
        rollout = Rollout.create!(agent_release: release, started_by: hostile_operator, canary_host_ids: [ host.id ], canary_tag: fit(32),
                                  state: "halted", halt_reason: text, halted_at: now, started_at: now, stage_opened_at: now)
        RolloutHost.create!(rollout:, host:, stage: 0, state: "rolled_back", offer_at: now, offered_at: now, resolved_at: now, from_version: fit(64))
        AgentUpdate.create!(host:, rollout:, report_id: SecureRandom.uuid, version: "0.3.0", outcome: "rolled_back", reason: text,
                            reported_agent_version: fit(64), occurred_at: now, received_at: now)
        rollout
      end

      # Config facts, CIS-aligned results, and result changes with hostile values, reasons, and fact keys (P2-D02).
      let!(:config) do
        facts = ->(value) do
          { "sshd.banner" => { "state" => "ok", "value" => value, "reason" => nil }, "sshd.maxauthtries" => { "state" => "unreadable", "value" => nil, "reason" => text },
            "users.login" => { "state" => "ok", "value" => [ text, value ], "reason" => nil }, text.first(200) => { "state" => "missing", "value" => nil, "reason" => text } }
        end
        older, newer = [ text, "#{text} (changed)" ].each_with_index.map do |value, index|
          ConfigSnapshot.create!(host:, facts: facts.(value), content_hash: SecureRandom.hex(32), manifest_version: 1, report_id: SecureRandom.uuid,
                                 collected_at: (2 - index).hours.ago, received_at: (2 - index).hours.ago)
        end
        HostConfig.create!(host:, facts: newer.facts, content_hash: newer.content_hash, manifest_version: 1, report_id: newer.report_id, schema_version: 1,
                           collected_at: newer.collected_at, received_at: newer.received_at)
        allow(CisEvaluationJob).to receive(:perform_later)
        rule, = define_cis_rules(cis_rule_hash(key: "ssh-banner", title: fit(200), reference: fit(128), fact: "sshd.banner", condition: { "eq" => text.first(100) }, remediation: text))
        [ older, newer ].each_with_index do |snapshot, index|
          CisResultChange.create!(host:, cis_rule: rule, cis_rule_version: rule.current_version, config_snapshot: snapshot, from_result: index.zero? ? nil : "pass",
                                  to_result: "fail", observed: text, reason: nil, occurred_at: snapshot.received_at + 1.second)
        end
        CisResult.create!(host:, cis_rule: rule, cis_rule_version: rule.current_version, config_snapshot: newer, result: "fail", observed: text,
                          evaluated_at: Time.current, changed_at: Time.current)
      end

      # A package set, two package snapshots, and the host's packages, with hostile names, versions, and sources (P2-D03).
      let!(:packages) do
        rows = ->(suffix) { [ [ fit(128), fit(200) + suffix, fit(128) ], [ "#{fit(100)}-2", "1.0", nil ] ].map { |name, version, source| [ name, fit(32), version, source ] } }
        [ "", "+1" ].each_with_index do |suffix, index|
          PackageSnapshot.create!(host:, manager: "dpkg", package_count: 2, content_hash: SecureRandom.hex(32), packages: rows.(suffix), report_id: SecureRandom.uuid,
                                  warnings: [ { "field" => text, "message" => text } ], collected_at: (2 - index).hours.ago, received_at: (2 - index).hours.ago)
        end
        HostPackageSet.create!(host:, manager: "dpkg", package_count: 2, content_hash: SecureRandom.hex(32), report_id: SecureRandom.uuid, schema_version: 1,
                               collected_at: 1.hour.ago, received_at: 1.hour.ago)
        HostPackage.insert_all(rows.("+1").map { |name, architecture, version, source| { host_id: host.id, name:, architecture:, version:, source: } })
      end

      # A vulnerability finding whose advisory and package text are hostile, with a script URL as its reference, and a
      # package the matcher could not check (P2-D04).
      let!(:finding) do
        advisory = Advisory.create!(advisory_id: fit(128), source: fit(256), summary: fit(512), severity: "high", reference_url: "javascript:alert(1)//#{fit(100)}",
                                    modified_at: Time.current)
        HostVulnerabilityEvaluation.create!(host:, ecosystem: "Debian:13", state: "evaluated", evaluated_at: Time.current, not_evaluated_count: 1,
                                            not_evaluated: [ { "package" => text, "architecture" => text, "version" => text, "source" => text, "advisory" => text, "reason" => text } ])
        VulnerabilityFinding.create!(host:, advisory:, package: fit(128), architecture: fit(32), source: fit(128), ecosystem: "Debian:13", installed_version: fit(256),
                                     fixed_version: fit(256), state: "reopened", first_seen_at: 2.hours.ago, resolved_at: 1.hour.ago, reopened_at: Time.current)
      end

      # [path, whether a value from above is shown on the page as text]
      def pages
        [
          [ "/", true ], [ "/?q=#{CGI.escape(text.first(200))}", false ], [ "/?tag=#{CGI.escape(text.first(30))}&status=#{CGI.escape(text.first(30))}", false ],
          [ "/compliance", true ], [ "/compliance?tag=#{CGI.escape(text.first(32))}", false ],
          [ "/compliance?q=#{CGI.escape(text.first(200))}&tag=#{CGI.escape(text.first(30))}&status=#{CGI.escape(text.first(30))}&cis=#{CGI.escape(text.first(30))}" \
            "&vuln=#{CGI.escape(text.first(30))}&sort=#{CGI.escape(text.first(30))}&page=#{CGI.escape(text.first(30))}", false ],
          [ "/hosts/#{host.id}", true ], [ "/hosts/#{host.id}/edit", true ],
          [ "/hosts/#{host.id}/config?result=all&facts=all&history=all", true ], [ "/hosts/#{host.id}/config/compare", true ],
          [ "/hosts/#{host.id}/config?q=#{CGI.escape(text.first(100))}&severity=#{CGI.escape(text.first(30))}&result=#{CGI.escape(text.first(30))}", false ],
          [ "/hosts/#{host.id}/config/compare?from=#{CGI.escape(text.first(30))}&to=#{CGI.escape(text.first(30))}", false ],
          [ "/hosts/#{host.id}/packages", true ], [ "/hosts/#{host.id}/packages/compare", true ],
          [ "/hosts/#{host.id}/packages?q=#{CGI.escape(text.first(100))}&arch=#{CGI.escape(text.first(30))}&sort=#{CGI.escape(text.first(30))}&page=#{CGI.escape(text.first(30))}", false ],
          [ "/hosts/#{host.id}/packages/compare?kind=#{CGI.escape(text.first(30))}", true ],
          [ "/hosts/#{host.id}/vulnerabilities?state=all", true ], [ "/hosts/#{host.id}/vulnerabilities/package?package=#{CGI.escape(text.first(128))}", true ],
          [ "/hosts/#{host.id}/vulnerabilities?q=#{CGI.escape(text.first(100))}&severity=#{CGI.escape(text.first(30))}&state=#{CGI.escape(text.first(30))}", false ],
          [ "/hosts/#{host.id}/revoke", true ], [ "/hosts/#{host.id}/retire", true ], [ "/hosts/#{host.id}/reenroll", true ],
          [ "/audit", true ], [ "/audit?actor=#{CGI.escape(text.first(100))}&target=#{CGI.escape(text.first(100))}&action=#{CGI.escape(text.first(30))}", false ],
          [ "/audit?host_id=#{host.id}", true ],
          [ "/agents", true ], [ "/agents/install?version=#{CGI.escape(text.first(80))}", false ],
          [ "/agents/rollouts/#{rollout.id}/resume", true ], [ "/agents/rollouts/#{rollout.id}/halt", false ],
          [ "/agents/rollouts/#{rollout.id}/advance", false ], [ "/agents/rollouts/#{rollout.id}/cancel", false ],
          [ "/agents/rollouts/new?release=#{CGI.escape(text.first(80))}&canary_tag=#{CGI.escape(text.first(32))}&stages=#{CGI.escape(text.first(100))}", false ],
          [ "/onboard", true ], [ "/onboard/#{onboarding.user_code}", true ], [ "/onboard/#{CGI.escape(text.first(30))}", false ],
          [ "/jobs/failed", true ], [ "/settings", false ], [ "/sign_in?return_to=#{CGI.escape(text.first(100))}", false ]
        ]
      end

      it "renders every view with the value escaped" do
        pages.each do |path, shown|
          get path
          expect(response.status).to be_between(200, 499), "GET #{path} -> #{response.status}"
          if response.status == 404
            # Rails' static error page: it has its own markup and must not echo the request.
            expect(response.body).not_to include(CGI.escapeHTML(text.first(30)), text.first(30)), "404 for #{path} echoes the request"
          else
            expect_no_injected_markup(path)
            expect_shown_as_text(text, path) if shown && response.successful?
          end
        end
      end

      it "renders the fleet list, the host page, and the audit log with the host's values escaped in re-rendered form errors" do
        patch "/hosts/#{host.id}", params: { host: { name: "", hostname: text.first(253), description: text.first(1_000), notes: text.first(2_000), tags: text.first(100) } }

        expect(response).to have_http_status(:unprocessable_content)
        expect_no_injected_markup("PATCH /hosts/:id")

        post "/hosts", params: { host: { name: text.first(100), hostname: "", description: text.first(1_000), notes: text.first(2_000), tags: text.first(100) } }
        expect(response).to have_http_status(:unprocessable_content)
        expect_no_injected_markup("POST /hosts")
      end

      it "escapes the rollout start confirmation, the start form's choices, and a finished rollout (P1-D09)" do
        Rollout.where(id: rollout.id).update_all(state: "cancelled", open_slot: nil, finished_at: Time.current)
        canary, = host_running("0.2.0")
        canary.update_columns(name: fit(100), hostname: fit(253), tags: [ fit(32) ])

        get "/agents/rollouts/new", params: { release: "0.3.0", canary_tag: fit(32), canary_host_ids: [ canary.id.to_s ], stages: "25, 100" }
        expect(response).to have_http_status(:ok)
        expect_no_injected_markup("/agents/rollouts/new")
        expect_shown_as_text(text, "/agents/rollouts/new")

        post "/agents/rollouts", params: { release: "0.3.0", canary_tag: fit(32), stages: text.first(100) }
        expect(response).to have_http_status(:unprocessable_content)
        expect_no_injected_markup("POST /agents/rollouts")

        [ "/agents", "/hosts/#{host.id}" ].each do |path|
          get path
          expect_no_injected_markup(path)
          expect_shown_as_text(text, path)
        end
      end

      it "escapes a retired host's name and the retirement notice" do
        Host.where(id: host.id).update_all(enrollment_state: "retired") # the transition methods validate; a stored row may not pass them

        get "/hosts/#{host.id}"
        expect_no_injected_markup("/hosts/:id (retired)")

        get "/audit?host_id=#{host.id}"
        expect_no_injected_markup("/audit (retired host)")
      end
    end
  end

  it "isolates the bidirectional context of every element that shows stored text, so an override cannot reorder its neighbours" do
    css = Rails.root.join("app/assets/stylesheets/application.css").read
    expect(css).to match(/main :is\([^)]*\bdd\b[^)]*\btd\b[^)]*\) \{ unicode-bidi: isolate; \}/)
  end

  it "names the same views the dashboard has, so a new one cannot be forgotten here" do
    shown = %w[hosts#index hosts#show hosts#edit hosts#new compliance#index host_configs#show host_configs#compare host_packages#show host_packages#compare
               host_vulnerabilities#show host_vulnerabilities#package
               host_actions#confirm_revoke host_actions#confirm_retire host_actions#confirm_reenroll
               audit_entries#index agent_releases#index agent_installs#show approvals#index approvals#show failed_jobs#index settings#edit sessions#new
               rollouts#new rollouts#confirm_advance rollouts#confirm_halt rollouts#confirm_resume rollouts#confirm_cancel]
    views = Rails.application.routes.routes.filter_map do |route|
      controller, action = route.defaults.values_at(:controller, :action)
      next unless route.verb == "GET" && controller && !controller.start_with?("api/", "rails/") && controller != "health"

      "#{controller}##{action}"
    end
    # Pages that do not render stored text: sign-in and OAuth plumbing, the live-update socket, and the token page (a POST result).
    plumbing = %w[sessions#create sessions#failure action_cable#serve]
    expect(views - shown - plumbing).to eq([]), "views not covered by the hostile-input spec: #{views - shown - plumbing}"
  end
end
