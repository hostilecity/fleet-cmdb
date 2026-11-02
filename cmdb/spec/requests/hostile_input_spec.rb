require "rails_helper"

# A compromised VM, or a careless operator, must not be able to inject markup into an operator's browser
# through any field (NFR-1, P1-S12, AC-1.7). Hostile values are stored directly in every agent-supplied and
# operator-supplied field, skipping the validations that normally reject most of them, so these specs prove the
# views escape on their own. Then every dashboard view that can show them is rendered and checked.
RSpec.describe "Hostile input in every view", type: :request do
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
    doc = Nokogiri::HTML(response.body)
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
    text = Nokogiri::HTML(response.body).at_css("body").text
    # Up to the first control character, which the HTML parser may normalise.
    expect(text).to include(value[/\A[^[:cntrl:]]+/].to_s.first(80)), "#{path} does not show the value as text"
  end

  let(:operator) { Operator.find_by!(email: "operator@example.com") }
  let(:hostile_operator) { create(:operator, name: HOSTILE) }

  before { sign_in_operator }

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

      # [path, whether a value from above is shown on the page as text]
      def pages
        [
          [ "/", true ], [ "/?q=#{CGI.escape(text.first(200))}", false ], [ "/?tag=#{CGI.escape(text.first(30))}&status=#{CGI.escape(text.first(30))}", false ],
          [ "/hosts/#{host.id}", true ], [ "/hosts/#{host.id}/edit", true ],
          [ "/hosts/#{host.id}/revoke", true ], [ "/hosts/#{host.id}/retire", true ], [ "/hosts/#{host.id}/reenroll", true ],
          [ "/audit", true ], [ "/audit?actor=#{CGI.escape(text.first(100))}&target=#{CGI.escape(text.first(100))}&action=#{CGI.escape(text.first(30))}", false ],
          [ "/audit?host_id=#{host.id}", true ],
          [ "/agents", false ], [ "/agents/install?version=#{CGI.escape(text.first(80))}", false ],
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
    shown = %w[hosts#index hosts#show hosts#edit hosts#new host_actions#confirm_revoke host_actions#confirm_retire host_actions#confirm_reenroll
               audit_entries#index agent_releases#index agent_installs#show approvals#index approvals#show failed_jobs#index settings#edit sessions#new]
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
