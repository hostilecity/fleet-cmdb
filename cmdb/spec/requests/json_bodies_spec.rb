require "rails_helper"

# How request bodies with long numbers are handled (NFR-1). JSON.parse makes a long integer a Bignum, which costs time
# that grows faster than its length and holds the interpreter lock, and logging it costs more. So the dashboard never
# parses JSON bodies (config/initializers/request_parameters.rb), and the agent API refuses a number of more than
# Api::V1::BaseController::MAX_NUMBER_DIGITS digits before it parses the body.
RSpec.describe "JSON request bodies", type: :request do
  let(:long_number) { "9" * 200 }

  describe "on the dashboard" do
    let(:json_headers) { { "CONTENT_TYPE" => "application/json" } }

    it "never parses a signed-out JSON POST, and sends it to sign in" do
      expect(ActiveSupport::JSON).not_to receive(:decode)
      expect(JSON).not_to receive(:parse)
      post "/onboard", params: %({"code":#{long_number}}), headers: json_headers
      expect(response).to redirect_to("/sign_in")
    end

    it "never parses one while drawing a 404, as production does" do
      config = Rails.application.env_config
      saved = config.slice("action_dispatch.show_exceptions", "action_dispatch.show_detailed_exceptions")
      config.merge!("action_dispatch.show_exceptions" => :all, "action_dispatch.show_detailed_exceptions" => false)
      expect(ActiveSupport::JSON).not_to receive(:decode)
      expect(JSON).not_to receive(:parse)
      post "/privacy", params: %({"a":#{long_number}}), headers: json_headers
      expect(response).to have_http_status(:not_found)
    ensure
      config.merge!(saved)
    end

    it "takes nothing from a JSON body, even signed in: only forms are read" do
      sign_in_operator
      before = Setting.liveness_thresholds
      patch "/settings", params: { online_minutes: "5", stale_minutes: "20" }.to_json, headers: json_headers
      expect(response).to have_http_status(:unprocessable_content)
      expect(Setting.liveness_thresholds).to eq(before)
      patch "/settings", params: { online_minutes: "5", stale_minutes: "20" }
      expect(Setting.liveness_thresholds).to eq(online: 5.minutes, stale: 20.minutes)
    end

    it "refuses a JSON POST for its missing CSRF token, even when the JSON carries one" do
      sign_in_operator
      ActionController::Base.allow_forgery_protection = true
      get "/settings"
      token = page.at_css('main form[action="/settings"] input[name="authenticity_token"]')["value"]
      patch "/settings", params: { authenticity_token: token, online_minutes: "5", stale_minutes: "20" }.to_json, headers: json_headers
      expect(response).to have_http_status(:unprocessable_content)
      patch "/settings", params: { authenticity_token: token, online_minutes: "5", stale_minutes: "20" }
      expect(response).to redirect_to("/settings")
    ensure
      ActionController::Base.allow_forgery_protection = false
    end
  end

  describe "on the agent API", :agent_host do
    let(:enrolled) { enrolled_host }
    let(:credential) { enrolled.last }
    let(:heartbeat) { JSON.parse(Rails.root.join("../docs/api/examples/v1/heartbeat.request/valid/typical.json").read) }
    let(:limit) { Api::V1::BaseController::MAX_NUMBER_DIGITS }

    # The heartbeat as JSON text with `extra` added as an undeclared field, written as it is.
    def heartbeat_with(extra) = heartbeat.to_json.delete_suffix("}") + %(,"extra":#{extra}})

    # Fails if a body with a run of more than `limit` digits reaches JSON.parse. Other parsing (stored JSON) goes on.
    def expect_long_number_never_parsed
      allow(JSON).to receive(:parse).and_call_original
      expect(JSON).not_to receive(:parse).with(a_string_matching(/[0-9]{#{limit + 1}}/), any_args)
    end

    it "refuses a number longer than the limit before parsing the body" do
      body = heartbeat_with(long_number)
      expect_long_number_never_parsed
      post_api "/api/v1/heartbeat", body, credential
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "message")).to eq("The request body has a number longer than #{limit} digits.")
    end

    it "refuses one digit over the limit, in an array, as a fraction, or in an exponent, and takes the limit itself" do
      [ "9" * (limit + 1), "[1,2,#{'9' * (limit + 1)}]", "1.#{'0' * limit}1", "1e#{'9' * (limit + 1)}", "-#{'9' * (limit + 1)}" ].each do |number|
        post_api "/api/v1/heartbeat", heartbeat_with(number), credential
        expect(json.dig("error", "message")).to eq("The request body has a number longer than #{limit} digits."), number
      end
      post_api "/api/v1/heartbeat", heartbeat_with("9" * limit), credential
      expect(response).to have_http_status(:ok)
    end

    it "does not count digits inside strings, keys, or escaped quotes" do
      [ %("#{long_number}"), %("a \\" #{long_number}"), %({"#{long_number}":1}), %(["\\\\", "#{long_number}\\\\"]) ].each do |value|
        post_api "/api/v1/heartbeat", heartbeat_with(value), credential
        expect(response).to have_http_status(:ok), value
      end
    end

    it "refuses a long number in a gzip body that expands within the limit" do
      body = ActiveSupport::Gzip.compress(%({"schema_version":1,"packages":[],"n":#{'9' * 3_000_000}}))
      expect(body.bytesize).to be < 64.kilobytes
      credential
      expect_long_number_never_parsed
      post_api "/api/v1/reports/packages", body, credential, headers: { "Content-Encoding" => "gzip" }
      expect(json.dig("error", "message")).to eq("The request body has a number longer than #{limit} digits.")
    end

    it "still refuses a body that is not JSON" do
      post_api "/api/v1/heartbeat", "#{long_number}-not-json", credential
      expect_error(:bad_request, "validation_failed")
    end

    it "scans invalid UTF-8 as bytes and leaves its handling to the parser and the endpoint, as before" do
      post_api "/api/v1/heartbeat", heartbeat_with(%("\xFF #{long_number}")).b, credential
      expect(response).to have_http_status(:ok)
      post_api "/api/v1/heartbeat", heartbeat_with("[\"\xFF\", #{long_number}]").b, credential
      expect(json.dig("error", "message")).to eq("The request body has a number longer than #{limit} digits.")
    end
  end
end
