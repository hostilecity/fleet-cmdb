# Every docs/api example for an endpoint's request schema, sent to the endpoint (NFR-5): valid examples get the
# endpoint's success (`accepted`: a status, or [status, code] for a valid body the endpoint refuses), invalid
# ones 400 validation_failed. The including group defines submit_example(data, valid:) to send one.
RSpec.shared_examples "the docs/api contract examples" do |schema_name, accepted:|
  ApiContract.examples_for(schema_name).each do |example|
    it "#{example.kind == 'valid' ? 'accepts' : 'rejects'} #{schema_name} #{example.name}" do
      submit_example(example.data, valid: example.kind == "valid")
      if example.kind == "invalid"
        expect_error(:bad_request, "validation_failed")
      elsif accepted.is_a?(Array)
        expect_error(*accepted)
      else
        expect(response).to have_http_status(accepted), "#{example.name}: #{response.body}"
      end
    end
  end
end
