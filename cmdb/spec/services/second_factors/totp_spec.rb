require "rails_helper"

# RFC 6238 and RFC 4226 test vectors, and the parameters the owner chose (P3-S09, Q26, Q30).
RSpec.describe SecondFactors::Totp do
  # The RFCs' shared secret, the ASCII bytes "12345678901234567890".
  let(:rfc_secret) { described_class.base32_encode("12345678901234567890") }

  it "matches RFC 4226's HOTP values (6 digits, SHA-1)" do
    expected = %w[755224 287082 359152 969429 338314 254676 287922 162583 399871 520489]
    expect((0..9).map { |counter| described_class.code_at_step(rfc_secret, counter) }).to eq(expected)
  end

  it "matches RFC 6238's TOTP values for SHA-1 (8 digits, 30-second steps)" do
    { 59 => "94287082", 1_111_111_109 => "07081804", 1_111_111_111 => "14050471", 1_234_567_890 => "89005924",
      2_000_000_000 => "69279037", 20_000_000_000 => "65353130" }.each do |time, code|
      expect(described_class.code_at_step(rfc_secret, described_class.step_at(Time.zone.at(time)), digits: 8)).to eq(code), "T=#{time}"
    end
  end

  it "makes 160-bit keys as unpadded base32 that decodes back to the same bytes" do
    secret = described_class.generate_secret
    expect(secret).to match(/\A[A-Z2-7]{32}\z/)
    expect(described_class.base32_decode(secret).bytesize).to eq(20)
    expect(described_class.base32_encode(described_class.base32_decode(secret))).to eq(secret)
    expect(described_class.base32_decode("mzxw 6ytb oi======")).to eq("foobar")
    expect { described_class.base32_decode("not base32!") }.to raise_error(ArgumentError)
    expect(described_class.generate_secret).not_to eq(secret)
  end

  it "accepts the current step and one either side, and says which matched" do
    now = Time.zone.at(1_700_000_000)
    step = described_class.step_at(now)
    secret = described_class.generate_secret
    code = ->(offset) { described_class.code_at_step(secret, step + offset) }
    expect(described_class.matching_step(secret, code.(0), now:)).to eq(step)
    expect(described_class.matching_step(secret, code.(-1), now:)).to eq(step - 1)
    expect(described_class.matching_step(secret, code.(1), now:)).to eq(step + 1)
    expect(described_class.matching_step(secret, code.(2), now:)).to be_nil
    expect(described_class.matching_step(secret, code.(-2), now:)).to be_nil
    expect(described_class.matching_step(secret, "", now:)).to be_nil
  end

  it "compares in constant time, every candidate step" do
    allow(ActiveSupport::SecurityUtils).to receive(:secure_compare).and_call_original
    described_class.matching_step(described_class.generate_secret, "000000")
    expect(ActiveSupport::SecurityUtils).to have_received(:secure_compare).exactly(3).times
  end

  it "builds the otpauth URI authenticator apps scan, and groups the key in fours" do
    uri = described_class.provisioning_uri("JBSWY3DPEHPK3PXP", account: "operator@example.com")
    expect(uri).to eq("otpauth://totp/Fleet%20CMDB%3Aoperator%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Fleet%20CMDB&algorithm=SHA1&digits=6&period=30")
    expect(described_class.display_secret("JBSWY3DPEHPK3PXPAB")).to eq("JBSW Y3DP EHPK 3PXP AB")
  end
end
