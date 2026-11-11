require "rails_helper"

# The QR code is drawn by the server as inline SVG (P3-S09, Q26): no third-party service, no style attributes.
RSpec.describe SecondFactors::QrCode do
  it "draws the modules of the text's QR code as one path, with a quiet zone and no style attribute" do
    text = "otpauth://totp/Fleet%20CMDB%3Aoperator%40example.com?secret=JBSWY3DPEHPK3PXP"
    svg = Nokogiri::XML(described_class.svg(text, label: "QR <code>"))
    root = svg.root
    qr = RQRCodeCore::QRCode.new(text, level: :m)
    size = qr.module_count + 8
    expect(root.name).to eq("svg")
    expect(root["viewBox"]).to eq("0 0 #{size} #{size}")
    expect(root["aria-label"]).to eq("QR <code>")
    expect(svg.xpath("//@style")).to be_empty

    # Painting the path's runs back onto a grid gives the QR matrix exactly.
    grid = Array.new(qr.module_count) { Array.new(qr.module_count, false) }
    svg.at_xpath("//*[local-name()='path']")["d"].scan(/M(\d+) (\d+)h(\d+)v1h-\3z/) do |x, y, width|
      width.to_i.times { |i| grid[y.to_i - 4][x.to_i - 4 + i] = true }
    end
    expect(grid).to eq(Array.new(qr.module_count) { |row| Array.new(qr.module_count) { |col| qr.checked?(row, col) } })
  end
end
