require "rqrcode_core"

module SecondFactors
  # Draws a QR code as inline SVG on the server (P3-S09, Q26): no third-party service and no script. The page's
  # CSP allows no style attributes, so the SVG uses presentation attributes only. One path of horizontal runs keeps
  # it small. The text it encodes is the key, so the page that shows it is never cached.
  module QrCode
    QUIET_ZONE = 4 # modules of white border, as the QR specification asks

    module_function

    def svg(text, label:)
      qr = RQRCodeCore::QRCode.new(text, level: :m)
      size = qr.module_count + 2 * QUIET_ZONE
      runs = (0...qr.module_count).flat_map do |row|
        (0...qr.module_count).chunk_while { |a, b| b == a + 1 && qr.checked?(row, a) == qr.checked?(row, b) }
                             .select { |cols| qr.checked?(row, cols.first) }
                             .map { |cols| "M#{cols.first + QUIET_ZONE} #{row + QUIET_ZONE}h#{cols.size}v1h-#{cols.size}z" }
      end
      ActiveSupport::SafeBuffer.new(
        %(<svg class="qr" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 #{size} #{size}" role="img" aria-label="#{ERB::Util.html_escape(label)}" shape-rendering="crispEdges">) +
        %(<rect width="#{size}" height="#{size}" fill="#fff"/><path fill="#000" d="#{runs.join}"/></svg>)
      )
    end
  end
end
