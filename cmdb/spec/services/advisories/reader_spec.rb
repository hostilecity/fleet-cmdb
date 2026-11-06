require "rails_helper"

# Reading OSV documents from a file, a directory, or a zip archive within size limits (P2-S10, NFR-1).
RSpec.describe Advisories::Reader do
  def entries(path, **options) = described_class.new(path, **options).to_a

  it "reads one file, every .json file under a directory (not symlinks), and every .json entry of an archive" do
    dir = osv_directory(osv_record(id: "DSA-1-1"))
    dir.join("nested").mkpath
    dir.join("nested/DSA-2-1.json").write("{}")
    dir.join("notes.txt").write("ignored")
    File.symlink(dir.join("DSA-1-1.json"), dir.join("link.json"))
    expect(entries(dir).map(&:location)).to eq(%w[DSA-1-1.json nested/DSA-2-1.json])
    expect(entries(dir.join("DSA-1-1.json")).sole).to have_attributes(location: "DSA-1-1.json", bytes: include("DSA-1-1"), problem: nil)

    zip = osv_zip("b/DSA-2-1.json" => "{}", "DSA-1-1.json" => "{}", "README" => "ignored")
    expect(entries(zip).map(&:location)).to eq(%w[DSA-1-1.json b/DSA-2-1.json])
  end

  it "recognises an archive by its first bytes as well as its name" do
    renamed = osv_directory.join("download.bin")
    FileUtils.cp(osv_zip("DSA-1-1.json" => "{}"), renamed)
    expect(entries(renamed).map(&:location)).to eq([ "DSA-1-1.json" ])
  end

  it "reports a document larger than the limit as a problem without reading it all, from a file or an archive" do
    stub_const("#{described_class}::MAX_RECORD_BYTES", 10)
    dir = osv_directory("x" * 11)
    expect(entries(dir).sole).to have_attributes(bytes: nil, problem: "is larger than 0 MiB")
    expect(entries(osv_zip("big.json" => "y" * 1000, "ok.json" => "{}")).map(&:problem)).to eq([ "is larger than 0 MiB", nil ])
  end

  it "refuses a path that is not a file or directory, an archive that is too large, and one with too many documents" do
    expect { entries(Pathname("/nonexistent/all.zip")) }.to raise_error(Advisories::Unreadable, "all.zip is not a file or directory")
    zip = osv_zip("a.json" => "{}", "b.json" => "{}")
    expect { entries(zip, max_archive_bytes: 10) }.to raise_error(Advisories::Unreadable, "all.zip is larger than 0 MiB")
    stub_const("#{described_class}::MAX_ENTRIES", 1)
    expect { entries(zip) }.to raise_error(Advisories::Unreadable, "all.zip has more than 1 JSON files")
    expect { entries(osv_directory("{}", "{}")) }.to raise_error(Advisories::Unreadable, /has more than 1 JSON files/)
  end

  it "reports an entry that cannot be decompressed as a problem" do
    zip = osv_zip("a.json" => "{}")
    allow_any_instance_of(Zip::Entry).to receive(:get_input_stream).and_raise(Zlib::DataError, "invalid stored block lengths")
    expect(entries(zip).sole).to have_attributes(location: "a.json", bytes: nil, problem: "could not be read from the archive")
  end

  it "is an Enumerable that can be read lazily" do
    expect(described_class.new(osv_directory("{}")).each).to be_an(Enumerator)
  end
end
