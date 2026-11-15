require "rails_helper"

# Thread and process counts for Puma and Solid Queue, and the database pool that follows them (#198, S-7).
RSpec.describe ProcessSizing do
  it "defaults to one Puma process's 3 threads, one job worker of 3 threads, one realtime thread, 2 evaluation threads, and a pool of 5" do
    expect(described_class.web_threads({})).to eq(3)
    expect(described_class.job_threads({})).to eq(3)
    expect(described_class.job_processes({})).to eq(1)
    expect(described_class.realtime_threads({})).to eq(1)
    expect(described_class.evaluation_threads({})).to eq(2)
    expect(described_class.database_pool({})).to eq(5)
  end

  it "sizes the pool for the process with the most threads, plus Solid Queue's polling and heartbeat" do
    expect(described_class.database_pool("RAILS_MAX_THREADS" => "5")).to eq(7)
    expect(described_class.database_pool("JOB_THREADS" => "8")).to eq(10)
    expect(described_class.database_pool("JOB_REALTIME_THREADS" => "4")).to eq(6)
    expect(described_class.database_pool("EVALUATION_THREADS" => "6")).to eq(8) # #197
    expect(described_class.database_pool("JOB_CONCURRENCY" => "4")).to eq(5) # more processes, not more threads in one
  end

  it "stops the boot on a value that is not a whole number from 1 to 64, naming the setting" do
    [ "", "0", "65", "-1", "3.5", "three", " 3", "0x10", "3_0", "03\n" ].each do |value|
      expect { described_class.job_threads("JOB_THREADS" => value) }
        .to raise_error(ArgumentError, "JOB_THREADS must be a whole number from 1 to 64, not #{value.inspect}")
    end
    expect { described_class.evaluation_threads("EVALUATION_THREADS" => "abc") }
      .to raise_error(ArgumentError, 'EVALUATION_THREADS must be a whole number from 1 to 64, not "abc"')
    expect(described_class.web_threads("RAILS_MAX_THREADS" => "64")).to eq(64)
    expect { described_class.database_pool("RAILS_MAX_THREADS" => "") }.to raise_error(ArgumentError, /RAILS_MAX_THREADS/)
  end

  it "is what Puma, the job workers, and the database pool use" do
    expect(Rails.root.join("config/puma.rb").read).to include("threads_count = ProcessSizing.web_threads")
    expect(ActiveRecord::Base.connection_pool.size).to eq(described_class.database_pool)
    expect(SolidQueue::Record.connection_pool.size).to eq(described_class.database_pool)
  end
end
