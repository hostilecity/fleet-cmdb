# In one of bin/rspec-parallel's processes (#288): how many examples it has finished, rewritten after each one, and
# "done" once it ends. The runner's heartbeat reads it, since each process's output is printed only when it ends.
# RSpec opens the file and hands this the IO.
class ProgressFileFormatter
  RSpec::Core::Formatters.register self, :example_finished, :close

  def initialize(output)
    @output = output
    @finished = 0
  end

  def example_finished(_notification)
    @finished += 1
    rewrite(@finished.to_s)
  end

  def close(_notification) = rewrite("#{@finished} done")

  private

  def rewrite(text)
    @output.rewind
    @output.truncate(0)
    @output.write(text)
    @output.flush
  end
end
