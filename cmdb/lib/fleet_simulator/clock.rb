module FleetSimulator
  # Wall-clock time and sleeping, in one place so specs can substitute a clock they advance themselves.
  class Clock
    def now = Time.current
    def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    def sleep(seconds) = seconds.positive? ? Kernel.sleep(seconds) : nil
  end
end
