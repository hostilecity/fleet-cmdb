class EvaluationRun
  # Where a run's preparation got to (#295): the step it reached (prepare_step) and, in a step that works through ids
  # in order, the last id it handled (prepare_cursor). A resume (EvaluationRunWatchJob), or the retry of a run never
  # split (EvaluationRun.retry!), carries on from it rather than preparing again from the start, and the watch counts
  # a move of it as progress, so a long preparation survives any number of deploys as long as each attempt moves it.
  #
  # - steps: the kind's steps in order (EvaluationRun::Advisories#prepare_steps, Triage::STEPS), then PREPARED. A step
  #   stored that is not in the list (the code changed between attempts) counts as none done: the run prepares again
  #   from the start, which every step allows, since each is idempotent.
  # - A step's work commits before its checkpoint moves, so a kill between the two repeats that page, idempotently;
  #   the checkpoint never claims work that did not commit.
  # - Each write is a compare-and-set on the run's row: it moves the checkpoint only from where this preparation last
  #   left it, and only while the run is queued. Two preparations of one run (a resume and a job thought dead) cannot
  #   both go on: the one whose write misses raises Lost, and EvaluationRun#fan_out! stops it quietly. A run
  #   superseded or failed meanwhile stops the same way. Each write touches updated_at, which the watch re-checks
  #   under the row lock, so a preparation that is moving is never taken for dead.
  # - Detached (no run: the benchmark, specs calling prepare! alone): the same steps, kept in memory only.
  class Checkpoint
    # Another preparation of the run moved the checkpoint, or the run is no longer queued.
    Lost = Class.new(StandardError)

    PREPARED = "prepared"

    def self.for(run, steps) = new(run.id, steps, run.prepare_step, run.prepare_cursor)

    def self.detached(steps) = new(nil, steps)

    def initialize(run_id, steps, step = nil, cursor = nil)
      @run_id = run_id
      @steps = steps + [ PREPARED ]
      @step = step
      @cursor = cursor
      @writes = 0
    end

    # How many times it was written (the measurements, #295).
    attr_reader :step, :cursor, :writes

    # Whether the step was done before (a later step was reached).
    def done?(name) = position > @steps.index(name)

    # Runs a step unless it was done, then moves on to the next. The block returns the scope to store with that move
    # (written in the same statement, so the step's result and the checkpoint commit together), or nil.
    def step!(name)
      return if done?(name)

      scope = yield
      advance!(after(name), nil, scope: scope.is_a?(Hash) ? scope : nil)
    end

    # Works through ids (sorted, then sliced by size) in a paged step, carrying on after the cursor when the step was
    # reached before: yields each slice, then moves the cursor to its last id. Then moves on to the next step.
    def pages!(name, ids, size)
      return if done?(name)

      ids = ids.uniq.sort
      if @step == name && @cursor
        from = ids.bsearch_index { |id| id > @cursor } || ids.size
        ids = ids.drop(from)
      end
      ids.each_slice(size) do |slice|
        yield slice
        advance!(name, slice.last)
      end
      advance!(after(name))
    end

    # Moves the checkpoint (compare-and-set, see above); raises Lost when another preparation moved it, or the run is
    # no longer queued.
    def advance!(name, cursor = nil, scope: nil)
      if @run_id
        values = { prepare_step: name, prepare_cursor: cursor, updated_at: Time.current }
        values[:scope] = scope if scope
        moved = EvaluationRun.where(id: @run_id, state: "queued", prepare_step: @step, prepare_cursor: @cursor).update_all(values)
        raise Lost, "run #{@run_id}: its preparation moved on elsewhere, or it is no longer queued" unless moved == 1
      end
      @step = name
      @cursor = cursor
      @writes += 1
    end

    private

    def position = @step ? (@steps.index(@step) || -1) : -1

    def after(name) = @steps.fetch(@steps.index(name) + 1)
  end
end
