#!/usr/bin/env ruby
# frozen_string_literal: true

# Backlog importer for fleet-cmdb.
#
# Turns docs/backlog/issues.yml into GitHub labels, milestones, issues, and "blocked by"
# relationships. Stdlib only; works on Ruby 2.6+.
#
# Design: a GitHub issue is a short stub (goal, requirement IDs, 2-3 acceptance criteria,
# a link, blockers). Everything else lives in the repository, in
# docs/backlog/specs/<key lowercased>.md, which is the source of truth for implementation
# details. Agents read that file, not the issue, and reference the issue in their pull requests.
#
#   ruby docs/backlog/import.rb check            validate sources, links, graph, and requirement coverage (no network)
#   ruby docs/backlog/import.rb plan             print everything that would be created (no network)
#   ruby docs/backlog/import.rb apply [options]  create on GitHub (needs `gh` authenticated)
#
# apply options:
#   (the target is always the current project's repository, as resolved by `gh`)
#   --skip-links        do not create "blocked by" relationships
#   --refresh           also rewrite title and body of existing backlog issues from the source
#                       (default: existing issues are left alone, so edits made on GitHub survive)
#
# Safety properties:
#   * Never closes or deletes anything, and never edits an issue that lacks this tool's marker comment.
#   * Idempotent and resumable: every issue body starts with `<!-- backlog-key: KEY -->`; re-running
#     skips issues that exist. A complete import followed by a re-run makes no writes.
#   * `check` and `plan` never touch the network.
#   * Cheap: one POST per issue (blockers are created first, so the body is final) plus one POST per
#     blocked-by link.
#
# issues.yml entries (see docs/backlog/README.md):
#   - key: P1-ACCESS            # unique; spec file is specs/p1-access.md
#     title: "..."
#     milestone: 1              # index into config.yml milestones
#     labels: ["area:server"]   # must exist in config.yml
#     covers: [FR-S.4, NFR-1]   # requirement IDs from docs/requirements.md
#     goal: "One sentence."
#     done: ["2 or 3 acceptance criteria"]
#     blocked_by: [P1-HOSTS]    # other issue keys

require 'yaml'
require 'json'
require 'set'
require 'open3'
require 'optparse'

ROOT = File.expand_path(__dir__)
REPO_ROOT = File.expand_path('../..', ROOT)
REQUIREMENTS = File.expand_path('../requirements.md', ROOT)
DECISIONS_DIR = File.expand_path('../decisions', ROOT)
CONFIG = File.join(ROOT, 'config.yml')
ISSUES_FILE = File.join(ROOT, 'issues.yml')
SPEC_DIR = File.join(ROOT, 'specs')
MARKER_RE = /\A<!-- backlog-key: ([A-Za-z0-9.\-]+) -->/.freeze
# Requirements that issues must cover. DEC-nn decisions are covered by an ADR, not an issue.
REQ_ID_RE = /\b(?:FR-S\.\d+|FR-\d\.\d+|NFR-\d+|AC-\d\.\d+)\b/.freeze
DEC_ID_RE = /\bDEC-\d{2}\b/.freeze
GH = ENV.fetch('GH_BIN', 'gh')

Issue = Struct.new(:key, :title, :milestone, :labels, :covers, :goal, :done, :blocked_by, :order)

class Backlog
  attr_reader :config, :issues, :errors, :requirement_ids, :by_key

  def initialize
    @errors = []
    @config = YAML.safe_load(File.read(CONFIG), permitted_classes: [], aliases: false)
    @issues = []
    load_issues
    @by_key = {}
    @issues.each { |i| @by_key[i.key] = i }
    text = File.read(REQUIREMENTS)
    @requirement_ids = text.scan(REQ_ID_RE).uniq.sort
    @decision_ids = text.scan(DEC_ID_RE).uniq.sort
    apply_gates
  end

  def milestones
    config['milestones']
  end

  def label_names
    config['labels'].map { |l| l['name'] }
  end

  def spec_file(issue)
    "#{issue.key.downcase}.md"
  end

  # ---- loading ------------------------------------------------------------

  def load_issues
    data = YAML.safe_load(File.read(ISSUES_FILE), permitted_classes: [], aliases: false)
    unless data.is_a?(Array)
      @errors << 'issues.yml must be a list of issues'
      return
    end
    data.each_with_index do |h, idx|
      unless h.is_a?(Hash)
        @errors << "issues.yml entry #{idx + 1} is not a mapping"
        next
      end
      @issues << Issue.new(
        h['key'].to_s, h['title'].to_s, h['milestone'],
        Array(h['labels']).map(&:to_s), Array(h['covers']).map(&:to_s),
        h['goal'].to_s, Array(h['done']).map(&:to_s), Array(h['blocked_by']).map(&:to_s), idx + 1
      )
    end
  rescue StandardError => e
    @errors << "issues.yml does not parse: #{e.message.lines.first.to_s.strip}"
  end

  # Every root issue (no blocker in its own milestone) of a gated milestone is blocked by the gate issue,
  # so the next phase's code cannot start before the previous phase is accepted.
  def apply_gates
    milestones.each_with_index do |m, idx|
      gate = m['gate']
      next unless gate

      @issues.select { |i| i.milestone == idx && i.key != gate }.each do |i|
        in_ms = i.blocked_by.any? { |k| @by_key[k] && @by_key[k].milestone == idx }
        i.blocked_by = (i.blocked_by + [gate]).uniq unless in_ms
      end
    end
  end

  # ---- validation ---------------------------------------------------------

  def validate
    counts = Hash.new(0)
    @issues.each { |i| counts[i.key] += 1 }
    counts.each { |k, n| @errors << "duplicate key #{k} (#{n} times)" if n > 1 }

    @issues.each do |i|
      where = "issues.yml: #{i.key.empty? ? "entry #{i.order}" : i.key}"
      @errors << "#{where}: key must look like P1-ACCESS" unless i.key =~ /\A[A-Z0-9]+(-[A-Z0-9]+)+\z/
      @errors << "#{where}: title missing or longer than 120 characters" if i.title.strip.empty? || i.title.length > 120
      unless i.milestone.is_a?(Integer) && i.milestone >= 0 && i.milestone < milestones.size
        @errors << "#{where}: milestone #{i.milestone.inspect} is not an index into config.yml"
      end
      i.labels.each { |l| @errors << "#{where}: unknown label #{l.inspect}" unless label_names.include?(l) }
      @errors << "#{where}: covers is empty" if i.covers.empty?
      i.covers.each do |r|
        @errors << "#{where}: covers #{r} is not a requirement ID in docs/requirements.md" unless @requirement_ids.include?(r)
      end
      if i.goal.strip.empty? || i.goal.include?("\n") || i.goal.length > 250
        @errors << "#{where}: goal must be one sentence on one line (at most 250 characters)"
      end
      @errors << "#{where}: goal must end with a period" unless i.goal.strip.end_with?('.')
      @errors << "#{where}: done needs 2 or 3 acceptance criteria, found #{i.done.size}" unless (2..3).cover?(i.done.size)
      i.done.each do |d|
        @errors << "#{where}: an acceptance criterion is empty or longer than 260 characters" if d.strip.empty? || d.length > 260
      end
      i.blocked_by.each do |k|
        if k == i.key
          @errors << "#{where}: blocked by itself"
        elsif !@by_key.key?(k)
          @errors << "#{where}: blocked_by unknown key #{k}"
        end
      end
      spec = File.join(SPEC_DIR, spec_file(i))
      if File.exist?(spec)
        first = File.foreach(spec).first.to_s
        @errors << "#{where}: #{spec_file(i)} should start with '# #{i.key}'" unless first.start_with?("# #{i.key}")
      else
        @errors << "#{where}: missing spec file docs/backlog/specs/#{spec_file(i)}"
      end
    end

    milestones.each do |m|
      next unless m['gate']

      @errors << "milestone #{m['title']}: gate #{m['gate']} is not a known key" unless @by_key.key?(m['gate'])
    end

    check_specs
    check_cycles
    check_milestone_order
    uncovered.each { |r| @errors << "requirement #{r} is not covered by any issue (add it to a covers list)" }
    @decision_ids.each do |d|
      adr = Dir.glob(File.join(DECISIONS_DIR, '[0-9]*.md')).any? { |f| File.read(f).include?("Decision issue: #{d}") }
      @errors << "decision #{d} has no ADR in docs/decisions (expected a line 'Decision issue: #{d}')" unless adr
    end
    self
  end

  # Orphan specs, unresolved placeholders, and broken relative links.
  def check_specs
    known = @issues.map { |i| spec_file(i) }
    Dir.glob(File.join(SPEC_DIR, '*.md')).sort.each do |f|
      base = File.basename(f)
      @errors << "specs/#{base} has no matching issue in issues.yml" unless known.include?(base)
      text = File.read(f)
      @errors << "specs/#{base} contains an unresolved {{placeholder}}" if text =~ /\{\{[^}]+\}\}/
      text.scan(/\]\(([^)\s]+)\)/).flatten.each do |link|
        next if link =~ %r{\A(https?:|mailto:|#)}

        target = File.expand_path(link.sub(/#.*\z/, ''), SPEC_DIR)
        @errors << "specs/#{base} links to #{link}, which does not exist" unless File.exist?(target)
      end
    end
  end

  def check_cycles
    state = {}
    visit = lambda do |k, path|
      return if state[k] == :done

      if state[k] == :active
        @errors << "dependency cycle: #{(path + [k]).join(' -> ')}"
        return
      end
      state[k] = :active
      (@by_key[k] ? @by_key[k].blocked_by : []).each { |d| visit.call(d, path + [k]) if @by_key.key?(d) }
      state[k] = :done
    end
    @issues.each { |i| visit.call(i.key, []) }
  end

  def check_milestone_order
    @issues.each do |i|
      i.blocked_by.each do |k|
        b = @by_key[k]
        next unless b && b.milestone.is_a?(Integer) && i.milestone.is_a?(Integer)

        @errors << "#{i.key} (milestone #{i.milestone}) is blocked by #{k} in a later milestone #{b.milestone}" if b.milestone > i.milestone
      end
    end
  end

  def uncovered
    covered = @issues.flat_map(&:covers).to_set
    @requirement_ids.reject { |r| covered.include?(r) }
  end

  # ---- ordering and rendering ---------------------------------------------

  # Blockers that are not already implied through another blocker (transitive reduction).
  # issues.yml may list more; only these are linked and shown, which keeps issues and API calls small.
  def direct_blockers(issue)
    issue.blocked_by.reject do |b|
      issue.blocked_by.any? { |other| other != b && reachable_blockers(other).include?(b) }
    end
  end

  def reachable_blockers(key)
    @reach ||= {}
    @reach[key] ||= begin
      seen = Set.new
      stack = (@by_key[key] ? @by_key[key].blocked_by.dup : [])
      until stack.empty?
        k = stack.pop
        next if seen.include?(k)

        seen << k
        stack.concat(@by_key[k].blocked_by) if @by_key[k]
      end
      seen
    end
  end

  # Blockers always come first, so a body can name its blockers by issue number when created.
  def creation_order
    done = Set.new
    result = []
    remaining = @issues.dup
    until remaining.empty?
      ready = remaining.select { |i| i.blocked_by.all? { |k| done.include?(k) || !@by_key.key?(k) } }
      raise 'cycle prevents ordering' if ready.empty?

      pick = ready.min_by { |i| [i.milestone.to_i, i.order] }
      result << pick
      done << pick.key
      remaining.delete(pick)
    end
    result
  end

  # numbers: key => issue number. repo turns the spec path into a link to the default branch
  # (HEAD), so no branch name is needed (plan mode passes nil).
  def render(issue, numbers = {}, repo = nil)
    path = "docs/backlog/specs/#{spec_file(issue)}"
    link = repo ? "[#{path}](https://github.com/#{repo}/blob/HEAD/#{path})" : "`#{path}`"
    out = +"<!-- backlog-key: #{issue.key} -->\n"
    out << "**Goal:** #{issue.goal.strip}\n\n"
    out << "**Covers:** #{issue.covers.join(', ')}\n\n"
    out << "**Done when**\n"
    issue.done.each { |d| out << "- [ ] #{d.strip}\n" }
    out << "\n**Details:** #{link} (source of truth for implementation; read it before starting)\n"
    unless direct_blockers(issue).empty?
      refs = direct_blockers(issue).map { |k| numbers[k] ? "##{numbers[k]}" : "`#{k}`" }
      out << "**Blocked by:** #{refs.join(', ')}\n"
    end
    out
  end
end

# ---- GitHub access ----------------------------------------------------------

class GitHub
  attr_reader :repo

  def initialize(repo)
    @repo = repo
  end

  def run(*args, stdin: nil)
    Open3.capture3(GH, *args, stdin_data: stdin.to_s)
  end

  def api(method, path, body = nil)
    args = ['api', '--method', method, path]
    stdin = nil
    if body
      args += ['--input', '-']
      stdin = JSON.generate(body)
    end
    out, err, st = run(*args, stdin: stdin)
    raise "gh api #{method} #{path} failed: #{err.strip} #{out.strip}" unless st.success?

    out.strip.empty? ? nil : JSON.parse(out)
  end

  def paged(path)
    sep = path.include?('?') ? '&' : '?'
    out, err, st = run('api', '--paginate', '--slurp', "#{path}#{sep}per_page=100")
    raise "gh api GET #{path} failed: #{err.strip}" unless st.success?

    JSON.parse(out).flatten
  end

  def self.default_repo
    out, err, st = Open3.capture3(GH, 'repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner')
    raise "cannot determine repository: #{err.strip}" unless st.success?

    out.strip
  end
end

def pause(seconds)
  sleep(seconds) unless ENV['BACKLOG_NO_SLEEP']
end

# ---- commands ---------------------------------------------------------------

def print_summary(backlog)
  puts "Issues: #{backlog.issues.size}  Milestones: #{backlog.milestones.size}  Labels: #{backlog.config['labels'].size}"
  backlog.milestones.each_with_index do |m, idx|
    puts format('  %d  %-42s %3d issues', idx, m['title'], backlog.issues.count { |i| i.milestone == idx })
  end
  links = backlog.issues.map { |i| backlog.direct_blockers(i).size }.inject(0, :+)
  covered = backlog.requirement_ids.size - backlog.uncovered.size
  puts "Blocked-by links: #{links}   FR/NFR/AC IDs covered: #{covered}/#{backlog.requirement_ids.size}"
end

def cmd_check(backlog)
  backlog.validate
  if backlog.errors.empty?
    print_summary(backlog)
    puts 'OK: issues.yml valid, specs and links resolve, graph acyclic, every FR/NFR/AC covered, every DEC has an ADR.'
    0
  else
    warn "#{backlog.errors.size} problem(s):"
    backlog.errors.each { |e| warn "  - #{e}" }
    1
  end
end

def cmd_plan(backlog)
  return 1 unless cmd_check(backlog).zero?

  puts
  puts 'Issues, in creation order:'
  backlog.creation_order.each_with_index do |i, n|
    direct = backlog.direct_blockers(i)
    blockers = direct.empty? ? '' : "  <- #{direct.join(', ')}"
    puts format('  %2d  %-18s M%d  %s%s', n + 1, i.key, i.milestone, i.title, blockers)
  end
  puts
  puts 'Sample issue body:'
  puts backlog.render(backlog.creation_order.first).gsub(/^/, '    ')
  0
end

def cmd_apply(backlog, opts)
  return 1 unless cmd_check(backlog).zero?

  gh = GitHub.new(GitHub.default_repo)
  repo = gh.repo
  puts
  puts "Target repository: #{repo}"
  puts "Up to #{backlog.issues.size} issues, #{backlog.milestones.size} milestones, #{backlog.config['labels'].size} labels."
  puts 'Note: spec links point at the default branch and resolve once docs/backlog/specs/ is pushed.'

  puts 'Ensuring labels...'
  backlog.config['labels'].each do |l|
    _out, err, st = gh.run('label', 'create', l['name'], '--color', l['color'], '--description', l['description'].to_s,
                           '--force', '--repo', repo)
    raise "label #{l['name']}: #{err.strip}" unless st.success?
  end

  puts 'Ensuring milestones...'
  existing_ms = gh.paged("repos/#{repo}/milestones?state=all")
  ms_numbers = {}
  backlog.milestones.each_with_index do |m, idx|
    found = existing_ms.find { |e| e['title'] == m['title'] }
    if found
      ms_numbers[idx] = found['number']
    else
      created = gh.api('POST', "repos/#{repo}/milestones", { 'title' => m['title'], 'description' => m['description'].to_s })
      ms_numbers[idx] = created['number']
      puts "  created milestone: #{m['title']}"
    end
  end

  puts 'Looking for issues from a previous run...'
  numbers = {}
  ids = {}
  gh.paged("repos/#{repo}/issues?state=all").each do |e|
    next if e['pull_request']

    m = MARKER_RE.match(e['body'].to_s)
    next unless m

    numbers[m[1]] = e['number']
    ids[m[1]] = e['id']
  end
  puts "  found #{numbers.size} existing"

  order = backlog.creation_order
  created = Set.new
  order.each do |i|
    if numbers.key?(i.key)
      if opts[:refresh]
        gh.api('PATCH', "repos/#{repo}/issues/#{numbers[i.key]}",
               { 'title' => i.title, 'body' => backlog.render(i, numbers, repo) })
        puts format('  #%-4d %-18s refreshed', numbers[i.key], i.key)
        pause(0.5)
      end
      next
    end

    res = gh.api('POST', "repos/#{repo}/issues", {
                   'title' => i.title,
                   'body' => backlog.render(i, numbers, repo),
                   'milestone' => ms_numbers[i.milestone],
                   'labels' => i.labels
                 })
    numbers[i.key] = res['number']
    ids[i.key] = res['id']
    created << i.key
    puts format('  #%-4d %-18s %s', res['number'], i.key, i.title)
    pause(1.0)
  end
  puts "Created #{created.size} issues."

  if opts[:skip_links]
    puts 'Skipping blocked-by relationships (--skip-links).'
  else
    puts 'Creating blocked-by relationships...'
    linked = 0
    order.each do |i|
      direct = backlog.direct_blockers(i)
      next if direct.empty?

      # A freshly created issue has no relationships yet, so only existing ones need a lookup.
      have = created.include?(i.key) ? Set.new : gh.paged("repos/#{repo}/issues/#{numbers[i.key]}/dependencies/blocked_by").map { |d| d['id'] }.to_set
      direct.each do |k|
        next if have.include?(ids[k])

        gh.api('POST', "repos/#{repo}/issues/#{numbers[i.key]}/dependencies/blocked_by", { 'issue_id' => ids[k] })
        linked += 1
        pause(0.5)
      end
    end
    puts "Created #{linked} relationships."
  end

  puts
  puts "Done. #{numbers.size} backlog issues exist in #{repo}."
  0
end

# ---- main -------------------------------------------------------------------

if $PROGRAM_NAME == __FILE__
  command = ARGV.shift
  opts = {}
  OptionParser.new do |o|
    o.on('--skip-links') { opts[:skip_links] = true }
    o.on('--refresh') { opts[:refresh] = true }
  end.parse!(ARGV)

  begin
    backlog = Backlog.new
    code = case command
           when 'check' then cmd_check(backlog)
           when 'plan' then cmd_plan(backlog)
           when 'apply' then cmd_apply(backlog, opts)
           else
             warn File.read(__FILE__).lines.take_while { |l| l.start_with?('#') }.join
             2
           end
    exit code
  rescue RuntimeError => e
    warn
    warn "ERROR: #{e.message}"
    warn 'Nothing was deleted. Fix the cause and re-run the same command; it resumes where it stopped.' if command == 'apply'
    exit 1
  end
end
