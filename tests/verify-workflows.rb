require 'psych'
require 'tempfile'
require 'open3'

def check(ok, code)
  raise code unless ok
end
files = Dir['.github/workflows/*.yml'].to_h { |p| [File.basename(p), Psych.safe_load(File.read(p), aliases: false)] }
files.each_value do |workflow|
  workflow.fetch('jobs').each_value do |job|
    job.fetch('steps', []).each do |step|
      check(step['uses'].match?(/@[a-f0-9]{40}\z/), 'mutable action') if step['uses']
      next unless step['run']
      check(!step['run'].include?('${{'), 'expression embedded in script')
      next unless step['shell'] == 'bash'
      Tempfile.create(['piflow-workflow', '.sh']) do |f|
        f.write(step['run']); f.flush
        _, err, status = Open3.capture3('bash', '-n', f.path)
        check(status.success?, "invalid shell: #{err}")
      end
    end
  end
end
release = files.fetch('release-tool.yml')
check(release.fetch('permissions') == {}, 'ambient release permissions')
build = release.fetch('jobs').fetch('build')
check(build.fetch('permissions') == {'contents'=>'read', 'packages'=>'read'}, 'build can mint credentials')
upload = build.fetch('steps').find { |s| s['uses']&.start_with?('actions/upload-artifact@') }.fetch('with')
check(upload.fetch('path') == '${{ runner.temp }}/release.pfs' && upload.fetch('retention-days') == 1, 'plaintext artifact boundary')
publish = release.fetch('jobs').fetch('publish')
check(publish.fetch('permissions') == {'contents'=>'read', 'id-token'=>'write'}, 'publish permissions')
check(publish.fetch('steps').map { |s| s['uses'] }.compact.length == 1 &&
  publish.fetch('steps')[0].fetch('uses').start_with?('actions/download-artifact@'), 'publish runs external code')
check(publish.fetch('steps').map { |s| s['run'] }.compact.length == 1, 'publish uses shell helpers')
check(publish.fetch('concurrency').fetch('cancel-in-progress') == false, 'release cancellation race')
puts 'Workflow permission, action pin, artifact and shell checks passed.'
