Gem::Specification.new do |s|
  s.name        = "ruby-pam"
  # git820d540
  s.version     = '1.5'
  s.has_rdoc    = true
  s.authors     = ["Akaaki Tateishi"]
  s.email       = ["ttate@users.sourceforge.jp"]
  s.homepage    = "http://github.com/portertech/ruby-pam"
  s.summary     = "Ruby/PAM Module"
  s.description = s.summary
  s.has_rdoc    = false
  s.files       = Dir.glob('*.{c,h}')
  s.files      += [
    'COPYING',
    'ChangeLog',
    'README',
  ]
  s.extensions  = ['extconf.rb']
  s.test_files  = `git ls-files -- {test}/*`.split("\n")
end
